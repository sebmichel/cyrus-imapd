/*  cyrusdb_sql: SQL db backends
 *
 * Copyright (c) 1998-2004 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact  
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id: cyrusdb_sql.c,v 1.3 2010/01/06 17:01:45 murch Exp $ */

#include <config.h>

#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

#include "assert.h"
#include "bsearch.h"
#include "cyrusdb.h"
#include "exitcodes.h"
#include "libcyr_cfg.h"
#include "ptrarray.h"
#include "xmalloc.h"
#include "util.h"

extern void fatal(const char *, int);

typedef int exec_cb(void *rock,
		    const char *key, size_t keylen,
		    const char *data, size_t datalen);

typedef struct sql_engine {
    const char *name;
    const char *binary_type;
    const char *cmd_begin_txn;
    const char *cmd_commit_txn;
    const char *cmd_rollback_txn;
    void *(*sql_open)(char *host, char *port, int usessl,
		      const char *user, const char *password,
		      const char *database);
    char *(*sql_escape)(void *conn, char **to,
			const char *from, size_t fromlen);
    int (*sql_exec)(void *conn, const char *cmd, exec_cb *cb, void *rock,
		    int *failover);
    void (*sql_close)(void *conn);
} sql_engine_t;

/** DB host data. */
typedef struct {
    /** Host name */
    char *hostname;
    /** Host port */
    char *port;
    /** Last time the host was seen active */
    time_t lastactive;
    /** Time at which host can become active again, -1 if available right now */
    time_t backoff_mark;
    /** Whether the host was already tried in current failover */
    int tried;
} dbhost_t;

struct dbengine {
    void *conn;     /* connection to database */
    char *database; /* database that we are operating on */
    char *user;     /* db user login */
    char *password; /* db user password */
    int usessl;     /* whether we use SSL */
    char *table;    /* table that we are operating on */
    char *esc_key;  /* allocated buffer for escaped key */
    char *esc_data; /* allocated buffer for escaped data */
    char *data;     /* allocated buffer for fetched data */

    ptrarray_t *hosts;  /* available hosts */
    int activeidx;      /* index of active host, -1 if none */
    int backoff_time;   /* backoff time upon connection failure */
    int idle_timeout;   /* time a connection should be able to stay idle */
};

struct txn {
    char *lastkey;  /* allocated buffer for last SELECTed key */
    size_t keylen;
};

static int dbinit = 0;
static const sql_engine_t *dbengine = NULL;


#ifdef HAVE_MYSQL
#include <errmsg.h>
#include <mysql.h>

static void *_mysql_open(char *host, char *port, int usessl,
			 const char *user, const char *password,
			 const char *database)
{
    MYSQL *mysql;
    void *conn;

    if (!(mysql = mysql_init(NULL))) {
	syslog(LOG_ERR, "DBERROR: SQL backend could not execute mysql_init()");
	return NULL;
    }

    conn = mysql_real_connect(mysql, host, user, password, database,
			      port ? strtoul(port, NULL, 10) : 0, NULL,
			      usessl ? CLIENT_SSL : 0);

    if (!conn) {
	syslog(LOG_ERR, "DBERROR: SQL backend: %s", mysql_error(mysql));
	mysql_close(mysql);
    }

    return conn;
}

static char *_mysql_escape(void *conn, char **to,
			   const char *from, size_t fromlen)
{
    *to = xrealloc(*to, 2 * fromlen + 1); /* +1 for NUL */

    mysql_real_escape_string(conn, *to, from, fromlen);

    return *to;
}

static void _mysql_check_error(void *conn, int *failover)
{
    if (!failover) {
	return;
    }

    /* Note: SQLState is HY000 for client errors, so rely on mysql_errno */
    switch (mysql_errno(conn)) {
    case CR_SERVER_GONE_ERROR:
	/* MySQL server has gone away */
    case CR_SERVER_LOST:
	/* Lost connection to MySQL server during query */
    case CR_SERVER_LOST_EXTENDED:
	/* Lost connection to MySQL server at '%s', system error: %d */
    case CR_INVALID_CONN_HANDLE:
	/* Invalid connection handle */
	*failover = 1;
	break;

    default:
	break;
    }
}

static int _mysql_exec(void *conn, const char *cmd, exec_cb *cb, void *rock,
    int *failover)
{
    MYSQL_RES *result;
    MYSQL_ROW row;
    int len, r = 0;

    if (failover) *failover = 0;

    syslog(LOG_DEBUG, "executing SQL cmd: %s", cmd);

    len = strlen(cmd);
    /* mysql_real_query() doesn't want a terminating ';' */
    if (cmd[len-1] == ';') len--;

    /* run the query */
    if ((mysql_real_query(conn, cmd, len) < 0) ||
	*mysql_error(conn)) {
	syslog(LOG_ERR, "DBERROR: SQL query failed: %s", mysql_error(conn));
	_mysql_check_error(conn, failover);
	return CYRUSDB_INTERNAL;
    }

    /* see if we should expect some results */
    if (!mysql_field_count(conn)) {
	/* no results (BEGIN, COMMIT, ROLLBACK, CREATE, INSERT, UPDATE, DELETE) */
	syslog(LOG_DEBUG, "no results from SQL cmd");
	return 0;
    }

    /* get the results */
    result = mysql_store_result(conn);
    if (!result) {
	syslog(LOG_ERR, "DBERROR: SQL query failed: %s", mysql_error(conn));
	_mysql_check_error(conn, failover);
	return CYRUSDB_INTERNAL;
    }

    /* process the results */
    while (!r && (row = mysql_fetch_row(result))) {
	unsigned long *length = mysql_fetch_lengths(result);
	r = cb(rock, row[0], length[0], row[1], length[1]);
    }

    /* free result */
    mysql_free_result(result);

    return r;
}

static void _mysql_close(void *conn)
{
    mysql_close(conn);
}
#endif /* HAVE_MYSQL */


#ifdef HAVE_PGSQL
#include <libpq-fe.h>

#define sql_max(a, b) ((a) > (b) ? (a) : (b))
#define sql_len(input) ((input) ? strlen(input) : 0)
#define sql_exists(input) ((input) && (*input))

static void *_pgsql_open(char *host, char *port, int usessl,
			 const char *user, const char *password,
			 const char *database)
{
    PGconn *conn = NULL;
    char *conninfo, *p;

    /* create the connection info string */
    /* The 64 represents the number of characters taken by
     * the keyword tokens, plus a small pad
     */
    p = conninfo = xzmalloc(64 + sql_len(host) + sql_len(port)
			   + sql_len(user) + sql_len(password)
			   + sql_len(database));

    /* add each term that exists */
    if (sql_exists(host)) p += sprintf(p, " host='%s'", host);
    if (sql_exists(port)) p += sprintf(p, " port='%s'", port);
    if (sql_exists(user)) p += sprintf(p, " user='%s'", user);
    if (sql_exists(password)) p += sprintf(p, " password='%s'", password);
    if (sql_exists(database)) p += sprintf(p, " dbname='%s'", database);
    p += sprintf(p, " requiressl='%d'", usessl);

    conn = PQconnectdb(conninfo);
    free(conninfo);

    if ((PQstatus(conn) != CONNECTION_OK)) {
	syslog(LOG_ERR, "DBERROR: SQL backend: %s", PQerrorMessage(conn));
	PQfinish(conn);
	conn = NULL;
    }

    return conn;
}

static char *_pgsql_escape(void *conn __attribute__((unused)),
			   char **to __attribute__((unused)),
			   const char *from, size_t fromlen)
{
    size_t tolen;

    /* returned buffer MUST be freed by caller */
    return (char *) PQescapeBytea((unsigned char *) from, fromlen, &tolen);
}

static void _pgsql_check_error(PGresult *result, int *failover)
{
    const char *sqlState;

    if (!failover) {
	return;
    }

    /* Note: SQLState, which is always present - at least if status is not
     * PGRES_FATAL_ERROR, is in class 08 for connection issues */
    sqlState = PQresultErrorField(result, PG_DIAG_SQLSTATE);
    if (!sqlState || !strncmp("08", sqlState, 2)) {
	*failover = 1;
    }
}

static int _pgsql_exec(void *conn, const char *cmd, exec_cb *cb, void *rock,
    int *failover)
{
    PGresult *result;
    int row_count, i, r = 0;
    ExecStatusType status;

    if (failover) *failover = 0;

    syslog(LOG_DEBUG, "executing SQL cmd: %s", cmd);

    /* run the query */
    result = PQexec(conn, cmd);

    /* check the status */
    status = PQresultStatus(result);
    if (status == PGRES_COMMAND_OK) {
	/* no results (BEGIN, COMMIT, ROLLBACK, CREATE, INSERT, UPDATE, DELETE) */
	PQclear(result);
	return 0;
    }
    else if (status != PGRES_TUPLES_OK) {
	/* error */
	syslog(LOG_DEBUG, "SQL backend: %s ", PQresStatus(status));
	_pgsql_check_error(result, failover);
	PQclear(result);
	return CYRUSDB_INTERNAL;
    }

    row_count = PQntuples(result);
    for (i = 0; !r && i < row_count; i++) {
	char *key, *data;
	size_t keylen, datalen;

	key = (char *)
	    PQunescapeBytea((unsigned char *) PQgetvalue(result, i, 0),
			    &keylen);
	data = (char *)
	    PQunescapeBytea((unsigned char *) PQgetvalue(result, i, 1),
			    &datalen);
	r = cb(rock, key, keylen, data, datalen);
	free(key); free(data);
    }

    /* free result */
    PQclear(result);

    return r;
}

static void _pgsql_close(void *conn)
{
    PQfinish(conn);
}
#endif /* HAVE_PGSQL */


#ifdef HAVE_SQLITE
#include <sqlite3.h>

static void *_sqlite_open(char *host __attribute__((unused)),
			  char *port __attribute__((unused)),
			  int usessl __attribute__((unused)),
			  const char *user __attribute__((unused)),
			  const char *password __attribute__((unused)),
			  const char *database)
{
    int rc;
    sqlite3 *db;

    rc = sqlite3_open(database, &db);
    if (rc != SQLITE_OK) {
	syslog(LOG_ERR, "DBERROR: SQL backend: %s", sqlite3_errmsg(db));
	sqlite3_close(db);
	db = NULL;
    }

    return db;
}

static char *_sqlite_escape(void *conn __attribute__((unused)),
			    char **to, const char *from, size_t fromlen)
{
    size_t tolen;
#if 0
    *to = xrealloc(*to, 2 + (257 * fromlen) / 254);

    tolen = sqlite3_encode_binary(from, fromlen, *to);
#else
    *to = xrealloc(*to, fromlen + 1);
    memcpy(*to, from, fromlen);
    tolen = fromlen;
    (*to)[tolen] = '\0';
#endif

    return *to;
}

static int _sqlite_exec(void *conn, const char *cmd, exec_cb *cb, void *rock,
    int *failover)
{
    int rc, r = 0;
    sqlite3_stmt *stmt = NULL;
    const char *tail;

    if (failover) *failover = 0;

    syslog(LOG_DEBUG, "executing SQL cmd: %s", cmd);

    /* compile the SQL cmd */
    rc = sqlite3_prepare(conn, cmd, strlen(cmd), &stmt, &tail);
    if (rc != SQLITE_OK) {
	syslog(LOG_DEBUG, "SQL backend: %s ", sqlite3_errmsg(conn));
	return CYRUSDB_INTERNAL;
    }

    /* process the results */
    while (!r && (rc = sqlite3_step(stmt)) == SQLITE_ROW) {
	const unsigned char *key = sqlite3_column_text(stmt, 0);
	int keylen = sqlite3_column_bytes(stmt, 0);
	const unsigned char *data = sqlite3_column_text(stmt, 1);
	int datalen = sqlite3_column_bytes(stmt, 1);

	r = cb(rock, (char *) key, keylen, (char *) data, datalen);
    }

    /* cleanup */
    rc = sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
	syslog(LOG_DEBUG, "SQL backend: %s ", sqlite3_errmsg(conn));
	return CYRUSDB_INTERNAL;
    }

    return r;
}

static void _sqlite_close(void *conn)
{
    sqlite3_close(conn);
}
#endif /* HAVE_SQLITE */


static const sql_engine_t sql_engines[] = {
#ifdef HAVE_MYSQL
    { "mysql", "BLOB",
#if MYSQL_VERSION_ID >= 40011
       "START TRANSACTION",
#else
       "BEGIN",
#endif
       "COMMIT", "ROLLBACK",
       &_mysql_open, &_mysql_escape,
      &_mysql_exec, &_mysql_close },
#endif /* HAVE_MYSQL */
#ifdef HAVE_PGSQL
    { "pgsql", "BYTEA",
      "BEGIN;", "COMMIT;", "ROLLBACK;",
      &_pgsql_open, &_pgsql_escape,
      &_pgsql_exec, &_pgsql_close },
#endif
#ifdef HAVE_SQLITE
    { "sqlite", "BLOB",
      "BEGIN TRANSACTION", "COMMIT TRANSACTION", "ROLLBACK TRANSACTION",
      &_sqlite_open, &_sqlite_escape,
      &_sqlite_exec, &_sqlite_close },
#endif
    { NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL }
};


static int init(const char *dbdir __attribute__((unused)),
		int flags __attribute__((unused)))
{
    const char *engine_name;
    int r = 0;

    if (dbinit++) return 0;

    engine_name = libcyrus_config_getstring(CYRUSOPT_SQL_ENGINE);

    /* find the correct engine */
    dbengine = sql_engines;
    while (dbengine->name) {
	if (!engine_name || !strcasecmp(engine_name, dbengine->name)) break;
	dbengine++;
    }

    if (!dbengine->name) {
	char errbuf[1024];
	snprintf(errbuf, sizeof(errbuf),
		 "SQL engine %s not supported", engine_name);
	fatal(errbuf, EC_CONFIG);
    }

    if (!engine_name) {
	syslog(LOG_DEBUG, "SQL backend defaulting to engine '%s'",
	       dbengine->name);
    }

    dbinit = 1;

    return r;
}

static int done(void)
{
    --dbinit;
    return 0;
}

static inline void dbhost_failed(struct dbengine *db, dbhost_t *dbhost)
{
    dbhost->backoff_mark = time(NULL) + db->backoff_time;
}

static void *dbhost_connect(struct dbengine *db, dbhost_t *dbhost)
{
    void *conn;

    syslog(LOG_DEBUG, "SQL backend trying to open db '%s' on host '%s' port '%s'%s",
	db->database, dbhost->hostname, dbhost->port ? dbhost->port : "",
	db->usessl ? " using SSL" : "");

    conn = dbengine->sql_open(dbhost->hostname, dbhost->port, db->usessl,
	db->user, db->password, db->database);
    if (conn) {
	dbhost->backoff_mark = (time_t)-1;
	dbhost->lastactive = time(NULL);
    }
    else {
	syslog(LOG_WARNING, "DBERROR: SQL backend could not connect to host '%s' port '%s'",
	    dbhost->hostname, dbhost->port ? dbhost->port : "");

	dbhost_failed(db, dbhost);
    }

    return conn;
}

static dbhost_t *dbhost_failover(struct dbengine *db, int idx, int untried)
{
    dbhost_t *dbhost;
    dbhost_t *activehost = NULL;
    void *activeconn = NULL;
    int i;

    for (i=0; !activehost && (i<db->hosts->count); i++, idx++) {
	if (idx >= db->hosts->count) {
	    idx = 0;
	}

	dbhost = (dbhost_t *)ptrarray_nth(db->hosts, idx);

	if ((untried && dbhost->tried) ||
	    ((dbhost->backoff_mark != (time_t)-1)
		&& (time(NULL) < dbhost->backoff_mark))
	    )
	{
	    continue;
	}

	/* here is a candidate */
	activehost = dbhost;
	activehost->tried = 1;
	if (db->activeidx != idx) {
	    /* make sure we can use it */
	    activeconn = dbhost_connect(db, activehost);
	    if (activeconn) {
		/* we got our new preferred active connection */
		if (db->conn) {
		    dbengine->sql_close(db->conn);
		}
		db->conn = activeconn;
		db->activeidx = idx;

		syslog(LOG_DEBUG, "SQL backend switched db '%s' connection to host '%s' port '%s'",
		    db->database, activehost->hostname,
		    activehost->port ? activehost->port : "");
	    }
	    else {
		activehost = NULL;
	    }
	}
	/* else: actually currently active */
    }

    return activehost;
}

static int _sql_exec(struct dbengine *db, int failover,
    const char *cmd, exec_cb *cb, void *rock)
{
    dbhost_t *activehost = NULL;
    int sql_res;
    int idx;
    int i;

    if (!db->hosts->count) {
	syslog(LOG_ERR, "DBERROR: could not open SQL database '%s': no hosts", db->database);
	return CYRUSDB_INTERNAL;
    }

    if (db->activeidx >= 0) {
	activehost = ptrarray_nth(db->hosts, db->activeidx);
    }

    if (!failover) {
	/* failover disabled for this query */
	if (db->conn) {
	    sql_res = dbengine->sql_exec(db->conn, cmd, cb, rock, NULL);
	}

	goto done;
    }

    /* If the active host is not our preferred one, check if we can now use a
     * more preferred one. */
    if (db->activeidx != 0) {
	activehost = dbhost_failover(db, 0, 0);
    }

    /* Safety net: at most, we will try each host once. */
    for (i=0; i<db->hosts->count; i++) {
	dbhost_t *dbhost = (dbhost_t *)ptrarray_nth(db->hosts, i);
	dbhost->tried = 0;
    }

    while (db->conn) {
	/* do the query now */
	sql_res = dbengine->sql_exec(db->conn, cmd, cb, rock, &failover);
	if (!failover) {
	    /* no need for failover */
	    break;
	}

	syslog(LOG_DEBUG, "SQL backend failover closing db '%s' connection to host '%s' port '%s'",
	    db->database, activehost->hostname,
	    activehost->port ? activehost->port : "");

	idx = db->activeidx;
	dbengine->sql_close(db->conn);
	db->conn = NULL;
	db->activeidx = -1;
	dbhost_failed(db, activehost);
	/* Note: we are supposed to be currently connected to the most
	 * preferred available host. So check the remaining ones.
	 * As a last chance if none works, dbhost_failover also checks if
	 * more preferred hosts, and the currently faulty one, became
	 * available again while we were playing around.
	 *
	 * Special case: if connection stayed idle beyond timeout, first try
	 * to reconnect before looking at the remaining hosts.
	 */
	if (!activehost->tried &&
	    (activehost->lastactive + db->idle_timeout < time(NULL)))
	{
	    syslog(LOG_DEBUG, "SQL backend failover trying to reconnect first");
	    activehost->backoff_mark = (time_t)-1;
	    /* trick to try current host first */
	    idx--;
	}
	activehost = dbhost_failover(db, idx + 1, 1);
	/* try again */
    }

  done:
    if (!db->conn) {
	/* bad news */
	sql_res = CYRUSDB_IOERROR;
    }

    /* update last activity time upon success */
    switch (sql_res) {
    case CYRUSDB_OK:
    case CYRUSDB_DONE:
    case CYRUSDB_EXISTS:
    case CYRUSDB_NOTFOUND:
	activehost->lastactive = time(NULL);
	break;

    default:
	break;
    }

    return sql_res;
}

static char *_sql_escape(struct dbengine *db, char **to,
    const char *from, size_t fromlen)
{
    /* some implementations (MySQL) require a connection ... */
    if (!db->conn) {
	dbhost_failover(db, 0, 0);
    }

    if (!db->conn) {
	/* bad news */
	syslog(LOG_ERR, "DBERROR: no SQL connection available");
	return NULL;
    }

    return dbengine->sql_escape(db->conn, to, from, fromlen);
}

static int myclose(struct dbengine *db)
{
    assert(db);

    if (db->conn) dbengine->sql_close(db->conn);
    if (db->database) free(db->database);
    if (db->user) free(db->user);
    if (db->password) free(db->password);
    if (db->table) free(db->table);
    if (db->esc_key) free(db->esc_key);
    if (db->esc_data) free(db->esc_data);
    if (db->data) free(db->data);
    if (db->hosts) {
	dbhost_t *dbhost = NULL;

	while ((dbhost = ptrarray_pop(db->hosts)) != NULL) {
	    free(dbhost->hostname);
	    if (dbhost->port) free(dbhost->port);
	}
	ptrarray_free(db->hosts);
    }
    free(db);

    return 0;
}

static int myopen(const char *fname, int flags, struct dbengine **ret)
{
    const char *database, *hostnames, *user, *passwd;
    char *host_ptr, *host, *cur_host, *cur_port;
    char *p, cmd[1024];
    struct dbengine *db;
    dbhost_t *dbhost;
    int r = 0;

    assert(fname);
    assert(ret);

    /* get database connection parameters */
    database = libcyrus_config_getstring(CYRUSOPT_SQL_DATABASE);
    hostnames = libcyrus_config_getstring(CYRUSOPT_SQL_HOSTNAMES);
    user = libcyrus_config_getstring(CYRUSOPT_SQL_USER);
    passwd = libcyrus_config_getstring(CYRUSOPT_SQL_PASSWD);

    db = *ret = (struct dbengine *) xzmalloc(sizeof(struct dbengine));
    db->hosts = ptrarray_new();
    db->activeidx = -1;
    if (user) db->user = xstrdup(user);
    if (passwd) db->password = xstrdup(passwd);
    db->usessl = libcyrus_config_getswitch(CYRUSOPT_SQL_USESSL);
    db->backoff_time = libcyrus_config_getint(CYRUSOPT_SQL_BACKOFF_TIME);
    db->idle_timeout = libcyrus_config_getint(CYRUSOPT_SQL_IDLE_TIMEOUT);

    /* create a working version of the hostnames */
    host_ptr = hostnames ? xstrdup(hostnames) : NULL;

    /* make sqlite clever */
    if (!database) database = fname;
    db->database = xstrdup(database);

    cur_host = host = host_ptr;
    while (cur_host != NULL) {
	host = strchr(host,',');
	if (host != NULL) {  
	    host[0] = '\0';

	    /* loop till we find some text */
	    while (!Uisalnum(host[0])) host++;
	}

	/* set the optional port */
	if ((cur_port = strchr(cur_host, ':'))) *cur_port++ = '\0';

	dbhost = (dbhost_t *)xzmalloc(sizeof(dbhost_t));
	dbhost->hostname = xstrdup(cur_host);
	dbhost->port = cur_port ? xstrdup(cur_port) : NULL;
	dbhost->backoff_mark = (time_t)-1;
	ptrarray_append(db->hosts, dbhost);

	cur_host = host;
    }

    if (host_ptr) free(host_ptr);

    /* get the name of the table and CREATE it if necessary */

    /* strip any path from the fname */
    p = strrchr(fname, '/');
    db->table = xstrdup(p ? ++p : fname);

    /* convert '.' to '_' */
    if ((p = strrchr(db->table, '.'))) *p = '_';

    /* check if the table exists */
    /* XXX is this the best way to do this? */
    snprintf(cmd, sizeof(cmd), "SELECT * FROM %s LIMIT 0;", db->table);

    if (_sql_exec(db, 1, cmd, NULL, NULL)) {
	if (db->conn && (flags & CYRUSDB_CREATE)) {
	    /* create the table */
	    snprintf(cmd, sizeof(cmd),
		     "CREATE TABLE %s (dbkey %s NOT NULL, data %s);",
		     db->table, dbengine->binary_type, dbengine->binary_type);
	    if (_sql_exec(db, 0, cmd, NULL, NULL)) {
		syslog(LOG_ERR, "DBERROR: SQL failed: %s", cmd);
		r = CYRUSDB_INTERNAL;
		goto done;
	    }
	}
	else {
	    r = db->conn ? CYRUSDB_NOTFOUND : CYRUSDB_INTERNAL;
	    goto done;
	}
    }

  done:
    if (r && db) {
	myclose(db);
	*ret = NULL;
    }

    return r;
}

static struct txn *start_txn(struct dbengine *db)
{
    /* start a transaction */
    if (_sql_exec(db, 1, dbengine->cmd_begin_txn, NULL, NULL)) {
	syslog(LOG_ERR, "DBERROR: failed to start txn on %s",
	       db->table);
	return NULL;
    }
    return xzmalloc(sizeof(struct txn));
}

struct select_rock {
    int found;
    struct txn *tid;
    foreach_cb *goodp;
    foreach_cb *cb;
    void *rock;
};

static int select_cb(void *rock,
		     const char *key, size_t keylen,
		     const char *data, size_t datalen)
{
    struct select_rock *srock = (struct select_rock *) rock;
    int r = CYRUSDB_OK;

    /* if we're in a transaction, save this key */
    if (srock->tid) {
	srock->tid->lastkey = xrealloc(srock->tid->lastkey, keylen);
	memcpy(srock->tid->lastkey, key, keylen);
	srock->tid->keylen = keylen;
    }

    /* see if we want this entry */
    if (!srock->goodp ||
	srock->goodp(srock->rock, key, keylen, data, datalen)) {

	srock->found = 1;

	/* make callback */
	if (srock->cb) r = srock->cb(srock->rock, key, keylen, data, datalen);
    }

    return r;
}

struct fetch_rock {
    char **data;
    size_t *datalen;
};

static int fetch_cb(void *rock,
		    const char *key __attribute__((unused)),
		    size_t keylen __attribute__((unused)),
		    const char *data, size_t datalen)
{
    struct fetch_rock *frock = (struct fetch_rock *) rock;

    if (frock->data) {
	*(frock->data) = xrealloc(*(frock->data), datalen);
	memcpy(*(frock->data), data, datalen);
    }
    if (frock->datalen) *(frock->datalen) = datalen;

    return 0;
}

static int fetch(struct dbengine *db, 
		 const char *key, size_t keylen,
		 const char **data, size_t *datalen,
		 struct txn **tid)
{
    char cmd[1024], *esc_key;
    size_t len = 0;
    struct fetch_rock frock = { &db->data, &len };
    struct select_rock srock = { 0, NULL, NULL, &fetch_cb, &frock };
    int r;

    assert(db);
    assert(key);
    assert(keylen);
    if (datalen) assert(data);

    if (data) *data = NULL;
    if (datalen) *datalen = 0;

    if (tid) {
	if (!*tid && !(*tid = start_txn(db))) return CYRUSDB_INTERNAL;
	srock.tid = *tid;
    }

    /* fetch the data */
    cmd[0] = 0;
    esc_key = _sql_escape(db, &db->esc_key, key, keylen);
    if (!esc_key && key) {
	r = CYRUSDB_INTERNAL;
	goto done;
    }
    snprintf(cmd, sizeof(cmd),
	     "SELECT * FROM %s WHERE dbkey = '%s';", db->table, esc_key);
    if (esc_key != db->esc_key) free(esc_key);
    r = _sql_exec(db, !tid, cmd, &select_cb, &srock);

  done:
    if (r) {
	if (cmd[0]) {
	    syslog(LOG_ERR, "DBERROR: SQL failed %s", cmd);
	}
	if (tid) _sql_exec(db, 0, dbengine->cmd_rollback_txn, NULL, NULL);
	return CYRUSDB_INTERNAL;
    }

    if (!srock.found) return CYRUSDB_NOTFOUND;

    if (data) *data = db->data;
    if (datalen) *datalen = len;

    return 0;
}

static int foreach(struct dbengine *db,
		   const char *prefix, size_t prefixlen,
		   foreach_p *goodp,
		   foreach_cb *cb, void *rock, 
		   struct txn **tid)
{
    char cmd[1024], *esc_key = NULL;
    struct select_rock srock = { 0, NULL, goodp, cb, rock };
    int r;

    assert(db);
    assert(cb);
    if (prefixlen) assert(prefix);

    if (tid) {
	if (!*tid && !(*tid = start_txn(db))) return CYRUSDB_INTERNAL;
	srock.tid = *tid;
    }

    /* fetch the data */
    cmd[0] = 0;
    if (prefixlen) /* XXX hack for SQLite */
	esc_key = _sql_escape(db, &db->esc_key, prefix, prefixlen);
    if (!esc_key && prefix) {
	r = CYRUSDB_INTERNAL;
	goto done;
    }
    snprintf(cmd, sizeof(cmd),
	     "SELECT * FROM %s WHERE dbkey LIKE '%s%%' ORDER BY dbkey;",
	     db->table, esc_key ? esc_key : "");
    if (esc_key && (esc_key != db->esc_key)) free(esc_key);
    r = _sql_exec(db, !tid, cmd, &select_cb, &srock);

  done:
    if (r) {
	if (cmd[0]) {
	    syslog(LOG_ERR, "DBERROR: SQL failed %s", cmd);
	}
	if (tid) _sql_exec(db, 0, dbengine->cmd_rollback_txn, NULL, NULL);
	return CYRUSDB_INTERNAL;
    }

    return 0;
}

static int mystore(struct dbengine *db, 
		   const char *key, int keylen,
		   const char *data, int datalen,
		   struct txn **tid, int overwrite,
		   int isdelete)
{
    char cmd[1024], *esc_key;
    int free_esc_key = 0;
    const char dummy = 0;
    int r = 0;

    assert(db);
    assert(key);
    assert(keylen);
    if (datalen) assert(data);

    if (!data) data = &dummy;

    if (tid && !*tid && !(*tid = start_txn(db))) return CYRUSDB_INTERNAL;

    cmd[0] = 0;
    esc_key = _sql_escape(db, &db->esc_key, key, keylen);
    if (!esc_key && key) {
	r = CYRUSDB_INTERNAL;
	goto done;
    }
    free_esc_key = (esc_key != db->esc_key);

    if (isdelete) {
	/* DELETE the entry */
	snprintf(cmd, sizeof(cmd), "DELETE FROM %s WHERE dbkey = '%s';",
		 db->table, esc_key);
	r = _sql_exec(db, !tid, cmd, NULL, NULL);

	/* see if we just removed the previously SELECTed key */
	if (!r && tid && *tid &&
	    (*tid)->keylen == strlen(esc_key) &&
	    !memcmp((*tid)->lastkey, esc_key, (*tid)->keylen)) {
	    (*tid)->keylen = 0;
	}
    }
    else {
	/* INSERT/UPDATE the entry */
	struct select_rock srock = { 0, NULL, NULL, NULL, NULL };

	char *esc_data = _sql_escape(db, &db->esc_data, data, datalen);
	if (!esc_data && data) {
	    r = CYRUSDB_INTERNAL;
	    goto done;
	}
	int free_esc_data = (esc_data != db->esc_data);

	/* see if we just SELECTed this key in this transaction */
	if (tid && *tid) {
	    if ((*tid)->keylen == strlen(esc_key) &&
		!memcmp((*tid)->lastkey, esc_key, (*tid)->keylen)) {
		srock.found = 1;
	    }
	    srock.tid = *tid;
	}

	/* check if the entry exists */
	if (!srock.found) {
	    snprintf(cmd, sizeof(cmd),
		     "SELECT * FROM %s WHERE dbkey = '%s';",
		     db->table, esc_key);
	    r = _sql_exec(db, !tid, cmd, &select_cb, &srock);
	}

	if (!r && srock.found) {
	    if (overwrite) {
		/* already have this entry, UPDATE it */
		snprintf(cmd, sizeof(cmd),
			 "UPDATE %s SET data = '%s' WHERE dbkey = '%s';",
			 db->table, esc_data, esc_key);
		r = _sql_exec(db, !tid, cmd, NULL, NULL);
	    }
	    else {
		if (tid) _sql_exec(db, 0, dbengine->cmd_rollback_txn, NULL, NULL);
		return CYRUSDB_EXISTS;
	    }
	}
	else if (!r && !srock.found) {
	    /* INSERT the new entry */
	    snprintf(cmd, sizeof(cmd),
		     "INSERT INTO %s VALUES ('%s', '%s');",
		     db->table, esc_key, esc_data);
	    r = _sql_exec(db, !tid, cmd, NULL, NULL);
	}

	if (free_esc_data) free(esc_data);
    }

  done:
    if (free_esc_key) free(esc_key);

    if (r) {
	if (cmd[0]) {
	    syslog(LOG_ERR, "DBERROR: SQL failed: %s", cmd);
	}
	if (tid) _sql_exec(db, 0, dbengine->cmd_rollback_txn, NULL, NULL);
	return CYRUSDB_INTERNAL;
    }

    return 0;
}

static int create(struct dbengine *db, 
		  const char *key, size_t keylen,
		  const char *data, size_t datalen,
		  struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 0, 0);
}

static int store(struct dbengine *db, 
		 const char *key, size_t keylen,
		 const char *data, size_t datalen,
		 struct txn **tid)
{
    return mystore(db, key, keylen, data, datalen, tid, 1, 0);
}

static int delete(struct dbengine *db, 
		  const char *key, size_t keylen,
		  struct txn **tid,
		  int force __attribute__((unused)))
{
    return mystore(db, key, keylen, NULL, 0, tid, 1, 1);
}

static int finish_txn(struct dbengine *db, struct txn *tid, int commit)
{
    if (tid) {
	int rc = _sql_exec(db, 0,
	    commit ? dbengine->cmd_commit_txn : dbengine->cmd_rollback_txn,
	    NULL, NULL);

	if (tid->lastkey) free(tid->lastkey);
	free(tid);

	if (rc) {
	    syslog(LOG_ERR, "DBERROR: failed to %s txn on %s",
		   commit ? "commit" : "abort", db->table);
	    return CYRUSDB_INTERNAL;
	}
    }

    return 0;
}

static int commit_txn(struct dbengine *db, struct txn *tid)
{
    assert(db);
    assert(tid);

    return finish_txn(db, tid, 1);
}

static int abort_txn(struct dbengine *db, struct txn *tid)
{
    assert(db);
    assert(tid);

    return finish_txn(db, tid, 0);
}

/* SQL databases have all sorts of evil collations - we can't
 * make any assumptions though, so just assume raw */
static int mycompar(struct dbengine *db, const char *a, int alen,
		    const char *b, int blen)
{
    return bsearch_ncompare_raw(a, alen, b, blen);
}

HIDDEN struct cyrusdb_backend cyrusdb_sql =
{
    "sql",			/* name */

    &init,
    &done,
    &cyrusdb_generic_sync,
    &cyrusdb_generic_noarchive,

    &myopen,
    &myclose,

    &fetch,
    &fetch,
    NULL,

    &foreach,
    &create,
    &store,
    &delete,

    &commit_txn,
    &abort_txn,

    NULL,
    NULL,
    NULL,
    &mycompar
};
