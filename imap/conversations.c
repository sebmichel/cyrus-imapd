/* conversations.c -- Routines for dealing with the conversation database
 *
 * Copyright (c) 1994-2010 Carnegie Mellon University.  All rights reserved.
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
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Carnegie Mellon University
 *      Center for Technology Transfer and Enterprise Creation
 *      4615 Forbes Avenue
 *      Suite 302
 *      Pittsburgh, PA  15213
 *      (412) 268-7393, fax: (412) 268-7395
 *      innovation@andrew.cmu.edu
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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <ctype.h>
#include <stdlib.h>

#include "acl.h"
#include "annotate.h"
#include "append.h"
#include "assert.h"
#include "charset.h"
#include "dlist.h"
#include "exitcodes.h"
#include "hash.h"
#include "imap_err.h"
#include "global.h"
#include "imapd.h"
#include "lsort.h"
#include "mailbox.h"
#include "map.h"
#include "mboxname.h"
#include "message.h"
#include "parseaddr.h"
#include "search_engines.h"
#include "seen.h"
#include "statuscache.h"
#include "strhash.h"
#include "stristr.h"
#include "util.h"
#include "xmalloc.h"
#include "xstrlcpy.h"
#include "xstrlcat.h"
#include "times.h"

#include "conversations.h"


#define CONVERSATION_ID_STRMAX	    (1+sizeof(conversation_id_t)*2)

/* per user conversations db extension */
#define FNAME_CONVERSATIONS_SUFFIX "conversations"

#define DB config_conversations_db

#define CONVERSATIONS_VERSION 0


char *conversations_getuserpath(const char *username)
{
    struct mboxname_parts parts;
    char *fname;

    if (mboxname_userid_to_parts(username, &parts))
	return NULL;
    fname = mboxname_conf_getpath(&parts, FNAME_CONVERSATIONS_SUFFIX);
    mboxname_free_parts(&parts);

    return fname;
}

char *conversations_getmboxpath(const char *mboxname)
{
    struct mboxname_parts parts;
    char *fname;

    if (mboxname_to_parts(mboxname, &parts))
	return NULL;
    fname = mboxname_conf_getpath(&parts, FNAME_CONVERSATIONS_SUFFIX);
    mboxname_free_parts(&parts);

    return fname;
}

static int _init_counted(struct conversations_state *state, const char *val)
{
    int r;
    const char *key = "$COUNTED_FLAGS";

    if (!val) {
	val = config_getstring(IMAPOPT_CONVERSATIONS_COUNTED_FLAGS);
	if (!val) val = "";
	r = DB->store(state->db, key, strlen(key), val, strlen(val), &state->txn);
	if (r) {
	    syslog(LOG_ERR, "Failed to write counted_flags");
	    return r;
	}
    }

    /* remove any existing value */
    if (state->counted_flags) {
	strarray_free(state->counted_flags);
	state->counted_flags = NULL;
    }

    /* add the value only if there's some flags set */
    if (strlen(val)) {
	state->counted_flags = strarray_split(val, " ");
    }

    return 0;
}

int conversations_open_path(const char *fname, struct conversations_state **statep)
{
    int r;
    struct conversations_open *open = NULL;
    const char *key = "$COUNTED_FLAGS";
    const char *val;
    int keylen = strlen(key);
    int vallen;
    char *counted = NULL;

    if (!fname)
	return IMAP_MAILBOX_BADNAME;

    for (open = open_conversations; open; open = open->next) {
	if (!strcmp(open->s.path, fname))
	    return IMAP_CONVERSATIONS_ALREADY_OPEN;
    }

    open = xzmalloc(sizeof(struct conversations_open));

    r = DB->open(fname, CYRUSDB_CREATE, &open->s.db);
    if (r || open->s.db == NULL) {
	free(open);
	return IMAP_IOERROR;
    }

    open->s.path = xstrdup(fname);
    open->next = open_conversations;
    open_conversations = open;

    /* ensure a write lock immediately, and also load the counted flags */
    r = DB->fetchlock(open->s.db, key, keylen, &val, &vallen, &open->s.txn);
    if (!r) {
	/* read a value, we'll use that */
	counted = xstrndup(val, vallen);
    }
    r = _init_counted(&open->s, counted);
    free(counted);

    if (!r)
	*statep = &open->s;

    return r;
}

int conversations_open_user(const char *username, struct conversations_state **statep)
{
    char *path = conversations_getuserpath(username);
    int r;
    if (!path) return IMAP_MAILBOX_BADNAME;
    r = conversations_open_path(path, statep);
    free(path);
    return r;
}

int conversations_open_mbox(const char *mboxname, struct conversations_state **statep)
{
    char *path = conversations_getmboxpath(mboxname);
    int r;
    if (!path) return IMAP_MAILBOX_BADNAME;
    r = conversations_open_path(path, statep);
    free(path);
    return r;
}

struct conversations_state *conversations_get_path(const char *fname)
{
    struct conversations_open *open = NULL;

    for (open = open_conversations; open; open = open->next) {
	if (!strcmp(open->s.path, fname))
	    return &open->s;
    }
    
    return NULL;
}

struct conversations_state *conversations_get_user(const char *username)
{
    struct conversations_state *state;
    char *path = conversations_getuserpath(username);
    if (!path) return NULL;
    state = conversations_get_path(path);
    free(path);
    return state;
}

struct conversations_state *conversations_get_mbox(const char *mboxname)
{
    struct conversations_state *state;
    char *path = conversations_getmboxpath(mboxname);
    if (!path) return NULL;
    state = conversations_get_path(path);
    free(path);
    return state;
}


void _conv_remove (struct conversations_state **statep)
{
    struct conversations_open **prevp = &open_conversations;
    struct conversations_open *cur;

    for (cur = open_conversations; cur; cur = cur->next) {
	if (*statep == &cur->s) {
	    /* found it! */
	    *prevp = cur->next;
	    free(cur->s.path);
	    if (cur->s.counted_flags)
		strarray_free(cur->s.counted_flags);
	    free(cur);
	    *statep = NULL;
	    return;
	}
	prevp = &cur->next;
    }

    fatal("unknown conversation db closed", EC_SOFTWARE);
}

int conversations_abort(struct conversations_state **statep)
{
    struct conversations_state *state = *statep;

    if (!state) return 0;
    
    if (state->db) {
	if (state->txn)
	    DB->abort(state->db, state->txn);
	DB->close(state->db);
    }

    _conv_remove(statep);

    return 0;
}

int conversations_commit(struct conversations_state **statep)
{
    struct conversations_state *state = *statep;
    int r = 0;

    if (!state) return 0;

    if (state->db) {
	if (state->txn)
	    r = DB->commit(state->db, state->txn);
	DB->close(state->db);
    }

    _conv_remove(statep);

    return r;
}

static int check_msgid(const char *msgid, int len, int *lenp)
{
    if (msgid == NULL)
	return IMAP_INVALID_IDENTIFIER;

    if (!len)
	len = strlen(msgid);

    if (msgid[0] != '<' || msgid[len-1] != '>' || strchr(msgid, '@') == NULL)
	return IMAP_INVALID_IDENTIFIER;

    if (lenp)
	*lenp = len;
    return 0;
}

static int _conversations_set_key(struct conversations_state *state,
				  const char *key, int keylen,
				  conversation_id_t cid, time_t stamp)
{
    int r;
    struct buf buf;
    int version = CONVERSATIONS_VERSION;

    buf_init(&buf);

    if (state->db == NULL)
	return IMAP_IOERROR;

    buf_printf(&buf, "%d " CONV_FMT " %lu", version, cid, stamp);

    r = DB->store(state->db,
		  key, keylen,
		  buf.s, buf.len,
		  &state->txn);

    buf_free(&buf);
    if (r)
	return IMAP_IOERROR;

    return 0;
}

int conversations_set_msgid(struct conversations_state *state,
			  const char *msgid,
			  conversation_id_t cid)
{
    int keylen;
    int r;

    r = check_msgid(msgid, 0, &keylen);
    if (r)
	return r;

    return _conversations_set_key(state, msgid, keylen, cid, time(NULL));
}

static int _conversations_parse(const char *data, int datalen,
				conversation_id_t *cidp, time_t *stampp)
{ 
    const char *rest;
    int restlen;
    int r;
    bit64 tval;
    bit64 version;

    r = parsenum(data, &rest, datalen, &version);
    if (r) return r;

    if (rest[0] != ' ')
	return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_VERSION) {
	/* XXX - an error code for "incorrect version"? */
	return IMAP_MAILBOX_BADFORMAT;
    }

    if (restlen < 17)
	return IMAP_MAILBOX_BADFORMAT;

    r = parsehex(rest, &rest, 16, cidp);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    if (rest[0] != ' ')
	return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    r = parsenum(rest, &rest, restlen, &tval);
    if (r) return IMAP_MAILBOX_BADFORMAT;

    /* should have parsed to the end of the string */
    if (rest - data != datalen)
	return IMAP_MAILBOX_BADFORMAT;

    if (stampp) *stampp = tval;

    return 0;
}

int conversations_get_msgid(struct conversations_state *state,
		          const char *msgid,
		          conversation_id_t *cidp)
{
    int keylen;
    int datalen = 0;
    const char *data;
    int r;

    r = check_msgid(msgid, 0, &keylen);
    if (r)
	return r;

    r = DB->fetch(state->db,
		  msgid, keylen,
		  &data, &datalen,
		  &state->txn);

    if (!r) r = _conversations_parse(data, datalen, cidp, NULL);

    if (r) *cidp = NULLCONVERSATION;

    return 0;
}

int _conversation_save(struct conversations_state *state,
		       const char *key, int keylen,
		       conversation_t *conv)
{
    struct dlist *dl, *n, *nn;
    struct buf buf = BUF_INITIALIZER;
    const conv_folder_t *folder;
    const conv_sender_t *sender;
    int version = CONVERSATIONS_VERSION;
    int i;
    int r = 0;

    /* see if any 'F' keys need to be changed */
    for (folder = conv->folders ; folder ; folder = folder->next) {
	int exists_diff = 0;
	int unseen_diff = 0;
	modseq_t modseq;
	uint32_t exists;
	uint32_t unseen;

	/* case: full removal of conversation - make sure to remove
	 * unseen as well */
	if (folder->exists) {
	    if (folder->prev_exists) {
		/* both exist, just check for unseen changes */
		unseen_diff = !!conv->unseen - !!conv->prev_unseen;
	    }
	    else {
		/* adding, check if it's unseen */
		exists_diff = 1;
		if (conv->unseen) unseen_diff = 1;
	    }
	}
	else if (folder->prev_exists) {
	    /* removing, check if it WAS unseen */
	    exists_diff = -1;
	    if (conv->prev_unseen) unseen_diff = -1;
	}
	else {
	    /* we don't care about unseen if the cid is not registered
	     * in this folder, and wasn't previously either */
	}

	/* XXX - it's super inefficient to be doing this for
	 * every cid in every folder in the transaction.  Big
	 * wins available by caching these in memory and writing
	 * once at the end of the transaction */
	r = conversation_getstatus(state, folder->mboxname,
				   &modseq, &exists, &unseen);
	if (r) goto done;
	if (exists_diff || unseen_diff || modseq < conv->modseq) {
	    if (modseq < conv->modseq) modseq = conv->modseq;
	    exists += exists_diff;
	    unseen += unseen_diff;
	    r = conversation_setstatus(state, folder->mboxname,
				       modseq, exists, unseen);
	    if (r) goto done;
	}
    }

    dl = dlist_newkvlist(NULL, NULL);
    dlist_setnum64(dl, "MODSEQ", conv->modseq);
    dlist_setnum32(dl, "EXISTS", conv->exists);
    dlist_setnum32(dl, "UNSEEN", conv->unseen);
    if (state->counted_flags) {
	n = dlist_newlist(dl, "COUNTS");
	for (i = 0; i < state->counted_flags->count; i++) {
	    const char *flag = strarray_nth(state->counted_flags, i);
	    dlist_setnum32(n, flag, conv->counts[i]);
	}
    }

    n = dlist_newlist(dl, "FOLDER");
    for (folder = conv->folders ; folder ; folder = folder->next) {
	nn = dlist_newkvlist(n, "FOLDER");
	dlist_setatom(nn, "MBOXNAME", folder->mboxname);
	dlist_setnum64(nn, "MODSEQ", folder->modseq);
	dlist_setnum32(nn, "EXISTS", folder->exists);
    }

    n = dlist_newlist(dl, "SENDER");
    for (sender = conv->senders ; sender ; sender = sender->next) {
	nn = dlist_newkvlist(n, "SENDER");
	/* envelope form */
	if (sender->name) dlist_setatom(nn, "NAME", sender->name);
	if (sender->route) dlist_setatom(nn, "ROUTE", sender->route);
	dlist_setatom(nn, "MAILBOX", sender->mailbox);
	dlist_setatom(nn, "DOMAIN", sender->domain);
    }

    buf_printf(&buf, "%d ", version);
    dlist_printbuf(dl, 0, &buf);
    dlist_free(&dl);

    r = DB->store(state->db,
		  key, keylen,
		  buf.s, buf.len,
		  &state->txn);

done:

    buf_free(&buf);
    if (!r)
	conv->dirty = 0;
    return r;
}

int conversation_save(struct conversations_state *state,
		      conversation_id_t cid,
		      conversation_t *conv)
{
    char bkey[CONVERSATION_ID_STRMAX+2];

    if (!conv)
	return IMAP_INTERNAL;
    if (!conv->dirty)
	return 0;

    /* old pre-conversations message, nothing to do */
    if (!cid)
	return 0;

    snprintf(bkey, sizeof(bkey), "B" CONV_FMT, cid);

    return _conversation_save(state, bkey, strlen(bkey), conv);
}

int conversation_getstatus(struct conversations_state *state,
			   const char *mboxname,
			   modseq_t *modseqp,
			   uint32_t *existsp,
			   uint32_t *unseenp)
{
    char *key = strconcat("F", mboxname, (char *)NULL);
    struct dlist *dl = NULL;
    struct dlist *n;
    const char *data;
    const char *rest;
    int datalen;
    int restlen;
    bit64 version;
    int r = IMAP_IOERROR;

    if (modseqp) *modseqp = 0;
    if (existsp) *existsp = 0;
    if (unseenp) *unseenp = 0;

    if (!state->db)
	goto done;

    r = DB->fetch(state->db,
		  key, strlen(key),
		  &data, &datalen,
		  &state->txn);

    if (r == CYRUSDB_NOTFOUND) {
	/* not existing is not an error */
	r = 0;
	goto done;
    } 
    if (r) goto done;

    r = parsenum(data, &rest, datalen, &version);
    if (r) goto done;

    if (rest[0] != ' ')
	return IMAP_MAILBOX_BADFORMAT;
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_VERSION) {
	/* XXX - an error code for "incorrect version"? */
	r = IMAP_MAILBOX_BADFORMAT;
	goto done;
    }

    r = dlist_parsemap(&dl, 0, rest, restlen);
    if (r) goto done;

    if (modseqp) {
	n = dlist_getchild(dl, "MODSEQ");
	if (n)
	    *modseqp = dlist_num(n);
    }
    if (existsp) {
	n = dlist_getchild(dl, "EXISTS");
	if (n)
	    *existsp = dlist_num(n);
    }
    if (unseenp) {
	n = dlist_getchild(dl, "UNSEEN");
	if (n)
	    *unseenp = dlist_num(n);
    }

 done:
    if (r)
	syslog(LOG_ERR, "IOERROR: conversations invalid status %s", mboxname);

    dlist_free(&dl);
    free(key);

    return r;
}

int conversation_setstatus(struct conversations_state *state,
			   const char *mboxname,
			   modseq_t modseq,
			   uint32_t exists,
			   uint32_t unseen)
{
    char *key = strconcat("F", mboxname, (char *)NULL);
    struct dlist *dl = NULL;
    struct buf buf = BUF_INITIALIZER;
    int r = IMAP_IOERROR;
    int version = CONVERSATIONS_VERSION;

    dl = dlist_newkvlist(NULL, NULL);
    dlist_setnum64(dl, "MODSEQ", modseq);
    dlist_setnum32(dl, "EXISTS", exists);
    dlist_setnum32(dl, "UNSEEN", unseen);

    buf_printf(&buf, "%d ", version);
    dlist_printbuf(dl, 0, &buf);
    dlist_free(&dl);

    r = DB->store(state->db,
		  key, strlen(key),
		  buf.s, buf.len,
		  &state->txn);

    buf_free(&buf);
    free(key);

    return r;
}

int _conversation_load(struct conversations_state *state,
		       const char *data, int datalen,
		       conversation_t **convp)
{
    const char *rest;
    int i;
    int restlen;
    bit64 version;
    struct dlist *dl = NULL;
    struct dlist *n, *nn;
    conversation_t *conv;
    conv_folder_t *folder;
    int r;

    r = parsenum(data, &rest, datalen, &version);
    if (r) {
	*convp = NULL;
	return 0;
    }

    if (rest[0] != ' ') {
	*convp = NULL;
	return 0;
    }
    rest++; /* skip space */
    restlen = datalen - (rest - data);

    if (version != CONVERSATIONS_VERSION) {
	*convp = NULL;
	return 0;
    }

    r = dlist_parsemap(&dl, 0, rest, restlen);
    if (r) return r;

    conv = conversation_new(state);

    n = dlist_getchild(dl, "MODSEQ");
    if (n)
	conv->modseq = dlist_num(n);
    n = dlist_getchild(dl, "EXISTS");
    if (n)
	conv->exists = dlist_num(n);
    n = dlist_getchild(dl, "UNSEEN");
    if (n)
	conv->unseen = dlist_num(n);
    if (state->counted_flags) {
	n = dlist_getchild(dl, "COUNTS");
	nn = n ? n->head : NULL;
	for (i = 0; i < state->counted_flags->count; i++) {
	    if (nn) {
		conv->counts[i] = dlist_num(nn);
		nn = nn->next;
	    }
	    else
		conv->counts[i] = 0;
	}
    }

    n = dlist_getchild(dl, "FOLDER");
    for (n = (n ? n->head : NULL) ; n ; n = n->next) {
	nn = dlist_getchild(n, "MBOXNAME");
	if (!nn)
	    continue;
	folder = conversation_add_folder(conv, nn->sval);

	nn = dlist_getchild(n, "MODSEQ");
	if (nn)
	    folder->modseq = dlist_num(nn);
	nn = dlist_getchild(n, "EXISTS");
	if (nn)
	    folder->exists = dlist_num(nn);

	folder->prev_exists = folder->exists;
    }

    n = dlist_getchild(dl, "SENDER");
    for (n = (n ? n->head : NULL) ; n ; n = n->next) {
	struct dlist *nn2, *nn3, *nn4;
	nn = dlist_getchild(n, "NAME");
	nn2 = dlist_getchild(n, "ROUTE");
	nn3 = dlist_getchild(n, "MAILBOX");
	nn4 = dlist_getchild(n, "DOMAIN");
	if (nn3 && nn4)
	    conversation_add_sender(conv, nn ? nn->sval : NULL,
				    nn2 ? nn2->sval : NULL,
				    nn3->sval, nn4->sval);
    }

    conv->prev_unseen = conv->unseen;

    dlist_free(&dl);
    conv->dirty = 0;
    *convp = conv;
    return 0;
}

int conversation_load(struct conversations_state *state,
		      conversation_id_t cid,
		      conversation_t **convp)
{
    const char *data;
    int datalen;
    char bkey[CONVERSATION_ID_STRMAX+2];
    int r;

    snprintf(bkey, sizeof(bkey), "B" CONV_FMT, cid);
    r = DB->fetch(state->db,
		  bkey, strlen(bkey),
		  &data, &datalen,
		  &state->txn);

    if (r == CYRUSDB_NOTFOUND) {
	*convp = NULL;
	return 0;
    } else if (r != CYRUSDB_OK) {
	return r;
    }

    r = _conversation_load(state, data, datalen, convp);
    if (r) {
	syslog(LOG_ERR, "IOERROR: conversations invalid conversation "
	       CONV_FMT, cid);
	*convp = NULL;
    }

    return 0;
}

static conv_folder_t *conversation_get_folder(conversation_t *conv,
					      const char *mboxname,
					      int create_flag)
{
    conv_folder_t *folder, **tailp = &conv->folders;

    /* first check if it already exists and find the tail */
    for (folder = conv->folders ; folder ; folder = folder->next) {
	if (!strcmp(folder->mboxname, mboxname))
	    return folder;
	tailp = &folder->next;
    }

    if (create_flag) {
	/* not found, create a new one at the end of the list */
	folder = xzmalloc(sizeof(*folder));
	folder->mboxname = xstrdup(mboxname);
	*tailp = folder;
	conv->dirty = 1;
    }

    return folder;
}

conv_folder_t *conversation_find_folder(conversation_t *conv,
				        const char *mboxname)
{
    return conversation_get_folder(conv, mboxname, /*create*/0);
}

conv_folder_t *conversation_add_folder(conversation_t *conv,
				       const char *mboxname)
{
    return conversation_get_folder(conv, mboxname, /*create*/1);
}

void conversation_add_sender(conversation_t *conv,
			     const char *name,
			     const char *route,
			     const char *mailbox,
			     const char *domain)
{
    conv_sender_t *sender, **tailp = &conv->senders;

    if (!mailbox || !domain) return;

    for (sender = conv->senders; sender; sender = sender->next) {
	if (!strcmp(sender->mailbox, mailbox) &&
	    !strcmp(sender->domain, domain)) {
	    /* found it.  Just check if we should update the name */
	    if (name && !sender->name) {
		sender->name = xstrdup(name);
		conv->dirty = 1;
	    }
	    return;
	}
	tailp = &sender->next;
    }

    sender = xzmalloc(sizeof(*sender));
    if (name) sender->name = xstrdup(name);
    if (route) sender->route = xstrdup(route);
    sender->mailbox = xstrdup(mailbox);
    sender->domain = xstrdup(domain);
    *tailp = sender;

    conv->dirty = 1;
}

static void _apply_delta(uint32_t *valp, int delta)
{
    if (delta >= 0) {
	*valp += delta;
    }
    else {
	uint32_t decrease = -delta;
	if (decrease > *valp)
	    *valp = 0;
	else
	    *valp -= decrease;
    }
}

void conversation_update(struct conversations_state *state,
			 conversation_t *conv, const char *mboxname,
			 int delta_exists, int delta_unseen,
			 int *delta_counts, modseq_t modseq)
{
    conv_folder_t *folder;
    int i;

    folder = conversation_add_folder(conv, mboxname);

    if (delta_exists) {
	_apply_delta(&conv->exists, delta_exists);
	_apply_delta(&folder->exists, delta_exists);
	conv->dirty = 1;
    }
    if (delta_unseen) {
	_apply_delta(&conv->unseen, delta_unseen);
	conv->dirty = 1;
    }
    if (state->counted_flags) {
	for (i = 0; i < state->counted_flags->count; i++) {
	    if (delta_counts[i]) {
		_apply_delta(&conv->counts[i], delta_counts[i]);
		conv->dirty = 1;
	    }
	}
    }
    if (modseq > conv->modseq) {
	conv->modseq = modseq;
	conv->dirty = 1;
    }
    if (modseq > folder->modseq) {
	folder->modseq = modseq;
	conv->dirty = 1;
    }
}

conversation_t *conversation_new(struct conversations_state *state)
{
    conversation_t *conv;

    conv = xzmalloc(sizeof(conversation_t));
    if (state->counted_flags)
	conv->counts = xzmalloc(sizeof(uint32_t) * state->counted_flags->count);
    conv->dirty = 1;

    return conv;
}

void conversation_free(conversation_t *conv)
{
    conv_folder_t *folder;
    conv_sender_t *sender;

    if (!conv) return;

    while ((folder = conv->folders)) {
	conv->folders = folder->next;
	free(folder->mboxname);
	free(folder);
    }

    while ((sender = conv->senders)) {
	conv->senders = sender->next;
	free(sender->name);
	free(sender->route);
	free(sender->mailbox);
	free(sender->domain);
	free(sender);
    }

    free(conv->counts);
    free(conv);
}


struct prune_rock {
    struct conversations_state *state;
    time_t thresh;
    unsigned int nseen;
    unsigned int ndeleted;
};

static int prunecb(void *rock,
		   const char *key, int keylen,
		   const char *data, int datalen)
{
    struct prune_rock *prock = (struct prune_rock *)rock;
    conversation_id_t cid;
    time_t stamp;
    int r;

    prock->nseen++;
    r = check_msgid(key, keylen, NULL);
    if (r) return r;

    r = _conversations_parse(data, datalen, &cid, &stamp);
    if (r) return r;

    /* keep records newer than the threshold */
    if (stamp >= prock->thresh)
	return 0;

    prock->ndeleted++;

    return DB->delete(prock->state->db,
		      key, keylen,
		      &prock->state->txn,
		      /*force*/1);
}

int conversations_prune(struct conversations_state *state,
			time_t thresh, unsigned int *nseenp,
			unsigned int *ndeletedp)
{
    struct prune_rock rock = { state, thresh, 0, 0 };

    DB->foreach(state->db, "<", 1, NULL, prunecb, &rock, &state->txn);

    if (nseenp)
	*nseenp = rock.nseen;
    if (ndeletedp)
	*ndeletedp = rock.ndeleted;

    return 0;
}

/* NOTE: this makes an "ATOM" return */
const char *conversation_id_encode(conversation_id_t cid)
{
    static char text[2*sizeof(cid)+1];

    if (cid != NULLCONVERSATION) {
	snprintf(text, sizeof(text), CONV_FMT, cid);
    } else {
	strncpy(text, "NIL", sizeof(text));
    }

    return text;
}

int conversation_id_decode(conversation_id_t *cid, const char *text)
{
    if (!strcmp(text, "NIL")) {
	*cid = NULLCONVERSATION;
    } else {
	if (strlen(text) != 16) return 0;
	*cid = strtoull(text, 0, 16);
    }
    return 1;
}

struct rename_rock {
    struct conversations_state *state;
    conversation_id_t from_cid;
    conversation_id_t to_cid;
    unsigned long entries_seen;
    unsigned long entries_renamed;
};

struct frename_rock {
    struct conversations_state *state;
    const char *from_name;
    const char *to_name;
    unsigned long entries_seen;
    unsigned long entries_renamed;
};

static int do_one_rename(void *rock,
		         const char *key, int keylen,
		         const char *data, int datalen)
{
    struct rename_rock *rrock = (struct rename_rock *)rock;
    conversation_id_t cid;
    time_t stamp;
    int r;

    r = check_msgid(key, keylen, NULL);
    if (r) return r;

    r = _conversations_parse(data, datalen, &cid, &stamp);
    if (r) return r;

    rrock->entries_seen++;

    if (cid != rrock->from_cid)
	return 0;	/* nothing to see, move along */

    rrock->entries_renamed++;

    return _conversations_set_key(rrock->state, key, keylen,
				  rrock->to_cid, stamp);
}

int conversations_rename_cid(struct conversations_state *state,
			     conversation_id_t from_cid,
			     conversation_id_t to_cid)
{
    struct rename_rock rrock;
    int r = 0;

    memset(&rrock, 0, sizeof(rrock));
    rrock.state = state;
    rrock.from_cid = from_cid;
    rrock.to_cid = to_cid;

    DB->foreach(state->db, "<", 1, NULL, do_one_rename, &rrock, &state->txn);

    syslog(LOG_NOTICE, "conversations_rename_cid: saw %lu entries, renamed %lu",
			rrock.entries_seen, rrock.entries_renamed);

    return r;
}

static int do_folder_rename(void *rock,
			    const char *key, int keylen,
			    const char *data, int datalen)
{
    struct frename_rock *frock = (struct frename_rock *)rock;
    conversation_t *conv = NULL;
    conv_folder_t *folder;
    conv_folder_t **prevp;
    int r = 0;

    _conversation_load(frock->state, data, datalen, &conv);
    if (!conv) return 0;

    frock->entries_seen++;

    prevp = &conv->folders;
    for (folder = conv->folders; folder; folder = folder->next) {
	if (strcmp(folder->mboxname, frock->from_name)) {
	    prevp = &folder->next;
	    continue;
	}

	if (frock->to_name) {
	    /* change the record */
	    free(folder->mboxname);
	    folder->mboxname = xstrdup(frock->to_name);
	}
	else {
	    /* remove the record */
	    *prevp = folder->next;
	    conv->exists -= folder->exists;
	    free(folder->mboxname);
	    free(folder);
	}

	r = _conversation_save(frock->state, key, keylen, conv);
	frock->entries_renamed++;
	break;
    }

    conversation_free(conv);

    return r;
}

static int folder_key_rename(struct conversations_state *state,
			     const char *from_name,
			     const char *to_name)
{
    const char *val;
    int vallen;
    char *oldkey = strconcat("F", from_name, (void *)NULL);
    char *newkey = NULL;
    int r = 0;

    r = DB->fetch(state->db, oldkey, strlen(oldkey),
		  &val, &vallen, &state->txn);
    if (r) goto done;

    DB->delete(state->db, oldkey, strlen(oldkey), &state->txn, 1);

    if (to_name) {
	newkey = strconcat("F", to_name, (void *)NULL);
	r = DB->store(state->db, newkey, strlen(newkey), val, vallen, &state->txn);
    }

 done:
    free(oldkey);
    free(newkey);

    return r;
}

int conversations_rename_folder(struct conversations_state *state,
			        const char *from_name,
			        const char *to_name)
{
    struct frename_rock frock;
    int r = 0;

    memset(&frock, 0, sizeof(frock));
    frock.state = state;
    frock.from_name = from_name;
    frock.to_name = to_name;

    /* alternatively, find all conversations named in the folder.
     * in a world with a million folders with a few conversations only
     * this would make sense - but that's not really likely, so this
     * is probably faster */

    DB->foreach(state->db, "B", 1, NULL, do_folder_rename, &frock, &state->txn);

    folder_key_rename(state, from_name, to_name);

    syslog(LOG_NOTICE, "conversations_rename_folder: saw %lu cids, renamed folder in %lu",
			frock.entries_seen, frock.entries_renamed);

    return r;
}


static int delete_cb(void *rock,
		     const char *key,
		     int keylen,
		     const char *val __attribute__((unused)),
		     int vallen __attribute__((unused)))
{
    struct conversations_state *state = (struct conversations_state *)rock;
    return DB->delete(state->db, key, keylen, &state->txn, 1);
}

int conversations_wipe_counts(struct conversations_state *state)
{
    int r = 0;
    /* wipe B counts */
    r = DB->foreach(state->db, "B", 1, NULL, delete_cb,
		    state, &state->txn);
    if (r) return r;

    /* wipe F counts */
    r = DB->foreach(state->db, "F", 1, NULL, delete_cb,
		    state, &state->txn);
    if (r) return r;

    /* wipe counted_flags */
    r = DB->delete(state->db, "$COUNTED_FLAGS", 14, &state->txn, 1);
    if (r) return r;

    return _init_counted(state, NULL);
}

void conversations_dump(struct conversations_state *state, FILE *fp)
{
    cyrusdb_dump(DB, state->db, "", 0, fp, &state->txn);
}

int conversations_truncate(struct conversations_state *state)
{
    return cyrusdb_truncate(DB, state->db, &state->txn);
}

int conversations_undump(struct conversations_state *state, FILE *fp)
{
    return cyrusdb_undump(DB, state->db, fp, &state->txn);
}

#undef DB