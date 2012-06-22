/* mboxevent.h -- interface for message store event notifications
 *
 * Copyright (c) 1994-2011 Carnegie Mellon University.  All rights reserved.
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
 *
 * Author: Sébastien Michel from Atos Worldline
 */

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <syslog.h>
#include <stdlib.h>

#include "assert.h"
#include "libconfig.h"
#include "hash.h"
#include "times.h"
#include "xmalloc.h"

#include "map.h"
#include "mboxevent.h"
#include "mboxname.h"
#include "notify.h"

#ifndef EVENT_VERSION
#define EVENT_VERSION 1
#endif

#if defined(__GNUC__) && __GNUC__ > 1
/* We can use the GCC union constructor extension */
#define EVTVAL(t,v)     (union event_param_value)((t)(v))
#else
#define EVTVAL(t,v)     {(void *)(v)}
#endif

#define EVENT(x) (1<<x)
#define MESSAGE_EVENTS(x) (x & (EVENT_MESSAGE_APPEND|EVENT_MESSAGE_EXPIRE|\
				EVENT_MESSAGE_EXPUNGE|EVENT_MESSAGE_NEW|\
				EVENT_MESSAGE_COPY|EVENT_MESSAGE_READ|\
				EVENT_MESSAGE_TRASH|EVENT_FLAGS_SET|\
				EVENT_FLAGS_CLEAR))

#define FILL_PARAM(e,p,t,v)     e->params[p].value = EVTVAL(t,v); e->params[p].filled = 1


/*
 * event parameters defined in RFC 5423 - Internet Message Store Events
 *
 * ordered to optimize the parsing of the notification message
 */
enum event_param {
    EVENT_HOST,
    EVENT_TIMESTAMP,
    EVENT_SERVICE,
    EVENT_SERVER_ADDRESS, /* gather serverDomain and serverPort together */
    EVENT_CLIENT_ADDRESS, /* gather clientIP and clientPort together */
    EVENT_DISK_QUOTA,
    EVENT_DISK_USED,
    EVENT_OLD_MAILBOX_ID,
    EVENT_OLD_UIDSET,
    EVENT_MAILBOX_ID,
    EVENT_MAX_MESSAGES,
    EVENT_MESSAGES,
    EVENT_NEW_MESSAGES,
    EVENT_UIDNEXT,
    EVENT_UIDSET,
    EVENT_MIDSET,
    EVENT_FLAG_NAMES,
    EVENT_USER,
    EVENT_MESSAGE_SIZE,
    EVENT_MODSEQ,
    EVENT_BODYSTRUCTURE,
    EVENT_MESSAGE_CONTENT
};


static const char *notifier = NULL;

static strarray_t *excluded_flags;
static strarray_t *excluded_specialuse;
static int enable_subfolder = 1;

static int enabled_events = 0;
static unsigned long extra_params;
static struct mboxevent event_template =
{ 0,
  { { "vnd.cmu.host", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "timestamp", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "service", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "serverAddress", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "clientAddress", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "diskQuota", EVENT_PARAM_INT, EVTVAL(long, 0), 0 },
    { "diskUsed", EVENT_PARAM_UINT, EVTVAL(quota_t, 0), 0 },
    { "oldMailboxID", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "vnd.cmu.oldUidset", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "mailboxID", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "maxMessages", EVENT_PARAM_INT, EVTVAL(long, 0), 0 },
    { "messages", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "vnd.cmu.newMessages", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "uidnext", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "uidset", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "vnd.cmu.midset", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "flagNames", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "user", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "messageSize", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "modseq", EVENT_PARAM_MODSEQT, EVTVAL(modseq_t, 0), 0 },
    /* always at end to let the parser to easily truncate this part */
    { "bodyStructure", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "messageContent", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 }
  },
  NULL, NULL, STRARRAY_INITIALIZER, { 0, 0 },
  NULL, BUF_INITIALIZER, NULL, NULL
};

#if 0
static char *properties_formatter(int event_type, struct event_parameter params[]);
#endif
static char *json_formatter(int event_type, struct event_parameter params[]);
#ifndef NDEBUG
static int filled_params(int event_type, struct mboxevent *mboxevent);
#endif
static int mboxevent_expected_param(int event_type, enum event_param param);


void mboxevent_init(void)
{
    const char *options;
    int groups;

    if (!(notifier = config_getstring(IMAPOPT_EVENTNOTIFIER)))
	return;

    /* some don't want to notify events for some IMAP flags */
    options = config_getstring(IMAPOPT_EVENT_EXCLUDE_FLAGS);
    excluded_flags = strarray_split(options, NULL);

    /* some don't want to notify events on some folders (ie. Sent, Spam) */
    /* identify those folders with IMAP SPECIAL-USE */
    options = config_getstring(IMAPOPT_EVENT_EXCLUDE_SPECIALUSE);
    excluded_specialuse = strarray_split(options, NULL);

    /* special meaning to disable event notification on all sub folders */
    if (strarray_find_case(excluded_specialuse, "ALL", 0) >= 0)
	enable_subfolder = 0;

    /* get event types's extra parameters */
    extra_params = config_getbitfield(IMAPOPT_EVENT_EXTRA_PARAMS);

    /* groups of related events to turn on notification */
    groups = config_getbitfield(IMAPOPT_EVENT_GROUPS);
    if (groups & IMAP_ENUM_EVENT_GROUPS_MESSAGE)
	enabled_events |= (EVENT_MESSAGE_APPEND|EVENT_MESSAGE_EXPIRE|\
			   EVENT_MESSAGE_EXPUNGE|EVENT_MESSAGE_NEW|\
			   EVENT_MESSAGE_COPY);

    if (groups & IMAP_ENUM_EVENT_GROUPS_QUOTA)
	enabled_events |= (EVENT_QUOTA_EXCEED|EVENT_QUOTA_WITHIN|\
			   EVENT_QUOTA_CHANGE);

    if (groups & IMAP_ENUM_EVENT_GROUPS_FLAGS)
	enabled_events |= (EVENT_MESSAGE_READ|EVENT_MESSAGE_TRASH|\
			   EVENT_FLAGS_SET|EVENT_FLAGS_CLEAR);

    if (groups & IMAP_ENUM_EVENT_GROUPS_ACCESS)
	enabled_events |= (EVENT_LOGIN|EVENT_LOGOUT);

    if (groups & IMAP_ENUM_EVENT_GROUPS_MAILBOX)
	enabled_events |= (EVENT_MAILBOX_CREATE|EVENT_MAILBOX_DELETE|\
			   EVENT_MAILBOX_RENAME|EVENT_MAILBOX_SUBSCRIBE|\
			   EVENT_MAILBOX_UNSUBSCRIBE);
}

static int mboxevent_enabled_for_mailbox(struct mailbox *mailbox)
{
    int i = 0;

    if (!enable_subfolder && (mboxname_isusermailbox(mailbox->name, 1)) == NULL) {
	return 0;
    }

    /* test if the mailbox has a special-use attribute in the exclude list */
    if (strarray_size(excluded_specialuse) > 0) {
	strarray_t *specialuse = NULL;
	const char *attribute;

	/* get info and set flags */
	specialuse = strarray_split(mailbox->specialuse, NULL);

	for (i = 0; i < strarray_size(specialuse) ; i++) {
	    attribute = strarray_nth(specialuse, i);
	    if (strarray_find(excluded_specialuse, attribute, 0) >= 0)
		return 0;
	}
    }

    return 1;
}

struct mboxevent *mboxevent_new(enum event_type type)
{
    struct mboxevent *mboxevent;

    /* event notification is completely disabled */
    if (!notifier)
	return NULL;

    /* the group to which belong the event is not enabled */
    if (!(enabled_events & type))
	return NULL;

    mboxevent = xmalloc(sizeof(struct mboxevent));
    memcpy(mboxevent, &event_template, sizeof(struct mboxevent));

    mboxevent->type = type;

    /* From RFC 5423:
     * the time at which the event occurred that triggered the notification
     * (...). This MAY be an approximate time.
     *
     * so it seems appropriate here */
    if (mboxevent_expected_param(type, EVENT_TIMESTAMP))
	gettimeofday(&mboxevent->timestamp, NULL);

    return mboxevent;
}

struct mboxevent *mboxevent_enqueue(enum event_type type,
                                    struct mboxevent **mboxevents)
{
    struct mboxevent *mboxevent, *ptr;

    if (!(mboxevent = mboxevent_new(type)))
	return NULL;

    if (mboxevents) {
	if (*mboxevents == NULL)
	    *mboxevents = mboxevent;
	else {
	    /* append the newly created event at end of the chained list */
	    ptr = *mboxevents;
	    while (ptr->next)
		ptr = ptr->next;
	    ptr->next = mboxevent;
	}
    }

    return mboxevent;
}

void mboxevent_free(struct mboxevent **mboxevent)
{
    struct mboxevent *next, *event = *mboxevent;
    int i;

    if (!event)
	return;

    do {
	seqset_free(event->uidset);
	seqset_free(event->olduidset);
	buf_free(&event->midset);

	if (event->mailboxid) {
	    free((char *)event->mailboxid->mailbox);
	    free(event->mailboxid);
	}
	if (event->oldmailboxid) {
	    free((char *)event->oldmailboxid->mailbox);
	    free(event->oldmailboxid);
	}

	for (i = 0; i <= EVENT_MESSAGE_CONTENT; i++) {
	    if (event->params[i].filled && event->params[i].t == EVENT_PARAM_DYNSTRING)
		free(event->params[i].value.s);
	}

	next = event->next;
	free(event);
	event = next;
    }
    while (event);

    *mboxevent = NULL;
}

static int mboxevent_expected_param(int event_type, enum event_param param)
{
    switch (param) {
    case EVENT_BODYSTRUCTURE:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_BODYSTRUCTURE) &&
	       (event_type & (EVENT_MESSAGE_NEW|EVENT_MESSAGE_APPEND));
    case EVENT_CLIENT_ADDRESS:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_CLIENTADDRESS) &&
	       (event_type & EVENT_LOGIN);
    case EVENT_DISK_QUOTA:
	return event_type & (EVENT_QUOTA_EXCEED|EVENT_QUOTA_WITHIN|\
			     EVENT_QUOTA_CHANGE);
    case EVENT_DISK_USED:
	return (event_type & (EVENT_QUOTA_EXCEED|EVENT_QUOTA_WITHIN));
	        /* XXX try to include diskUsed parameter to events below */
		/*|| ((extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_DISKUSED) &&
		 (event_type & (EVENT_MESSAGE_APPEND|EVENT_MESSAGE_NEW|\
				EVENT_MESSAGE_COPY|EVENT_MESSAGE_EXPUNGE)));*/
    case EVENT_FLAG_NAMES:
	return (event_type & (EVENT_FLAGS_SET|EVENT_FLAGS_CLEAR)) ||
	       ((extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_FLAGNAMES) &&
	        (event_type & (EVENT_MESSAGE_APPEND|EVENT_MESSAGE_NEW)));
    case EVENT_MAILBOX_ID:
	return !(event_type & (EVENT_LOGIN|EVENT_LOGOUT));
    case EVENT_MAX_MESSAGES:
	return event_type & (EVENT_QUOTA_EXCEED|EVENT_QUOTA_WITHIN|\
			     EVENT_QUOTA_CHANGE);
    case EVENT_MESSAGE_CONTENT:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGECONTENT) &&
	       (event_type & (EVENT_MESSAGE_APPEND|EVENT_MESSAGE_NEW));
    case EVENT_MESSAGE_SIZE:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGESIZE) &&
	       (event_type & (EVENT_MESSAGE_APPEND|EVENT_MESSAGE_NEW));
    case EVENT_MESSAGES:
	if (event_type & (EVENT_QUOTA_EXCEED|EVENT_QUOTA_WITHIN))
	    return 1;
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGES))
	    return 0;
	break;
    case EVENT_MODSEQ:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MODSEQ))
	    return 0;
	break;
    case EVENT_OLD_MAILBOX_ID:
	return event_type & (EVENT_MESSAGE_COPY|EVENT_MAILBOX_RENAME);
    case EVENT_SERVER_ADDRESS:
	return event_type & (EVENT_LOGIN|EVENT_LOGOUT);
    case EVENT_SERVICE:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_SERVICE;
    case EVENT_TIMESTAMP:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_TIMESTAMP;
    case EVENT_UIDNEXT:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_UIDNEXT))
	    return 0;
	break;
    case EVENT_UIDSET:
	break;
    case EVENT_USER:
	return event_type & (EVENT_MAILBOX_SUBSCRIBE|EVENT_MAILBOX_UNSUBSCRIBE|\
			     EVENT_LOGIN|EVENT_LOGOUT);
    case EVENT_HOST:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_HOST;
    case EVENT_MIDSET:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_MIDSET))
	    return 0;
	break;
    case EVENT_NEW_MESSAGES:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_NEWMESSAGES))
	    return 0;
	break;
    case EVENT_OLD_UIDSET:
	return event_type & EVENT_MESSAGE_COPY;
    }

    /* test if the parameter is related to a message event */
    return MESSAGE_EVENTS(event_type);
}

static void mboxevent_fill_uids(struct imapurl *imapurl, struct seqset **uids)
{
    if (*uids == NULL)
	return;

    /* add message's UID in IMAP URL if single message */
    if (seqset_first(*uids) == seqset_last(*uids)) {
	imapurl->uid = seqset_first(*uids);

	/* also don't send the uidset parameter */
	seqset_free(*uids);
	*uids = NULL;
    }
}

#define TIMESTAMP_MAX 32
void mboxevent_notify(struct mboxevent *mboxevents)
{
    char url[MAX_MAILBOX_PATH+1];
    int type;
    struct mboxevent *event, *next;
    char *formatted_message;
    char stimestamp[TIMESTAMP_MAX+1];

    /* nothing to notify */
    if (!mboxevents)
	return;

    event = mboxevents;

    /* swap FlagsSet and FlagsClear notification order depending the presence of
     * the \Seen flag because it changes the value of vnd.cmu.newMessages */
    if (event->type == EVENT_FLAGS_SET &&
	event->next &&
	event->next->type == EVENT_FLAGS_CLEAR &&
	strarray_find_case(&event->next->flagnames, "\\Seen", 0) >= 0) {

	next = event->next;
	event->next = next->next;
	next->next = event;
	event = next;
    }

    /* loop over the chained list of events */
    do {
	if (event->type == EVENT_CANCELLED)
	    goto next;

	/* others quota are not supported by RFC 5423 */
	if ((event->type & (EVENT_QUOTA_EXCEED|EVENT_QUOTA_WITHIN|EVENT_QUOTA_CHANGE)) &&
	    !event->params[EVENT_DISK_QUOTA].filled &&
	    !event->params[EVENT_MAX_MESSAGES].filled)
	    goto next;

	/* finish to fill event parameters structure */

	/* use an IMAP URL to refer to a mailbox or to a specific message */
	if (event->mailboxid) {
	    mboxevent_fill_uids(event->mailboxid, &event->uidset);

	    memset(url, 0, sizeof(url));
	    imapurl_toURL(url, event->mailboxid);
	    FILL_PARAM(event, EVENT_MAILBOX_ID, char *, strdup(url));
	}

	if (event->oldmailboxid) {
	    mboxevent_fill_uids(event->oldmailboxid, &event->olduidset);

	    memset(url, 0, sizeof(url));
	    imapurl_toURL(url, event->oldmailboxid);
	    FILL_PARAM(event, EVENT_OLD_MAILBOX_ID, char *, strdup(url));
	}

	if (mboxevent_expected_param(event->type, EVENT_SERVICE)) {
	    FILL_PARAM(event, EVENT_SERVICE, char *, config_ident);
	}

	if (mboxevent_expected_param(event->type, EVENT_TIMESTAMP)) {
	    timeval_to_iso8601(&event->timestamp, timeval_ms,
	                       stimestamp, sizeof(stimestamp));
	    FILL_PARAM(event, EVENT_TIMESTAMP, char *, stimestamp);
	}

	if (event->uidset) {
	    FILL_PARAM(event, EVENT_UIDSET, char *, seqset_cstring(event->uidset));
	}
	/* XXX this legacy parameter is not needed since mailboxID is an IMAP URL */
	if (mboxevent_expected_param(event->type, EVENT_HOST)) {
	    FILL_PARAM(event, EVENT_HOST, char *, config_servername);
	}
	if (buf_len(&event->midset) > 0) {
	    FILL_PARAM(event, EVENT_MIDSET, char *, buf_cstring(&event->midset));
	}
	if (event->olduidset) {
	    FILL_PARAM(event, EVENT_OLD_UIDSET, char *, seqset_cstring(event->olduidset));
	}

	/* may split FlagsSet event in several event notifications */
	do {
	    type = event->type;
	    /* prefer MessageRead and MessageTrash to FlagsSet as advised in the RFC */
	    if (type == EVENT_FLAGS_SET) {
		int i;

		if ((i = strarray_find(&event->flagnames, "\\Deleted", 0)) >= 0) {
		    type = EVENT_MESSAGE_TRASH;
		    strarray_remove(&event->flagnames, i);
		}
		else if ((i = strarray_find(&event->flagnames, "\\Seen", 0)) >= 0) {
		    type = EVENT_MESSAGE_READ;
		    strarray_remove(&event->flagnames, i);
		}
	    }

	    if (strarray_size(&event->flagnames) > 0) {
		/* don't send flagNames parameter for those events */
		if (type != EVENT_MESSAGE_TRASH && type != EVENT_MESSAGE_READ) {
		    char *flagnames = strarray_join(&event->flagnames, " ");
		    FILL_PARAM(event, EVENT_FLAG_NAMES, char *, flagnames);

		    /* stop to loop for flagsSet event here */
		    strarray_fini(&event->flagnames);
		}
	    }

	    /* check if expected event parameters are filled */
	    assert(filled_params(type, event));

	    /* notification is ready to send */
	    formatted_message = json_formatter(type, event->params);
	    notify(notifier, "EVENT", NULL, NULL, NULL, 0, NULL, formatted_message);
	}
	while (strarray_size(&event->flagnames) > 0);

    next:
	event = event->next;
    }
    while (event);

    return;
}

int mboxevent_add_system_flags(struct mboxevent *event, bit32 system_flags)
{
    if (system_flags & FLAG_DELETED) {
	if (strarray_find_case(excluded_flags, "\\Deleted", 0) < 0)
	    strarray_add_case(&event->flagnames, "\\Deleted");
    }
    if (system_flags & FLAG_ANSWERED) {
	if (strarray_find_case(excluded_flags, "\\Answered", 0) < 0)
	    strarray_add_case(&event->flagnames, "\\Answered");
    }
    if (system_flags & FLAG_FLAGGED) {
	if (strarray_find_case(excluded_flags, "\\Flagged", 0) < 0)
	    strarray_add_case(&event->flagnames, "\\Flagged");
    }
    if (system_flags & FLAG_DRAFT) {
	if (strarray_find_case(excluded_flags, "\\Draft", 0) < 0)
	    strarray_add_case(&event->flagnames, "\\Draft");
    }
    if (system_flags & FLAG_SEEN) {
	if (strarray_find_case(excluded_flags, "\\Seen", 0) < 0)
	    strarray_add_case(&event->flagnames, "\\Seen");
    }

    return strarray_size(&event->flagnames);
}


int mboxevent_add_user_flags(struct mboxevent *event,
                             const struct mailbox *mailbox, bit32 *user_flags)
{
    int flag;

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox->flagname[flag])
	    continue;
	if (!(user_flags[flag/32] & (1<<(flag&31))))
	    continue;

	if (strarray_find_case(excluded_flags, mailbox->flagname[flag], 0) < 0)
	    strarray_add_case(&event->flagnames, mailbox->flagname[flag]);
    }

    return strarray_size(&event->flagnames);
}

void mboxevent_add_flag(struct mboxevent *event, const char *flag)
{
    if (!event)
	return;

    if (mboxevent_expected_param(event->type, EVENT_FLAG_NAMES))
	strarray_add_case(&event->flagnames, flag);
}

void mboxevent_set_access(struct mboxevent *event,
                          const char *serveraddr, const char *clientaddr,
                          const char *userid)
{
    if (!event)
	return;

    /* only notify Logout after successful Login */
    if (!userid && event->type & EVENT_LOGOUT) {
	event->type = EVENT_CANCELLED;
    }

    if (serveraddr && mboxevent_expected_param(event->type, EVENT_SERVER_ADDRESS)) {
	FILL_PARAM(event, EVENT_SERVER_ADDRESS, char *, serveraddr);
    }
    if (clientaddr && mboxevent_expected_param(event->type, EVENT_CLIENT_ADDRESS)) {
	FILL_PARAM(event, EVENT_CLIENT_ADDRESS, char *, clientaddr);
    }
    if (userid && mboxevent_expected_param(event->type, EVENT_USER)) {
	FILL_PARAM(event, EVENT_USER, char *, userid);
    }
}

void mboxevent_extract_record(struct mboxevent *event, struct mailbox *mailbox,
                              struct index_record *record)
{
    const char *msgid = NULL;

    if (!event)
	return;

    /* add modseq */
    if (mboxevent_expected_param(event->type, EVENT_MODSEQ)) {
	if (event->uidset == NULL) {
	    FILL_PARAM(event, EVENT_MODSEQ, modseq_t, record->modseq);
	}
	else {
	    /* From RFC 5423:
	     * modseq May be included with any notification referring
	     * to one message.
	     *
	     * thus cancel inclusion of modseq parameter
	     */
	    event->params[EVENT_MODSEQ].filled = 0;
	}
    }

    /* add UID to uidset */
    if (event->uidset == NULL)
	event->uidset = seqset_init(0, SEQ_SPARSE);
    seqset_add(event->uidset, record->uid, 1);

    /* add Message-Id to midset or NIL if doesn't exists */
    if (mboxevent_expected_param(event->type, (EVENT_MIDSET))) {
	msgid = mailbox_cache_get_msgid(mailbox, record);

	if (buf_len(&event->midset) == 0)
	    buf_printf(&event->midset, "%s", msgid ? msgid : "NIL");
	else
	    buf_printf(&event->midset, " %s", msgid ? msgid : "NIL");
    }

    /* add message size */
    if (mboxevent_expected_param(event->type, EVENT_MESSAGE_SIZE)) {
	FILL_PARAM(event, EVENT_MESSAGE_SIZE, uint32_t, record->size);
    }

    /* add bodyStructure */
    if (mboxevent_expected_param(event->type, EVENT_BODYSTRUCTURE)) {
	FILL_PARAM(event, EVENT_BODYSTRUCTURE, char *,
	           strndup(cacheitem_base(record, CACHE_BODYSTRUCTURE),
	                   cacheitem_size(record, CACHE_BODYSTRUCTURE)));
    }
}

void mboxevent_extract_copied_record(struct mboxevent *event,
				     const struct mailbox *mailbox, uint32_t uid)
{
    if (!event)
	return;

    /* add the source message's UID to oldUidset */
    if (event->olduidset == NULL)
	event->olduidset = seqset_init(0, SEQ_SPARSE);
    seqset_add(event->olduidset, uid, 1);
}

void mboxevent_extract_content(struct mboxevent *event,
                               const struct index_record *record, FILE* content)
{
    const char *base = NULL;
    unsigned long len = 0;
    int offset, size, truncate;

    if (!event)
	return;

    if (!mboxevent_expected_param(event->type, EVENT_MESSAGE_CONTENT))
	return;

    truncate = config_getint(IMAPOPT_EVENT_CONTENT_SIZE);

    switch (config_getenum(IMAPOPT_EVENT_CONTENT_INCLUSION_MODE)) {
    /*  include message up to 'truncate' in size with the notification */
    case IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_STANDARD:
	if (!truncate || record->size <= truncate) {
	    offset = 0;
	    size = record->size;
	}
	else {
	    /* XXX RFC 5423 suggests to include a URLAUTH [RFC4467] reference
	     * for larger messages. IMAP URL of mailboxID seems enough though */
	    return;
	}
	break;
    /* include message truncated to a size of 'truncate' */
    case IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_MESSAGE:
	offset = 0;
	size = (truncate && (record->size > truncate)) ?
		truncate : record->size;
	break;
    /* include headers truncated to a size of 'truncate' */
    case IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_HEADER:
	offset = 0;
	size = (truncate && (record->header_size > truncate)) ?
		truncate : record->header_size;
	break;
    /* include body truncated to a size of 'truncate' */
    case IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_BODY:
	offset = record->header_size;
	size = (truncate && ((record->size - record->header_size) > truncate)) ?
		truncate : record->size - record->header_size;
	break;
    /* include full headers and body truncated to a size of 'truncate' */
    case IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_HEADERBODY:
	offset = 0;
	size = (truncate && ((record->size - record->header_size) > truncate)) ?
		record->header_size + truncate : record->size;
	break;
    /* never happen */
    default:
	return;
    }

    map_refresh(fileno(content), 1, &base, &len, record->size, "new message", 0);
    FILL_PARAM(event, EVENT_MESSAGE_CONTENT, char *, strndup(base+offset, size));
    map_free(&base, &len);
}

void mboxevent_extract_quota(struct mboxevent *event, const struct quota *quota,
                             enum quota_resource res)
{
    if (!event)
	return;

    switch(res) {
    case QUOTA_STORAGE:
	if (mboxevent_expected_param(event->type, EVENT_DISK_QUOTA)) {
	    FILL_PARAM(event, EVENT_DISK_QUOTA, long, quota->limits[res]);
	}
	if (mboxevent_expected_param(event->type, EVENT_DISK_USED)) {
	    FILL_PARAM(event, EVENT_DISK_USED, quota_t, quota->useds[res]/1024);
	}
	break;
    case QUOTA_MESSAGE:
	FILL_PARAM(event, EVENT_MAX_MESSAGES, long, quota->limits[res]);
	FILL_PARAM(event, EVENT_MESSAGES, long, quota->useds[res]);
	break;
    default:
	/* others quota are not supported by RFC 5423 */
	break;
    }

    /* From RFC 5423 :
     * The parameters SHOULD include at least the relevant user
     * and quota and, optionally, the mailbox.
     *
     * It seems that it does not correspond to the concept of
     * quota root specified in RFC 2087. Thus we fill mailboxID with quota root
     */
    if (!event->mailboxid && event->type & (EVENT_QUOTA_EXCEED|EVENT_QUOTA_WITHIN|EVENT_QUOTA_CHANGE)) {
	event->mailboxid = xzmalloc(sizeof(struct imapurl));
	event->mailboxid->server = config_servername;
	event->mailboxid->mailbox = strdup(quota->root);
    }
}

void mboxevent_extract_mailbox(struct mboxevent *event, struct mailbox *mailbox)
{
    if (!event)
	return;

    /* verify if event notification should be disabled for this mailbox  */
    if (!mboxevent_enabled_for_mailbox(mailbox)) {
	event->type = EVENT_CANCELLED;
	return;
    }

    /* verify that at least one message has been added depending the event type */
    if (MESSAGE_EVENTS(event->type) && event->uidset == NULL) {
	event->type = EVENT_CANCELLED;
	return;
    }

    assert(event->mailboxid == NULL);
    event->mailboxid = mboxevent_toURL(mailbox);

    if (mboxevent_expected_param(event->type, EVENT_UIDNEXT)) {
	FILL_PARAM(event, EVENT_UIDNEXT, uint32_t, mailbox->i.last_uid+1);
    }
    if (mboxevent_expected_param(event->type, EVENT_MESSAGES)) {
	FILL_PARAM(event, EVENT_MESSAGES, uint32_t, mailbox->i.exists);
    }
    if (mboxevent_expected_param(event->type, EVENT_NEW_MESSAGES)) {
	/* as event notification is focused on mailbox, we don't care about the
    	 * authenticated user but the mailbox's owner.
    	 * also the number of unseen messages is a non sense for public and
    	 * shared folders */
	FILL_PARAM(event, EVENT_NEW_MESSAGES, uint32_t, mailbox_count_unseen(mailbox));
    }
}

struct imapurl *mboxevent_toURL(const struct mailbox *mailbox)
{
    struct imapurl *url = xzmalloc(sizeof(struct imapurl));
    url->server = config_servername;
    url->mailbox = strdup(mailbox->name);
    url->uidvalidity = mailbox->i.uidvalidity;

    return url;
}

static const char *eventname(int type)
{
    switch (type) {
    case EVENT_MESSAGE_APPEND:
	return "MessageAppend";
    case EVENT_MESSAGE_EXPIRE:
	return "MessageExpire";
    case EVENT_MESSAGE_EXPUNGE:
	return "MessageExpunge";
    case EVENT_MESSAGE_NEW:
	return "MessageNew";
    case EVENT_MESSAGE_COPY:
	return "vnd.cmu.MessageCopy";
    case EVENT_QUOTA_EXCEED:
	return "QuotaExceed";
    case EVENT_QUOTA_WITHIN:
	return "QuotaWithin";
    case EVENT_QUOTA_CHANGE:
	return "QuotaChange";
    case EVENT_MESSAGE_READ:
    	return "MessageRead";
    case EVENT_MESSAGE_TRASH:
	return "MessageTrash";
    case EVENT_FLAGS_SET:
	return "FlagsSet";
    case EVENT_FLAGS_CLEAR:
	return "FlagsClear";
    case EVENT_LOGIN:
	return "Login";
    case EVENT_LOGOUT:
	return "Logout";
    case EVENT_MAILBOX_CREATE:
	return "MailboxCreate";
    case EVENT_MAILBOX_DELETE:
	return "MailboxDelete";
    case EVENT_MAILBOX_RENAME:
	return "MailboxRename";
    case EVENT_MAILBOX_SUBSCRIBE:
	return "MailboxSubscribe";
    case EVENT_MAILBOX_UNSUBSCRIBE:
	return "MailboxUnSubscribe";
    default:
	fatal("Unknown message event", EC_SOFTWARE);
    }

    /* never happen */
    return NULL;
}

#if 0
static char *properties_formatter(int event_type, struct event_parameter params[])
{
    struct buf buffer = BUF_INITIALIZER;
    char *val;
    int param;

    buf_printf(&buffer, "version=%d\n", EVENT_VERSION);
    buf_printf(&buffer, "event=%s\n", eventname(event_type));

    for (param = 0; param <= EVENT_MESSAGE_CONTENT; param++) {

	if (!params[param].filled)
	    continue;

	switch (param) {
	case EVENT_CLIENT_ADDRESS:
	    /* come from saslprops structure */
	    val = params[EVENT_CLIENT_ADDRESS].value.s;
	    buf_printf(&buffer, "clientIP=%.*s\n",
	               (int)(strchr(val, ';') - val), val);
	    buf_printf(&buffer, "clientPort=%s\n", strchr(val, ';') + 1);
	    break;
	case EVENT_SERVER_ADDRESS:
	    /* come from saslprops structure */
	    val = params[EVENT_SERVER_ADDRESS].value.s;
	    buf_printf(&buffer, "serverDomain=%.*s\n",
	               (int)(strchr(val, ';') - val), val);
	    buf_printf(&buffer, "serverPort=%s\n", strchr(val, ';') + 1);
	    break;
	default:
	    switch (params[param].t) {
	    case EVENT_PARAM_INT:
		buf_printf(&buffer, "%s=%ld\n",
		           params[param].name, params[param].value.i);
		break;
	    case EVENT_PARAM_UINT:
		buf_printf(&buffer, "%s=%u\n",
		           params[param].name, params[param].value.u);
		break;
	    case EVENT_PARAM_QUOTAT:
		buf_printf(&buffer, "%s=" QUOTA_T_FMT "\n",
		           params[param].name, params[param].value.q);
		break;
	    case EVENT_PARAM_MODSEQT:
		buf_printf(&buffer, "%s=" MODSEQ_FMT "\n",
		           params[param].name, params[param].value.m);
		break;
	    case EVENT_PARAM_STRING:
	    case EVENT_PARAM_DYNSTRING:
		buf_printf(&buffer, "%s=%s\n",
		           params[param].name, params[param].value.s);
		break;
	    }
	    break;
	}
    }

    return buf_release(&buffer);
}
#endif

const char *hex_chars = "0123456789abcdef";

static char *json_escape_str(const char *str)
{
    struct buf buffer = BUF_INITIALIZER;
    int pos = 0, start_offset = 0;
    unsigned char c;
    char *text, seq[8];

    do {
	c = str[pos];
	switch(c) {
	case '\0':
	    break;
	case '\b':
	    text = "\\b";
	    break;
	case '\n':
	    text = "\\n";
	    break;
	case '\r':
	    text = "\\r";
	    break;
	case '\t':
	    text = "\\t";
	    break;
	case '"':
	    text = "\\\"";
	    break;
	case '\\':
	    text = "\\\\";
	    break;
	case '/':
	    text = "\\/";
	    break;
	default:
	    if(c < ' ') {
		sprintf(seq, "\\u00%c%c", hex_chars[c >> 4], hex_chars[c & 0xf]);
		text = seq;
		break;
	    }
	    else {
		pos++;
		continue;
	    }
	}

	/* we encounter a character to escape or reach the end of the string */
	if (c) {
	    if (pos - start_offset > 0) {
		buf_appendmap(&buffer, str + start_offset, pos - start_offset);
	    }

	    buf_appendcstr(&buffer, text);
	    start_offset = ++pos;
	}
    }
    while(c);

    if (pos - start_offset > 0) {
	buf_appendmap(&buffer, str + start_offset, pos - start_offset);
    }

    return buf_release(&buffer);
}

static char *json_formatter(int event_type, struct event_parameter params[])
{
    struct buf buffer = BUF_INITIALIZER;
    char *val;
    int param;

    buf_printf(&buffer, "{\"event\":\"%s\"", eventname(event_type));

    for (param = 0; param <= EVENT_MESSAGE_CONTENT; param++) {

	if (!params[param].filled)
	    continue;

	switch (param) {
	case EVENT_CLIENT_ADDRESS:
	    /* come from saslprops structure */
	    val = params[EVENT_CLIENT_ADDRESS].value.s;
	    buf_printf(&buffer, ",\"clientIP\":\"%.*s\"",
	               (int)(strchr(val, ';') - val), val);
	    buf_printf(&buffer, ",\"clientPort\":%s", strchr(val, ';') + 1);
	    break;
	case EVENT_SERVER_ADDRESS:
	    /* come from saslprops structure */
	    val = params[EVENT_SERVER_ADDRESS].value.s;
	    buf_printf(&buffer, ",\"serverDomain\":\"%.*s\"",
	               (int)(strchr(val, ';') - val), val);
	    buf_printf(&buffer, ",\"serverPort\":%s", strchr(val, ';') + 1);
	    break;
	default:
	    switch (params[param].t) {
	    case EVENT_PARAM_INT:
		buf_printf(&buffer, ",\"%s\":%ld",
		           params[param].name, params[param].value.i);
		break;
	    case EVENT_PARAM_UINT:
		buf_printf(&buffer, ",\"%s\":%u",
		           params[param].name, params[param].value.u);
		break;
	    case EVENT_PARAM_MODSEQT:
		buf_printf(&buffer, ",\"%s\":" MODSEQ_FMT,
		           params[param].name, params[param].value.m);
		break;
	    case EVENT_PARAM_QUOTAT:
		buf_printf(&buffer, ",\"%s\":" QUOTA_T_FMT,
		           params[param].name, params[param].value.q);
		break;
	    case EVENT_PARAM_STRING:
	    case EVENT_PARAM_DYNSTRING:
		buf_printf(&buffer, ",\"%s\":\"%s\"",
		           params[param].name, json_escape_str(params[param].value.s));
		break;
	    }
	    break;
	}
    }
    buf_printf(&buffer, "}");

    return buf_release(&buffer);
}

#ifndef NDEBUG
/* overrides event->type with event_type because FlagsSet may be derived to
 * MessageTrash or MessageRead */
static int filled_params(int event_type, struct mboxevent *event)
{
    struct buf buffer = BUF_INITIALIZER;
    int param, ret = 1;

    for (param = 0; param <= EVENT_MESSAGE_CONTENT; param++) {

	if (mboxevent_expected_param(event_type, param) &&
		!event->params[param].filled) {
	    switch (param) {
	    case EVENT_DISK_QUOTA:
		return event->params[EVENT_MAX_MESSAGES].filled;
	    case EVENT_DISK_USED:
		return event->params[EVENT_MESSAGES].filled;
	    case EVENT_FLAG_NAMES:
		/* flagNames may be included with MessageAppend and MessageNew
		 * also we don't expect it here. */
		if (!(event_type & (EVENT_MESSAGE_APPEND|EVENT_MESSAGE_NEW)))
		    buf_appendcstr(&buffer, " flagNames");
		break;
	    case EVENT_MAX_MESSAGES:
		return event->params[EVENT_DISK_QUOTA].filled;
	    case EVENT_MESSAGE_CONTENT:
		/* messageContent is not included in standard mode if the size
		 * of the message exceed the limit */
		if (config_getenum(IMAPOPT_EVENT_CONTENT_INCLUSION_MODE) !=
			IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_STANDARD)
		    buf_appendcstr(&buffer, " messageContent");
		break;
	    case EVENT_MESSAGES:
		return event->params[EVENT_DISK_USED].filled;
	    case EVENT_MODSEQ:
		/* modseq is not included if notification refers to several
		 * messages */
		if (event->mailboxid->uid)
		    buf_appendcstr(&buffer, " modseq");
		break;
	    case EVENT_UIDSET:
		/* at least one UID must be found in mailboxID */
		if (!event->mailboxid->uid)
		    buf_appendcstr(&buffer, " uidset");
		break;
	    case EVENT_OLD_UIDSET:
		/* at least one UID must be found in oldMailboxID */
		if (!event->oldmailboxid->uid)
		    buf_appendcstr(&buffer, "oldUidset");
		break;
	    default:
		buf_appendcstr(&buffer, " ");
		buf_appendcstr(&buffer, event->params[param].name);
		break;
	    }
	}
    }

    if (buf_len(&buffer)) {
	syslog(LOG_ALERT, "Cannot notify event %s: missing parameters:%s",
	       eventname(event_type), buf_cstring(&buffer));
	ret = 0;
    }

    buf_free(&buffer);
    return ret;
}

#endif
