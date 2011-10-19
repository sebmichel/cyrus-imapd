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
#define MESSAGE_EVENTS(x) (x & (MessageAppend|MessageExpire|MessageExpunge|\
				MessageNew|vnd_cmu_MessageCopy|MessageRead|\
				MessageTrash|FlagsSet|FlagsClear))

#define FILL_PARAM(e,p,t,v)     e->params[p].value = EVTVAL(t,v); e->params[p].filled = 1


/*
 * event parameters defined in RFC 5423 - Internet Message Store Events
 *
 * numbered to optimize the parsing of the notification message
 */
enum event_param {
    bodyStructure = 18,
    clientAddress = 4, /* gather clientIP and clientPort together */
    diskQuota = 5,
    diskUsed = 6,
    flagNames = 15,
    mailboxID = 9,
    messageContent = 19,
    messageSize = 17,
    messages = 10,
    oldMailboxID = 7,
    serverAddress = 3, /* gather serverDomain and serverPort together */
    service = 2,
    timestamp = 1,
    uidnext = 12,
    uidset = 13,
    user = 16,
    /* below extra event parameters not defined in the RFC */
    vnd_cmu_host = 0,
    vnd_cmu_midset = 14,
    vnd_cmu_newMessages = 11,
    vnd_cmu_oldUidset = 8
};


static const char *notifier = NULL;
static char *eventnames[19];

static strarray_t excluded_flags;
static strarray_t excluded_folders;
static int enable_subfolder = 1;

static int enabled_events = 0;
static unsigned long extra_params;
static struct event_state event_template =
{ 0,
  { { "vnd.cmu.host", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "timestamp", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "service", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "serverAddress", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "clientAddress", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "diskQuota", EVENT_PARAM_INT, EVTVAL(long, 0), 0 },
    { "diskUsed", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "oldMailboxID", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "vnd.cmu.oldUidset", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "mailboxID", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "messages", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "vnd.cmu.newMessages", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "uidnext", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    { "uidset", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "vnd.cmu.midset", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "flagNames", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "user", EVENT_PARAM_STRING, EVTVAL(char *, NULL), 0 },
    { "messageSize", EVENT_PARAM_UINT, EVTVAL(uint32_t, 0), 0 },
    /* always at end to let the parser to easily truncate this part */
    { "bodyStructure", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 },
    { "messageContent", EVENT_PARAM_DYNSTRING, EVTVAL(char *, NULL), 0 }
  },
  NULL, NULL, STRARRAY_INITIALIZER, { 0, 0 },
  BUF_INITIALIZER, BUF_INITIALIZER, BUF_INITIALIZER, NULL
};

#if 0
static char *properties_formatter(int event_type, const char **event_params);
#endif
static char *json_formatter(int event_type, struct event_parameter params[]);
#ifndef NDEBUG
static int filled_params(int event_type, struct event_state *event);
#endif
static int mboxevent_expected_params(int event_type, enum event_param param);


void mboxevent_init(void)
{
    const char *options;
    int groups;

    if (!(notifier = config_getstring(IMAPOPT_EVENTNOTIFIER)))
	return;

    /* some don't want to notify events for some IMAP flags */
    if ((options = config_getstring(IMAPOPT_EVENT_EXCLUDE_FLAGS))) {
	char *tmpbuf, *cur_flag, *next_flag;

	strarray_init(&excluded_flags);

	/* make a working copy of the flags */
	cur_flag = tmpbuf = xstrdup(options);

	while (cur_flag) {
	    /* eat any leading whitespace */
	    while (Uisspace(*cur_flag)) cur_flag++;

	    /* find end of flag */
	    if ((next_flag = strchr(cur_flag, ' ')) ||
		(next_flag = strchr(cur_flag, '\t')))
		*next_flag++ = '\0';

	    /* add the flag to the list */
	    strarray_append(&excluded_flags, lcase(cur_flag));
	    cur_flag = next_flag;
	}

	free(tmpbuf);
    }

    /* some don't want to notify events on some folders (ie. Sent, Spam) */
    /* XXX Identify those folders with IMAP SPECIAL-USE ? */
    if ((options = config_getstring(IMAPOPT_EVENT_EXCLUDE_FOLDERS))) {
	char *tmpbuf, *cur_folder, *next_folder;

	strarray_init(&excluded_folders);

	/* make a working copy of the flags */
	cur_folder = tmpbuf = xstrdup(options);

	while (cur_folder) {
	    /* eat any leading whitespace */
	    while (Uisspace(*cur_folder)) cur_folder++;

	    /* find end of folder */
	    if ((next_folder = strchr(cur_folder, ' ')) ||
		(next_folder = strchr(cur_folder, '\t')))
		*next_folder++ = '\0';

	    /* special option to exclude all folders */
	    if (!strcasecmp(cur_folder, "ALL")) {
		enable_subfolder = 0;
		break;
	    }

	    /* add the folder to the list */
	    strarray_append(&excluded_folders, cur_folder);
	    cur_folder = next_folder;
	}

	free(tmpbuf);
    }

    /* get event types's extra parameters */
    extra_params = config_getbitfield(IMAPOPT_EVENT_EXTRA_PARAMS);

    /* groups of related events to turn on notification */
    groups = config_getbitfield(IMAPOPT_EVENT_GROUPS);
    if (groups & IMAP_ENUM_EVENT_GROUPS_MESSAGE)
	enabled_events |= (MessageAppend|MessageExpire|MessageExpunge|\
			   MessageNew|vnd_cmu_MessageCopy);
    if (groups & IMAP_ENUM_EVENT_GROUPS_QUOTA)
	enabled_events |= (QuotaExceed|QuotaWithin|QuotaChange);
    if (groups & IMAP_ENUM_EVENT_GROUPS_FLAGS)
	enabled_events |= (MessageRead|MessageTrash|FlagsSet|FlagsClear);
    if (groups & IMAP_ENUM_EVENT_GROUPS_ACCESS)
	enabled_events |= (Login|Logout);
    if (groups & IMAP_ENUM_EVENT_GROUPS_MAILBOX)
	enabled_events |= (MailboxCreate|MailboxDelete|MailboxRename|\
			   MailboxSubscribe|MailboxUnSubscribe);
}

static int event_enabled_for_mailbox(const char *name)
{
    const char *mailbox;
    int i = 0;

    if (name == NULL)
	return 0;

    /* XXX plan to support shared and public folder ? */
    if ((mailbox = mboxname_isusermailbox(name, 0)) == NULL) {
	return 0;
    }

    /* test only the first level of children hierarchy */
    mailbox = strchr(name+5, '.');
    if (!enable_subfolder && mailbox)
	return 0;

    /* disable event due to folder in the exclude list */
    if (mailbox) {
	const char *excluded;

	mailbox++;
	for (i = 0; i < excluded_folders.count ; i++) {
	    excluded = strarray_nth(&excluded_folders, i);
	    if (!strncasecmp(excluded, mailbox, strlen(excluded)))
		return 0;
	}
    }

    return 1;
}

struct event_state *event_newstate(int type, struct event_state **event)
{
    struct event_state *new_event, *ptr;

    /* event notification is completely disabled */
    if (!notifier)
	return NULL;

    /* the group to which belong the event is not enabled */
    if (!(enabled_events & type))
	return NULL;

    new_event = xmalloc(sizeof(struct event_state));
    memcpy(new_event, &event_template, sizeof(struct event_state));

    new_event->type = type;

    /* From RFC 5423:
     * the time at which the event occurred that triggered the notification
     * (...). This MAY be an approximate time.
     *
     * so it seems appropriate here */
    if (mboxevent_expected_params(type, timestamp))
	gettimeofday(&new_event->timestamp, NULL);

    if (event) {
	if (*event == NULL)
	    *event = new_event;
	else {
	    /* append the newly created event at end of the chained list */
	    ptr = *event;
	    while (ptr->next)
		ptr = ptr->next;
	    ptr->next = new_event;
	}
    }

    return new_event;
}

void mboxevent_free(struct event_state **event_state)
{
    struct event_state *next, *event = *event_state;
    int i;

    if (!event)
	return;

    do {
	buf_free(&event->midset);
	buf_free(&event->olduidset);
	buf_free(&event->uidset);

	if (event->mailboxid) {
	    free((char *)event->mailboxid->mailbox);
	    free(event->mailboxid);
	}
	if (event->oldmailboxid) {
	    free((char *)event->oldmailboxid->mailbox);
	    free(event->oldmailboxid);
	}

	for (i = 0; i <= messageContent; i++) {
	    if (event->params[i].filled && event->params[i].t == EVENT_PARAM_DYNSTRING)
		free(event->params[i].value.s);
	}

	next = event->next;
	free(event);
	event = next;
    }
    while (event);

    *event_state = NULL;
}

static int mboxevent_expected_params(int event_type, enum event_param param)
{
    switch (param) {
    case bodyStructure:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_BODYSTRUCTURE) &&
	       (event_type & (MessageNew|MessageAppend));
    case clientAddress:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_CLIENTADDRESS) &&
	       (event_type & Login);
    case diskQuota:
	return event_type & (QuotaExceed|QuotaWithin|QuotaChange);
    case diskUsed:
	return (event_type & (QuotaExceed|QuotaWithin));
	        /* XXX try to include diskUsed parameter to events below */
		/*|| ((extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_DISKUSED) &&
		 (event_type & (MessageAppend|MessageNew|vnd_cmu_MessageCopy|MessageExpunge)));*/
    case flagNames:
	return (event_type & (FlagsSet|FlagsClear)) ||
	       ((extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_FLAGNAMES) &&
	        (event_type & (MessageAppend|MessageNew)));
    case mailboxID:
	return !(event_type & (Login|Logout));
    case messageContent:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGECONTENT) &&
	       (event_type & (MessageAppend|MessageNew));
    case messageSize:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGESIZE) &&
	       (event_type & (MessageAppend|MessageNew));
    case messages:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGES))
	    return 0;
	break;
    case oldMailboxID:
	return event_type & (vnd_cmu_MessageCopy|MailboxRename);
    case serverAddress:
	return event_type & (Login|Logout);
    case service:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_SERVICE;
    case timestamp:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_TIMESTAMP;
    case uidnext:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_UIDNEXT))
	    return 0;
	break;
    case uidset:
	break;
    case user:
	return event_type & (MailboxSubscribe|MailboxUnSubscribe|Login|Logout);
    case vnd_cmu_host:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_HOST;
    case vnd_cmu_midset:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_MIDSET))
	    return 0;
	break;
    case vnd_cmu_newMessages:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_NEWMESSAGES))
	    return 0;
	break;
    case vnd_cmu_oldUidset:
	return event_type & vnd_cmu_MessageCopy;
    }

    /* test if the parameter is related to a message event */
    return MESSAGE_EVENTS(event_type);
}

void mboxevent_notify(struct event_state *event)
{
    char url[MAX_MAILBOX_PATH+1];
    uint32_t uid;
    int type;
    struct event_state *next;
    char *formatted_message;
    char stimestamp[30];

    /* nothing to notify */
    if (!event)
	return;

    /* swap FlagsSet and FlagsClear notification order depending the presence of
     * the \Seen flag because it changes the value of vnd.cmu.newmessages */
    if (event->type == FlagsSet &&
	event->next &&
	event->next->type == FlagsClear &&
	strarray_find_case(&event->next->flagnames, "\\Seen", 0) >= 0) {

	next = event->next;
	next->next = event;
	event->next = NULL;
	event = next;
    }

    /* loop over the chained list of events */
    do {
	if (event->type == CancelledEvent)
	    goto next;

	/* finish to fill event parameters structure */

	/* use an IMAP URL to refer to a mailbox or to a specific message */
	if (event->mailboxid) {
	    /* XXX store uidset in an array of uint32 to avoid such parsing */
	    /* add message's UID in IMAP URL if single message */
	    if (buf_len(&event->uidset) &&
		!strchr(buf_cstring(&event->uidset), ' ')) {

		parseuint32(buf_cstring(&event->uidset), NULL, &uid);
		event->mailboxid->uid = uid;
		/* also don't send the oldUidset parameter */
		buf_reset(&event->uidset);
	    }

	    memset(url, 0, sizeof(url));
	    imapurl_toURL(url, event->mailboxid);
	    FILL_PARAM(event, mailboxID, char *, strdup(url));
	}

	if (event->oldmailboxid) {
	    /* add message's UID in IMAP URL if single message */
	    if (buf_len(&event->olduidset) &&
		!strchr(buf_cstring(&event->olduidset), ' ')) {

		parseuint32(buf_cstring(&event->olduidset), NULL, &uid);
		event->oldmailboxid->uid = uid;
		/* also don't send the oldUidset parameter */
		buf_reset(&event->olduidset);
	    }

	    memset(url, 0, sizeof(url));
	    imapurl_toURL(url, event->oldmailboxid);
	    FILL_PARAM(event, oldMailboxID, char *, strdup(url));
	}

	if (mboxevent_expected_params(event->type, service)) {
	    FILL_PARAM(event, service, char *, config_ident);
	}

	if (mboxevent_expected_params(event->type, timestamp)) {
	    switch (config_getenum(IMAPOPT_EVENT_TIMESTAMP_FORMAT)) {
	    case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_EPOCH :
		sprintf(stimestamp, "%ld%03ld\n", event->timestamp.tv_sec,
		        event->timestamp.tv_usec ? (event->timestamp.tv_usec/1000) : 0);
		break;
	    case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_ISO8601 :
		time_to_iso8601(event->timestamp.tv_sec,
		                event->timestamp.tv_usec/1000,
		                stimestamp, sizeof(stimestamp));
		break;
	    default:
		/* never happen */
		break;
	    }
	    FILL_PARAM(event, timestamp, char *, stimestamp);
	}

	if (buf_len(&event->uidset) > 0) {
	    FILL_PARAM(event, uidset, char *, buf_cstring(&event->uidset));
	}
	/* XXX this legacy parameter is not needed since mailboxID is an IMAP URL */
	if (mboxevent_expected_params(event->type, vnd_cmu_host)) {
	    FILL_PARAM(event, vnd_cmu_host, char *, config_servername);
	}
	if (buf_len(&event->midset) > 0) {
	    FILL_PARAM(event, vnd_cmu_midset, char *, buf_cstring(&event->midset));
	}
	if (buf_len(&event->olduidset) > 0) {
	    FILL_PARAM(event, vnd_cmu_oldUidset, char *, buf_cstring(&event->olduidset));
	}

	/* may split FlagsSet event in several event notifications */
	do {
	    type = event->type;
	    /* prefer MessageRead and MessageTrash to FlagsSet as advised in the RFC */
	    if (type == FlagsSet) {
		int i;

		if ((i = strarray_find(&event->flagnames, "\\Deleted", 0)) >= 0) {
		    type = MessageTrash;
		    strarray_remove(&event->flagnames, i);
		}
		else if ((i = strarray_find(&event->flagnames, "\\Seen", 0)) >= 0) {
		    type = MessageRead;
		    strarray_remove(&event->flagnames, i);
		}
	    }

	    if (strarray_size(&event->flagnames) > 0) {
		/* don't send flagNames parameter for those events */
		if (type != MessageTrash && type != MessageRead) {
		    char *flagnames = strarray_join(&event->flagnames, " ");
		    FILL_PARAM(event, flagNames, char *, flagnames);

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

int mboxevent_add_sysflags(struct event_state *event, bit32 sysflags)
{
    if (sysflags & FLAG_DELETED) {
	if (strarray_find(&excluded_flags, "\\deleted", 0) < 0)
	    strarray_add(&event->flagnames, "\\Deleted");
    }
    if (sysflags & FLAG_ANSWERED) {
	if (strarray_find(&excluded_flags, "\\answered", 0) < 0)
	    strarray_add(&event->flagnames, "\\Answered");
    }
    if (sysflags & FLAG_FLAGGED) {
	if (strarray_find(&excluded_flags, "\\flagged", 0) < 0)
	    strarray_add(&event->flagnames, "\\Flagged");
    }
    if (sysflags & FLAG_DRAFT) {
	if (strarray_find(&excluded_flags, "\\draft", 0) < 0)
	    strarray_add(&event->flagnames, "\\Draft");
    }
    if (sysflags & FLAG_SEEN) {
	if (strarray_find(&excluded_flags, "\\seen", 0) < 0)
	    strarray_add(&event->flagnames, "\\Seen");
    }

    return strarray_size(&event->flagnames);
}


int mboxevent_add_usrflags(struct event_state *event, struct mailbox *mailbox,
			   bit32 *usrflags)
{
    int flag;

    for (flag = 0; flag < MAX_USER_FLAGS; flag++) {
	if (!mailbox->flagname[flag])
	    continue;
	if (!(usrflags[flag/32] & (1<<(flag&31))))
	    continue;

	if (strarray_find_case(&excluded_flags, mailbox->flagname[flag], 0) < 0)
	    strarray_add(&event->flagnames, mailbox->flagname[flag]);
    }

    return strarray_size(&event->flagnames);
}

void mboxevent_add_flag(struct event_state *event, const char *flag)
{
    if (!event)
	return;

    if (mboxevent_expected_params(event->type, flagNames))
	strarray_add(&event->flagnames, flag);
}

void mboxevent_extract_access(struct event_state *event,
                              const char *serveraddr, const char *clientaddr,
                              const char *userid)
{
    if (!event)
	return;

    if (serveraddr && mboxevent_expected_params(event->type, serverAddress)) {
	FILL_PARAM(event, serverAddress, char *, serveraddr);
    }
    if (clientaddr && mboxevent_expected_params(event->type, clientAddress)) {
	FILL_PARAM(event, clientAddress, char *, clientaddr);
    }
    if (userid && mboxevent_expected_params(event->type, user)) {
	FILL_PARAM(event, user, char *, userid);
    }
}

void mboxevent_extract_record(struct event_state *event, struct mailbox *mailbox,
			      struct index_record *record)
{
    const char *msgid = NULL;

    if (!event)
	return;

    /* add UID to uidset */
    if (buf_len(&event->uidset) == 0)
	buf_printf(&event->uidset, "%u", record->uid);
    else
	buf_printf(&event->uidset, " %u", record->uid);

    /* add Message-Id to midset or NIL if doesn't exists */
    if (mboxevent_expected_params(event->type, (vnd_cmu_midset))) {
	msgid = mailbox_cache_get_msgid(mailbox, record);

	if (buf_len(&event->midset) == 0)
	    buf_printf(&event->midset, "%s", msgid ? msgid : "NIL");
	else
	    buf_printf(&event->midset, " %s", msgid ? msgid : "NIL");
    }

    /* add message size */
    if (mboxevent_expected_params(event->type, messageSize)) {
	FILL_PARAM(event, messageSize, uint32_t, record->size);
    }

    /* add bodyStructure */
    if (mboxevent_expected_params(event->type, bodyStructure)) {
	FILL_PARAM(event, bodyStructure, char *,
	           strndup(cacheitem_base(record, CACHE_BODYSTRUCTURE),
	                   cacheitem_size(record, CACHE_BODYSTRUCTURE)));
    }
}

void mboxevent_extract_copied_record(struct event_state *event,
				     struct mailbox *mailbox, uint32_t uid)
{
    if (!event)
	return;

    /* add the source message's UID to oldUidset */
    if (buf_len(&event->olduidset) == 0)
	buf_printf(&event->olduidset, "%u", uid);
    else
	buf_printf(&event->olduidset, " %u", uid);
}

void mboxevent_extract_content(struct event_state *event,
                               struct index_record *record, FILE* content)
{
    const char *base = NULL;
    unsigned long len = 0;
    int offset, size, truncate;

    if (!event)
	return;

    if (!mboxevent_expected_params(event->type, messageContent))
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
    FILL_PARAM(event, messageContent, char *, strndup(base+offset, size));
    map_free(&base, &len);
}

void mboxevent_extract_quota(struct event_state *event, struct quota *quota)
{
    if (!event)
	return;

    if (mboxevent_expected_params(event->type, diskQuota)) {
	FILL_PARAM(event, diskQuota, long, quota->limit);
    }
    if (mboxevent_expected_params(event->type, diskUsed)) {
	FILL_PARAM(event, diskUsed, quota_t, quota->used/1024);
    }
}

void mboxevent_extract_mailbox(struct event_state *event, struct mailbox *mailbox)
{
    if (!event)
	return;

    /* verify that mailbox is not in exclude list  */
    if (!event_enabled_for_mailbox(mailbox->name)) {
	event->type = CancelledEvent;
	return;
    }

    /* verify that at least one message has been added depending the event type */
    if (MESSAGE_EVENTS(event->type)) {
	if (buf_len(&event->uidset) == 0) {
	    event->type = CancelledEvent;
	    return;
	}
    }

    assert(event->mailboxid == NULL);
    event->mailboxid = mboxevent_toURL(mailbox);

    if (mboxevent_expected_params(event->type, uidnext)) {
	FILL_PARAM(event, uidnext, uint32_t, mailbox->i.last_uid+1);
    }
    if (mboxevent_expected_params(event->type, messages)) {
	FILL_PARAM(event, messages, uint32_t, mailbox->i.exists);
    }
    if (mboxevent_expected_params(event->type, vnd_cmu_newMessages)) {
	/* as event notification is focused on mailbox, we don't care about the
    	 * authenticated user but the mailbox's owner.
    	 * also the number of unseen messages is a non sense for public and
    	 * shared folders */
	FILL_PARAM(event, vnd_cmu_newMessages, uint32_t, mailbox_count_unseen(mailbox));
    }
}

struct imapurl *mboxevent_toURL(struct mailbox *mailbox)
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
    case MessageAppend:
	return "MessageAppend";
    case MessageExpire:
	return "MessageExpire";
    case MessageExpunge:
	return "MessageExpunge";
    case MessageNew:
	return "MessageNew";
    case vnd_cmu_MessageCopy:
	return "vnd.cmu.MessageCopy";
    case QuotaExceed:
	return "QuotaExceed";
    case QuotaWithin:
	return "QuotaWithin";
    case QuotaChange:
	return "QuotaChange";
    case MessageRead:
    	return "MessageRead";
    case MessageTrash:
	return "MessageTrash";
    case FlagsSet:
	return "FlagsSet";
    case FlagsClear:
	return "FlagsClear";
    case Login:
	return "Login";
    case Logout:
	return "Logout";
    case MailboxCreate:
	return "MailboxCreate";
    case MailboxDelete:
	return "MailboxDelete";
    case MailboxRename:
	return "MailboxRename";
    case MailboxSubscribe:
	return "MailboxSubscribe";
    case MailboxUnSubscribe:
	return "MailboxUnSubscribe";
    default:
	fatal("Unknown message event", EC_SOFTWARE);
    }

    /* never happen */
    return NULL;
}

#if 0
static char *properties_formatter(int event_type, const char **event_params)
{
    struct buf buffer = BUF_INITIALIZER;

    buf_printf(&buffer, "version=%d\n", EVENT_VERSION);
    buf_printf(&buffer, "event=%s\n", eventname(event_type));

    for (event = 0; event <= messageContent; event++) {

	if (params[event].value == NULL)
	    continue;

	switch (params[event].type) {
	case INT_TYPE:
	    buf_printf(&buffer, "%s=%d\n",
	               params[event].name, params[event].value.i);
	    break;
	case UINT_TYPE:
	    buf_printf(&buffer, "%s=%u\n",
	               params[event].name, params[event].value.u);
	    break;
	case EVENT_PARAM_QUOTAT:
	    buf_printf(&buffer, "%s=" UQUOTA_T_FMT "\n",
	               params[param].name, params[param].value.q);
	    break;
	case STR_TYPE:
	case STR_DYN_TYPE:
	    buf_printf(&buffer, "%s=%s\n",
	               params[event].name, params[event].value.s);
	    break;
	}
    }

    return buf_release(&buffer);
}
#endif

static char *json_formatter(int event_type, struct event_parameter params[])
{
    struct buf buffer = BUF_INITIALIZER;
    const char *stimestamp;
    char *val;
    int param;

    buf_printf(&buffer, "{\"event\":\"%s\"", eventname(event_type));

    for (param = 0; param <= messageContent; param++) {

	if (!params[param].filled)
	    continue;

	switch (param) {
	case serverAddress:
	    /* come from saslprops structure */
	    val = params[serverAddress].value.s;
	    buf_printf(&buffer, ",\"serverDomain\":\"%.*s\"",
	               (int)(strchr(val, ';') - val), val);
	    buf_printf(&buffer, ",\"serverPort\":%s", strchr(val, ';') + 1);
	    break;
	case clientAddress:
	    /* come from saslprops structure */
	    val = params[clientAddress].value.s;
	    buf_printf(&buffer, ",\"clientIP\":\"%.*s\"",
	               (int)(strchr(val, ';') - val), val);
	    buf_printf(&buffer, ",\"clientPort\":%s", strchr(val, ';') + 1);
	    break;
	case timestamp:
	    stimestamp = params[timestamp].value.s;
	    switch (config_getenum(IMAPOPT_EVENT_TIMESTAMP_FORMAT)) {
	    case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_EPOCH :
		buf_printf(&buffer, ",\"timestamp\":%s", stimestamp);
		break;
	    case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_ISO8601 :
		buf_printf(&buffer, ",\"timestamp\":\"%s\"", stimestamp);
		break;
	    default:
		/* never happen */
		break;
	    }
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
	    case EVENT_PARAM_QUOTAT:
		buf_printf(&buffer, ",\"%s\":" UQUOTA_T_FMT,
		           params[param].name, params[param].value.q);
		break;
	    case EVENT_PARAM_STRING:
	    case EVENT_PARAM_DYNSTRING:
		buf_printf(&buffer, ",\"%s\":\"%s\"", params[param].name, (char *)params[param].value.s);
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
static int filled_params(int event_type, struct event_state *event)
{
    struct buf buffer = BUF_INITIALIZER;
    int param, ret = 1;

    for (param = 0; param <= messageContent; param++) {

	if (mboxevent_expected_params(event_type, param) &&
		!event->params[param].filled) {
	    switch (param) {
	    case flagNames:
		/* flagNames may be included with MessageAppend and MessageNew
		 * also we don't expect it here. */
		if (!(event_type & (MessageAppend|MessageNew)))
		    buf_appendcstr(&buffer, " flagNames");
		break;
	    case messageContent:
		/* messageContent is not included in standard mode if the size
		 * of the message exceed the limit */
		if (config_getenum(IMAPOPT_EVENT_CONTENT_INCLUSION_MODE) !=
			IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_STANDARD)
		    buf_appendcstr(&buffer, " messageContent");
		break;
	    case uidset:
		/* at least one UID must be found in mailboxID */
		if (!event->mailboxid->uid)
		    buf_appendcstr(&buffer, " uidset");
		break;
	    case vnd_cmu_oldUidset:
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
