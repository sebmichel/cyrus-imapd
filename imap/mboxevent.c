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


static unsigned long extra_params;
static const char *notifier = NULL;
static strarray_t excludedflags;
static int enable_subfolder = 1;
static strarray_t exclude_folders;

#if 0
static char *properties_formatter(int event_type, const char **event_params);
#endif
static char *json_formatter(int event_type, const char **event_params);
#ifndef NDEBUG
static int filled_params(struct event_state *event);
#endif

#define MESSAGE_EVENTS(X) (X & (MessageAppend|MessageExpire|MessageExpunge|\
				MessageNew|vnd_cmu_MessageCopy|MessageRead|\
				MessageTrash|FlagsSet|FlagsClear))

void mboxevent_init(void)
{
    const char *options;

    if (!(notifier = config_getstring(IMAPOPT_EVENTNOTIFIER)))
	return;

    /* some don't want to notify events for some IMAP flags */
    if ((options = config_getstring(IMAPOPT_EVENT_EXCLUDE_FLAGS))) {
	char *tmpbuf, *cur_flag, *next_flag;

	strarray_init(&excludedflags);

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
	    strarray_append(&excludedflags, lcase(cur_flag));
	    cur_flag = next_flag;
	}

	free(tmpbuf);
    }

    /* some don't want to notify events on some folders (ie. Sent, Spam) */
    /* XXX Identify those folders with IMAP SPECIAL-USE */
    if ((options = config_getstring(IMAPOPT_EVENT_EXCLUDE_FOLDERS))) {
	char *tmpbuf, *cur_folder, *next_folder;

	strarray_init(&exclude_folders);

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
	    strarray_append(&exclude_folders, cur_folder);
	    cur_folder = next_folder;
	}

	free(tmpbuf);
    }

    /* get event types's extra parameters */
    extra_params = config_getbitfield(IMAPOPT_EVENT_EXTRA_PARAMS);
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
	for (i = 0; i < exclude_folders.count ; i++) {
	    excluded = strarray_nth(&exclude_folders, i);
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

    new_event = xzmalloc(sizeof(struct event_state));
    new_event->type = type;

    buf_init(&new_event->uidset);
    buf_init(&new_event->midset);
    buf_init(&new_event->olduidset);

    /* the time at which the event occurred that triggered the notification
     * it may be an approximate time, so it seems appropriate here */
    if (mboxevent_expected_params(type, event_timestamp))
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

    if (!event)
	return;

    do {
	buf_free(&event->midset);
	buf_free(&event->olduidset);
	buf_free(&event->uidset);

	if (event->bodystructure)
	    free(event->bodystructure);
	if (event->messagecontent)
	    free(event->messagecontent);
	if (event->mailboxid) {
	    free((char *)event->mailboxid->mailbox);
	    free(event->mailboxid);
	}
	if (event->oldmailboxid) {
	    free((char *)event->oldmailboxid->mailbox);
	    free(event->oldmailboxid);
	}

	next = event->next;
	free(event);
	event = next;
    }
    while (event);

    *event_state = NULL;
}

int mboxevent_expected_params(int event_type, enum event_param param)
{
    switch (param) {
    case event_bodyStructure:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_BODYSTRUCTURE) &&
	       (event_type & (MessageNew|MessageAppend));
    case event_clientIP:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_CLIENTIP) &&
	       (event_type & Login);
    case event_clientPort:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_CLIENTPORT) &&
	       (event_type & Login);
    case event_flagNames:
	return (event_type & (FlagsSet|FlagsClear)) ||
	       ((extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_FLAGNAMES) &&
	        (event_type & (MessageAppend|MessageNew)));
    case event_mailboxID:
	return !(event_type & (Login|Logout));
    case event_messageContent:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGECONTENT) &&
	       (event_type & (MessageAppend|MessageNew));
    case event_messageSize:
	return (extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGESIZE) &&
	       (event_type & (MessageAppend|MessageNew));
    case event_messages:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGES))
	    return 0;
	break;
    case event_oldMailboxID:
	return event_type & (vnd_cmu_MessageCopy|MailboxRename);
    case event_serverDomain:
	return event_type & (Login|Logout);
    case event_serverPort:
	return event_type & Login;
    case event_service:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_SERVICE;
    case event_timestamp:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_TIMESTAMP;
    case event_uidnext:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_UIDNEXT))
	    return 0;
	break;
    case event_uidset:
	break;
    case event_user:
	return event_type & (MailboxSubscribe|MailboxUnSubscribe|Login|Logout);
    case event_vnd_cmu_host:
	return extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_HOST;
    case event_vnd_cmu_midset:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_MIDSET))
	    return 0;
	break;
    case event_vnd_cmu_newMessages:
	if (!(extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_NEWMESSAGES))
	    return 0;
	break;
    case event_vnd_cmu_oldUidset:
	return event_type & vnd_cmu_MessageCopy;
    }

    /* test if the parameter is related to a message event */
    return MESSAGE_EVENTS(event_type);
}

void mboxevent_notify(struct event_state *event)
{
    char *url1 = xmalloc(MAX_MAILBOX_PATH+1);
    char *url2 = NULL;
    char *flagnames = NULL;
    uint32_t uid;
    int type;
    struct event_state *next;
    char *formatted_message;
    char timestamp[30];

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
	/* abort the notification */
	if (event->aborting)
	    goto next;

	/* check if expected event parameters are filled */
	assert(filled_params(event));

	event->params[event_bodyStructure_idx] = event->bodystructure;

	if (mboxevent_expected_params(event->type, event_clientIP))
	    event->params[event_clientIP_idx] = event->ipremoteport;
	if (mboxevent_expected_params(event->type, event_clientPort))
	    event->params[event_clientPort_idx] = event->ipremoteport;

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
	    imapurl_toURL(url1, event->mailboxid);
	    event->params[event_mailboxID_idx] = url1;
	}

	event->params[event_messageContent_idx] = event->messagecontent;
	if (*(event->messagesize))
	    event->params[event_messageSize_idx] = event->messagesize;

	if (*(event->messages))
	    event->params[event_messages_idx] = event->messages;

	if (event->oldmailboxid) {
	    if (url2 == NULL)
		url2 = xmalloc(MAX_MAILBOX_PATH+1);

	    /* add message's UID in IMAP URL if single message */
	    if (buf_len(&event->olduidset) &&
		!strchr(buf_cstring(&event->olduidset), ' ')) {

		parseuint32(buf_cstring(&event->olduidset), NULL, &uid);
		event->oldmailboxid->uid = uid;
		/* also don't send the oldUidset parameter */
		buf_reset(&event->olduidset);
	    }
	    imapurl_toURL(url2, event->oldmailboxid);
	    event->params[event_oldMailboxID_idx] = url2;
	}

	if (mboxevent_expected_params(event->type, event_serverDomain))
	    event->params[event_serverDomain_idx] = event->iplocalport;
	if (mboxevent_expected_params(event->type, event_serverPort))
	    event->params[event_serverPort_idx] = event->iplocalport;

	if (mboxevent_expected_params(event->type, event_service))
	    event->params[event_service_idx] = config_ident;

	if (mboxevent_expected_params(event->type, event_timestamp)) {
	    switch (config_getenum(IMAPOPT_EVENT_TIMESTAMP_FORMAT)) {
	    case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_EPOCH :
		sprintf(timestamp, "%ld%03ld\n", event->timestamp.tv_sec,
		        event->timestamp.tv_usec ? (event->timestamp.tv_usec/1000) : 0);
		break;
	    case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_ISO8601 :
		time_to_iso8601(event->timestamp.tv_sec,
		                event->timestamp.tv_usec/1000,
		                timestamp, sizeof(timestamp));
		break;
	    default:
		/* never happen */
		break;
	    }
	    event->params[event_timestamp_idx] = timestamp;
	}

	if (*(event->uidnext))
	    event->params[event_uidnext_idx] = event->uidnext;

	if (buf_len(&event->uidset) > 0)
	    event->params[event_uidset_idx] = buf_cstring(&event->uidset);

	event->params[event_user_idx] = event->user;

	/* XXX this legacy parameter is not needed since mailboxID is an IMAP URL */
	if (mboxevent_expected_params(event->type, event_vnd_cmu_host))
	    event->params[event_vnd_cmu_host_idx] = config_servername;

	if (buf_len(&event->midset) > 0)
	    event->params[event_vnd_cmu_midset_idx] = buf_cstring(&event->midset);

	if (*(event->newmessages))
	    event->params[event_vnd_cmu_newMessages_idx] = event->newmessages;


	if (buf_len(&event->olduidset) > 0)
	    event->params[event_vnd_cmu_oldUidset_idx] = buf_cstring(&event->olduidset);

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
		    flagnames = strarray_join(&event->flagnames, " ");
		    event->params[event_flagNames_idx] = flagnames;

		    /* stop to loop for flagsSet event here */
		    strarray_fini(&event->flagnames);
		}
	    }

	    /* notification is ready to send */
	    formatted_message = json_formatter(type, event->params);
	    notify(notifier, "EVENT", NULL, NULL, NULL, 0, NULL, formatted_message);

	    if (flagnames) {
		free(flagnames);
		event->params[event_flagNames_idx] = flagnames = NULL;
	    }

	}
	while (strarray_size(&event->flagnames) > 0);

	memset(url1, 0, sizeof(url1));
	if (url2)
	    memset(url2, 0, sizeof(url2));

     next:
	event = event->next;
    }
    while (event);

    free(url1);
    if (url2)
	free(url2);

    return;
}

int mboxevent_add_sysflags(struct event_state *event, bit32 sysflags)
{
    if (sysflags & FLAG_DELETED) {
	if (strarray_find(&excludedflags, "\\deleted", 0) < 0)
	    strarray_add(&event->flagnames, "\\Deleted");
    }
    if (sysflags & FLAG_ANSWERED) {
	if (strarray_find(&excludedflags, "\\answered", 0) < 0)
	    strarray_add(&event->flagnames, "\\Answered");
    }
    if (sysflags & FLAG_FLAGGED) {
	if (strarray_find(&excludedflags, "\\flagged", 0) < 0)
	    strarray_add(&event->flagnames, "\\Flagged");
    }
    if (sysflags & FLAG_DRAFT) {
	if (strarray_find(&excludedflags, "\\draft", 0) < 0)
	    strarray_add(&event->flagnames, "\\Draft");
    }
    if (sysflags & FLAG_SEEN) {
	if (strarray_find(&excludedflags, "\\seen", 0) < 0)
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

	if (strarray_find_case(&excludedflags, mailbox->flagname[flag], 0) < 0)
	    strarray_add(&event->flagnames, mailbox->flagname[flag]);
    }

    return strarray_size(&event->flagnames);
}

void mboxevent_add_flag(struct event_state *event, const char *flag)
{
    if (!event)
	return;

    if (mboxevent_expected_params(event->type, event_flagNames))
	strarray_add(&event->flagnames, flag);
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
    if (mboxevent_expected_params(event->type, event_vnd_cmu_midset)) {
	msgid = mailbox_cache_get_msgid(mailbox, record);

	if (buf_len(&event->midset) == 0)
	    buf_printf(&event->midset, "%s", msgid ? msgid : "NIL");
	else
	    buf_printf(&event->midset, " %s", msgid ? msgid : "NIL");
    }

    /* add message size */
    if (mboxevent_expected_params(event->type, event_messageSize))
	sprintf(event->messagesize, "%u", record->size);

    /* add bodyStructure */
    if (mboxevent_expected_params(event->type, event_bodyStructure)) {
	event->bodystructure = strndup(cacheitem_base(record, CACHE_BODYSTRUCTURE),
	                               cacheitem_size(record, CACHE_BODYSTRUCTURE));
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

    if (!mboxevent_expected_params(event->type, event_messageContent))
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
    event->messagecontent = strndup(base+offset, size);
    map_free(&base, &len);
}

void mboxevent_extract_mailbox(struct event_state *event, struct mailbox *mailbox)
{
    if (!event)
	return;

    if (!event_enabled_for_mailbox(mailbox->name)) {
	event->aborting = 1;
	return;
    }

    /* verify that at least one message has been added depending the event type */
    if (MESSAGE_EVENTS(event->type)) {
	if (buf_len(&event->uidset) == 0) {
	    event->aborting = 1;
	    return;
	}
    }

    assert(event->mailboxid == NULL);
    event->mailboxid = mboxevent_toURL(mailbox);

    if (mboxevent_expected_params(event->type, event_uidnext))
	sprintf(event->uidnext, "%u", mailbox->i.last_uid+1);

    if (mboxevent_expected_params(event->type, event_messages))
	sprintf(event->messages, "%u", mailbox->i.exists);

    if (mboxevent_expected_params(event->type, event_vnd_cmu_newMessages))
	/* as event notification is focused on mailbox, we don't care about the
    	 * authenticated user but the mailbox's owner.
    	 * also the number of unseen messages is a non sense for public and
    	 * shared folders */
	sprintf(event->newmessages, "%u", mailbox_count_unseen(mailbox));
}

struct imapurl *mboxevent_toURL(struct mailbox *mailbox)
{
    struct imapurl *url = xzmalloc(sizeof(struct imapurl));
    url->server = config_servername;
    url->mailbox = strdup(mailbox->name);
    url->uidvalidity = mailbox->i.uidvalidity;

    return url;
}

static const char *event2name(int type)
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
    const char *timestamp;

    buf_printf(&buffer, "version=%d\n", EVENT_VERSION);
    buf_printf(&buffer, "event=%s\n", event2name(event_type));

    if (event_params[event_vnd_cmu_host_idx] != NULL)
	buf_printf(&buffer, "vnd.cmu.host=%s\n", event_params[event_vnd_cmu_host_idx]);
    if ((timestamp = event_params[event_timestamp_idx]) != NULL)
	buf_printf(&buffer, "timestamp=%s\n", event_params[event_timestamp_idx]);
    if (event_params[event_oldMailboxID_idx] != NULL)
	buf_printf(&buffer, "oldMailboxID=%s\n", event_params[event_oldMailboxID_idx]);
    if (event_params[event_vnd_cmu_oldUidset_idx] != NULL)
	buf_printf(&buffer, "oldUidset=%s\n", event_params[event_vnd_cmu_oldUidset_idx]);
    if (event_params[event_mailboxID_idx] != NULL)
	buf_printf(&buffer, "mailboxID=%s\n", event_params[event_mailboxID_idx]);
    if (event_params[event_messages_idx] != NULL)
	buf_printf(&buffer, "messages=%s\n", event_params[event_messages_idx]);
    if (event_params[event_vnd_cmu_newMessages_idx] != NULL)
	buf_printf(&buffer, "vnd.cmu.newmessages=%s\n", event_params[event_vnd_cmu_newMessages_idx]);
    if (event_params[event_uidnext_idx] != NULL)
	buf_printf(&buffer, "uidnext=%s\n", event_params[event_uidnext_idx]);
    if (event_params[event_uidset_idx] != NULL)
	buf_printf(&buffer, "uidset=%s\n", event_params[event_uidset_idx]);
    if (event_params[event_vnd_cmu_midset_idx] != NULL)
	buf_printf(&buffer, "vnd.cmu.midset=%s\n", event_params[event_vnd_cmu_midset_idx]);
    if (event_params[event_flagNames_idx] != NULL)
	buf_printf(&buffer, "flagNames=%s\n", event_params[event_flagNames_idx]);
    if (event_params[event_user_idx] != NULL)
	buf_printf(&buffer, "user=%s\n", event_params[event_user_idx]);

    /* always at end of the notification message to optimize parsing */
    if (event_params[event_bodyStructure_idx] != NULL)
	buf_printf(&buffer, "bodyStructure=%s\n", event_params[event_bodyStructure_idx]);
    if (event_params[event_messageContent_idx] != NULL)
	buf_printf(&buffer, "messageContent=%s", event_params[event_messageContent_idx]);

    return buf_release(&buffer);
}
#endif

static char *json_formatter(int event_type, const char **event_params)
{
    struct buf buffer = BUF_INITIALIZER;
    const char *timestamp;

    buf_printf(&buffer, "{\"event\":\"%s\"", event2name(event_type));

    if (event_params[event_vnd_cmu_host_idx] != NULL)
	buf_printf(&buffer, ",\"vnd.cmu.host\":\"%s\"", event_params[event_vnd_cmu_host_idx]);

    if ((timestamp = event_params[event_timestamp_idx]) != NULL) {
	switch (config_getenum(IMAPOPT_EVENT_TIMESTAMP_FORMAT)) {
	case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_EPOCH :
	    buf_printf(&buffer, ",\"timestamp\":%s", timestamp);
	    break;
	case IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_ISO8601 :
	    buf_printf(&buffer, ",\"timestamp\":\"%s\"", timestamp);
	    break;
	default:
	    /* never happen */
	    break;
	}
    }
    if (event_params[event_service_idx] != NULL)
	buf_printf(&buffer, ",\"service\":\"%s\"", event_params[event_service_idx]);

    if (event_params[event_serverDomain_idx] != NULL)
	buf_printf(&buffer, ",\"serverDomain\":\"%.*s\"",
	           (int)(strchr(event_params[event_serverDomain_idx], ';') -
	           event_params[event_serverDomain_idx]),
	           event_params[event_serverDomain_idx]);
    if (event_params[event_serverPort_idx] != NULL)
	buf_printf(&buffer, ",\"serverPort\":%s",
	           strchr(event_params[event_serverPort_idx], ';') + 1);

    if (event_params[event_clientIP_idx] != NULL)
	buf_printf(&buffer, ",\"clientIP\":\"%.*s\"",
	           (int)(strchr(event_params[event_clientIP_idx], ';') -
		   event_params[event_clientIP_idx]),
		   event_params[event_clientIP_idx]);
    if (event_params[event_clientPort_idx] != NULL)
	buf_printf(&buffer, ",\"clientPort\":%s",
	           strchr(event_params[event_clientPort_idx], ';') + 1);

    if (event_params[event_oldMailboxID_idx] != NULL)
	buf_printf(&buffer, ",\"oldMailboxID\":\"%s\"",
	           event_params[event_oldMailboxID_idx]);
    if (event_params[event_vnd_cmu_oldUidset_idx] != NULL)
	buf_printf(&buffer, ",\"oldUidset\":\"%s\"",
	           event_params[event_vnd_cmu_oldUidset_idx]);

    if (event_params[event_mailboxID_idx] != NULL)
	buf_printf(&buffer, ",\"mailboxID\":\"%s\"",
	           event_params[event_mailboxID_idx]);
    if (event_params[event_messages_idx] != NULL)
	buf_printf(&buffer, ",\"messages\":%s", event_params[event_messages_idx]);
    if (event_params[event_vnd_cmu_newMessages_idx] != NULL)
	buf_printf(&buffer, ",\"vnd.cmu.newmessages\":%s",
	           event_params[event_vnd_cmu_newMessages_idx]);
    if (event_params[event_uidnext_idx] != NULL)
	buf_printf(&buffer, ",\"uidnext\":%s", event_params[event_uidnext_idx]);

    if (event_params[event_uidset_idx] != NULL)
	buf_printf(&buffer, ",\"uidset\":\"%s\"", event_params[event_uidset_idx]);
    if (event_params[event_vnd_cmu_midset_idx] != NULL)
	buf_printf(&buffer, ",\"vnd.cmu.midset\":\"%s\"",
	           event_params[event_vnd_cmu_midset_idx]);

    if (event_params[event_flagNames_idx] != NULL)
	buf_printf(&buffer, ",\"flagNames\":\"%s\"",
	           event_params[event_flagNames_idx]);

    if (event_params[event_user_idx] != NULL)
	buf_printf(&buffer, ",\"user\":\"%s\"", event_params[event_user_idx]);

    if (event_params[event_messageSize_idx] != NULL)
	buf_printf(&buffer, ",\"messageSize\":%s", event_params[event_messageSize_idx]);

    /* always at end of the notification message to optimize parsing */
    if (event_params[event_bodyStructure_idx] != NULL)
	/* XXX escape characters that don't comply with JSON format */
	buf_printf(&buffer, ",\"bodyStructure\":\"%s\"",
	           event_params[event_bodyStructure_idx]);
    if (event_params[event_messageContent_idx] != NULL)
	/* XXX escape characters that don't comply with JSON format */
	buf_printf(&buffer, ",\"messageContent\":\"%s\"",
	           event_params[event_messageContent_idx]);
    buf_printf(&buffer, "}");

    return buf_release(&buffer);
}

#ifndef NDEBUG
static int filled_params(struct event_state *event)
{
    struct buf buffer = BUF_INITIALIZER;
    int ret = 1;

    if (mboxevent_expected_params(event->type, event_bodyStructure) &&
	event->bodystructure == NULL)
	buf_appendcstr(&buffer, " bodyStructure");

    if (mboxevent_expected_params(event->type, event_clientIP) &&
	event->ipremoteport == NULL)
	buf_appendcstr(&buffer, " clientIP");

    if (mboxevent_expected_params(event->type, event_clientPort) &&
	event->ipremoteport == NULL)
	buf_appendcstr(&buffer, " clientPort");

    if (mboxevent_expected_params(event->type, event_flagNames) &&
	strarray_size(&event->flagnames) == 0) {
	/* flagNames may be included with MessageAppend and MessageNew also
	 * we don't expect it here. */
	if (!(event->type & (MessageAppend|MessageNew)))
	    buf_appendcstr(&buffer, " flagNames");
    }
    if (mboxevent_expected_params(event->type, event_mailboxID) &&
	event->mailboxid == NULL)
	buf_appendcstr(&buffer, " mailboxID");

    if (mboxevent_expected_params(event->type, event_messageContent) &&
	event->messagecontent == NULL)
	/* messageContent is not included in standard mode if the size of
	 * the message exceed the limit */
	if (config_getenum(IMAPOPT_EVENT_CONTENT_INCLUSION_MODE) !=
	    IMAP_ENUM_EVENT_CONTENT_INCLUSION_MODE_STANDARD)
	    buf_appendcstr(&buffer, " messageContent");

    if (mboxevent_expected_params(event->type, event_messages) &&
	*event->messages == 0)
	buf_appendcstr(&buffer, " messages");

    if (mboxevent_expected_params(event->type, event_oldMailboxID) &&
	event->oldmailboxid == NULL)
	buf_appendcstr(&buffer, " oldMailboxID");

    if (mboxevent_expected_params(event->type, event_serverDomain) &&
	event->iplocalport == NULL)
	buf_appendcstr(&buffer, " serverDomain");

    if (mboxevent_expected_params(event->type, event_serverPort) &&
	event->iplocalport == NULL)
	buf_appendcstr(&buffer, " serverPort");

    if (mboxevent_expected_params(event->type, event_timestamp) &&
    	event->timestamp.tv_sec == 0)
	buf_appendcstr(&buffer, " timestamp");

    if (mboxevent_expected_params(event->type, event_uidnext) &&
	*event->uidnext == 0)
	buf_appendcstr(&buffer, " uidnext");

    if (mboxevent_expected_params(event->type, event_uidset) &&
	buf_len(&event->uidset) == 0)
	buf_appendcstr(&buffer, " uidset");

    if (mboxevent_expected_params(event->type, event_user) &&
	event->user == NULL)
	buf_appendcstr(&buffer, " user");

    if (mboxevent_expected_params(event->type, event_vnd_cmu_midset) &&
	buf_len(&event->midset) == 0)
	buf_appendcstr(&buffer, " vnd.cmu.midset");

    if (mboxevent_expected_params(event->type, event_vnd_cmu_newMessages) &&
        *event->newmessages == 0)
	buf_appendcstr(&buffer, " vnd.cmu.newMessages");

    if (mboxevent_expected_params(event->type, event_vnd_cmu_oldUidset) &&
	buf_len(&event->olduidset) == 0)
	buf_appendcstr(&buffer, " vnd.cmu.oldUidset");

    if (buf_len(&buffer)) {
	syslog(LOG_ALERT, "Cannot notify event %s: missing parameters:%s",
	       event2name(event->type), buf_cstring(&buffer));
	ret = 0;
    }

    buf_free(&buffer);
    return ret;
}
#endif
