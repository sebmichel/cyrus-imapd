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
#include "imapurl.h"
#include "libconfig.h"
#include "times.h"
#include "util.h"
#include "xmalloc.h"

#include "mboxevent.h"
#include "notify.h"

/* XXX declare version 2 for internal use */
#define EVENT_VERSION 1

static int extra_params = 0;
static const char *notifier = NULL;
static strarray_t excludedflags;
static int enable_subfolder = 1;
static strarray_t exclude_folders;

#define mboxevent_free(e) mboxevent_abort((struct event_state *)e)


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
    unsigned long event_extra_params =
	    config_getbitfield(IMAPOPT_EVENT_EXTRA_PARAMS);

    if (event_extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_FLAGNAMES)
    	extra_params |= event_flagnames;
    if (event_extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_MESSAGES)
	extra_params |= event_messages;
    if (event_extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_TIMESTAMP)
	extra_params |= event_timestamp;
    if (event_extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_UIDNEXT)
	extra_params |= event_uidnext;
    if (event_extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_HOST)
	extra_params |= event_vnd_cmu_host;
    if (event_extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_MIDSET)
	extra_params |= event_vnd_cmu_midset;
    if (event_extra_params & IMAP_ENUM_EVENT_EXTRA_PARAMS_VND_CMU_NEWMESSAGES)
	extra_params |= event_vnd_cmu_newMessages;
}

int mboxevent_enabled_for_folder(const char *event, const char *folder)
{
    const char *subfolder;
    int i = 0;

    if (folder == NULL)
	return 0;

    /* XXX plan to support shared and public folder ? */
    if (strncmp("user.", folder, 5) != 0)
	return 0;

    /* test only the first level of children hierarchy */
    subfolder = strchr(folder+5, '.');
    if (!enable_subfolder && subfolder)
	return 0;

    /* disable event due to folder in the exclude list */
    if (subfolder) {
	subfolder++;
	for (i = 0; i < exclude_folders.count ; i++) {
	    if (!strcasecmp(strarray_nth(&exclude_folders, i), subfolder))
		return 0;
	}
    }

    return 1;
}

struct event_state *event_newstate(int type, struct event_state *event)
{
    /* event notification is completely disabled */
    if (!notifier)
    	return NULL;

    /* detect notification reused but not properly sent or aborted */
    assert(event && event->state == EVENT_INIT);

    /* the time at which the event occurred that triggered the notification
       it may be an approximate time, so it seems appropriate here */
    gettimeofday(&event->timestamp, NULL);

    event->type = type;

    /* add common extra parameters first */
    event->extraparams = (extra_params & (event_timestamp|event_vnd_cmu_host));

    /* add extra parameters for events that make sense */
    switch (event->type) {
    case MessageAppend:
    case MessageNew:
    case vnd_cmu_MessageCopy:
	event->extraparams |= (extra_params & event_flagnames);
    case MessageExpunge:
    case MessageRead:
    case MessageTrash:
    case FlagsSet:
    case FlagsClear:
	event->extraparams |= (extra_params & (event_messages|
					       event_vnd_cmu_newMessages|
					       event_vnd_cmu_midset|
					       event_uidnext));
    }
    buf_init(&event->uidset);
    buf_init(&event->midset);

    event->state = EVENT_READY;
    return event;
}

void mboxevent_abort(struct event_state *event)
{
    assert(event);

    buf_reset(&event->uidset);
    buf_reset(&event->midset);

    if (event->mailbox)
	free(event->mailbox);
    if (event->oldmailboxid)
	free(event->oldmailboxid);

    memset(event, 0, sizeof(struct event_state));
}

static const char *event2name(int event_type)
{
    switch (event_type) {
    case MessageAppend:
	return "MessageAppend";
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
    case MailboxCreate:
	return "MailboxCreate";
    case MailboxDelete:
	return "MailboxDelete";
    case MailboxRename:
	return "MailboxRename";
    default:
	fatal("Unknown message event", EC_SOFTWARE);
    }

    /* never append */
    return NULL;
}

void mboxevent_notify(struct event_state *event)
{
    struct buf buffer = BUF_INITIALIZER;
    int event_type;
    bit32 noflag[MAX_USER_FLAGS/32];
    struct imapurl mailboxid;
    char *url = xmalloc(MAX_MAILBOX_PATH+1);
    uint32_t uid;

    assert(event->type);
    assert(event->state == EVENT_PENDING);

    memset(noflag, 0, sizeof(noflag));

    /* may send several notifications for FlagsSet event */
    do {
	buf_printf(&buffer, "version=%d\n", EVENT_VERSION);

	event_type = event->type;
	/* prefer MessageRead and MessageTrash to FlagsSet as advised in the RFC */
	if (event_type == FlagsSet) {
	    int i;

	    if ((i = strarray_find(&event->flagnames, "\\Deleted", 0)) >= 0) {
		event_type = MessageTrash;
		strarray_remove(&event->flagnames, i);
	    }
	    else if ((i = strarray_find(&event->flagnames, "\\Seen", 0)) >= 0) {
		event_type = MessageRead;
		strarray_remove(&event->flagnames, i);
	    }
	}
	buf_printf(&buffer, "event=%s\n", event2name(event_type));

	/* this legacy parameter is not needed since mailboxID is an IMAP URL */
	if (event->extraparams & event_vnd_cmu_host)
	    buf_printf(&buffer, "vnd.cmu.host=%s\n", config_servername);

	if (event->extraparams & event_timestamp) {
	    if (config_getenum(IMAPOPT_EVENT_TIMESTAMP_FORMAT) ==
		IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_EPOCH) {
		buf_printf(&buffer, "timestamp=%ld%03ld\n",
			event->timestamp.tv_sec,
			event->timestamp.tv_usec ? (event->timestamp.tv_usec/1000) : 0);
	    }
	    else if (config_getenum(IMAPOPT_EVENT_TIMESTAMP_FORMAT) ==
		IMAP_ENUM_EVENT_TIMESTAMP_FORMAT_ISO8601) {
		char buf[30];
		time_to_iso8601(event->timestamp.tv_sec,
			event->timestamp.tv_usec/1000, buf, sizeof(buf));
		buf_printf(&buffer, "timestamp=%s\n", buf);
	    }
	    else {
		/* unkown format! */
	    }
	}

	/* use an IMAP URL to refer to a mailbox */
	assert(event->mailbox);
	memset(&mailboxid, 0, sizeof(struct imapurl));
	mailboxid.server = config_servername;
	mailboxid.mailbox = event->mailbox;
	mailboxid.uidvalidity = event->uidvalidity;
	/* use an IMAP URL to refer to a specific message */
	/* XXX store uidset in an array of uint32 to avoid such parsing */
	if (buf_len(&event->uidset) && !strchr(buf_cstring(&event->uidset), ' ')) {
	    parseuint32(buf_cstring(&event->uidset), NULL, &uid);
	    mailboxid.uid = uid;
	    buf_reset(&event->uidset);
	}
	imapurl_toURL(url, &mailboxid);
	buf_printf(&buffer, "mailboxID=%s\n", url);

	if (event->oldmailboxid)
	    buf_printf(&buffer, "oldMailboxID=%s\n", event->oldmailboxid);

	if (event->extraparams & event_uidnext)
	    buf_printf(&buffer, "uidnext=%u\n", event->uidnext);
	if (event->extraparams & event_messages)
	    buf_printf(&buffer, "messages=%u\n", event->messages);
	if (event->extraparams & event_vnd_cmu_newMessages) {
	    buf_printf(&buffer, "vnd.cmu.newMessages=%u\n", event->newMessages);
	}

	if (buf_len(&event->uidset))
	    buf_printf(&buffer, "uidset=%s\n", buf_cstring(&event->uidset));

	if (buf_len(&event->midset))
	    buf_printf(&buffer, "vnd.cmu.midset=%s\n", buf_cstring(&event->midset));

	if (event_type == FlagsSet || event_type == FlagsClear ||
	    (event->extraparams & event_flagnames)) {

	    if (strarray_size(&event->flagnames) > 0) {
		char *str = strarray_join(&event->flagnames, " ");

		buf_printf(&buffer, "flagNames=%s\n", str);
		free(str);
		/* stop to loop for flag changed here */
		strarray_fini(&event->flagnames);
	    }
	}

	notify(notifier, "EVENT", NULL, NULL, NULL, 0, NULL, buf_cstring(&buffer));
	buf_reset(&buffer);
    }
    while (strarray_size(&event->flagnames) > 0);

    buf_free(&buffer);
    mboxevent_free(event);
    free(url);

    return;
}

void mboxevent_add_sysflags(struct event_state *event, bit32 sysflags)
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
}


void mboxevent_add_usrflags(struct event_state *event, struct mailbox *mailbox,
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
}

void mboxevent_extract_record(struct event_state *event, struct mailbox *mailbox,
			 struct index_record *record)
{
    const char *msgid = NULL;

    /* add UID to uidset */
    if (buf_len(&event->uidset) == 0) {
	buf_printf(&event->uidset, "%u", record->uid);
    }
    else {
	buf_printf(&event->uidset, " %u", record->uid);
    }

    /* add Message-Id to midset or NIL if doesn't exists */
    if (event->extraparams & event_vnd_cmu_midset) {
	msgid = mailbox_cache_get_msgid(mailbox, record);

	if (buf_len(&event->midset) == 0)
	    buf_printf(&event->midset, "%s", msgid ? msgid : "NIL");
	else
	    buf_printf(&event->midset, " %s", msgid ? msgid : "NIL");
    }
}

void mboxevent_extract_mailbox(struct event_state *event, struct mailbox *mailbox)
{
    assert(event->mailbox == NULL);
    event->mailbox = strdup(mailbox->name);
    event->uidvalidity = mailbox->i.uidvalidity;

    if (event->extraparams & event_uidnext)
	event->uidnext = mailbox->i.last_uid+1;
    if (event->extraparams & event_messages)
	event->messages = mailbox->i.exists;
    if (event->extraparams & event_vnd_cmu_newMessages) {
	/* event notification is focused on mailbox, we don't care about the
    	 * authenticated user */
	event->newMessages = mailbox_count_unseen(mailbox);
    }
}

char *mboxevent_toURL(struct mailbox *mailbox)
{
    struct imapurl imapurl;
    char *url = xmalloc(MAX_MAILBOX_PATH+1);

    memset(&imapurl, 0, sizeof(struct imapurl));
    imapurl.server = config_servername;
    imapurl.mailbox = mailbox->name;
    imapurl.uidvalidity = mailbox->i.uidvalidity;
    imapurl_toURL(url, &imapurl);

    return url;
}
