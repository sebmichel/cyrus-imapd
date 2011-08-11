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

#ifndef _MBOXEVENT_H
#define _MBOXEVENT_H

#include "hash.h"
#include "strarray.h"
#include "util.h"
#include "mailbox.h"


enum {
    EVENT_INIT = 0,
    EVENT_READY,
    EVENT_PENDING,
    EVENT_ABORTING
};

/*
 * event types defined in RFC 5423 - Internet Message Store Events
 */
enum {
    // Message Addition and Deletion
    MessageAppend = 1,
    MessageExpunge,
    MessageNew,
    vnd_cmu_MessageCopy, /* additional event type to notify IMAP COPY */
    // Message Flags
    MessageRead,
    MessageTrash,
    FlagsSet,
    FlagsClear,
    // Mailbox Management
    MailboxCreate,
    MailboxDelete,
    MailboxRename
};

/*
 * extra event parameters than those mandatory in the RFC 5423
 */
enum {
    event_flagnames =            (1<<0),
    event_messages =             (1<<1),
    event_timestamp =            (1<<2),
    event_uidnext =              (1<<3),
    event_vnd_cmu_host =         (1<<4),
    event_vnd_cmu_midset =       (1<<5),
    event_vnd_cmu_newMessages =  (1<<6),
    event_vnd_cmu_oldUidset =    (1<<7)
};

struct event_state {
    unsigned long state;

    /* event type */
    int type;

    /* standard event parameters */
    char *mailbox; /* XXX translate mailbox name to external ? */
    uint32_t uidvalidity;

    struct timeval timestamp;
    uint32_t uidnext;
    uint32_t messages;
    struct buf uidset;
    char *oldmailboxid;
    strarray_t flagnames;

    /* private event parameters */
    struct buf midset;
    unsigned newMessages;

    /* enabled extra parameters */
    int extraparams;
};

#define EVENT_STATE_INITIALIZER	{ EVENT_INIT, 0, NULL, 0, { 0, 0 }, 0, 0, \
				  BUF_INITIALIZER, NULL, STRARRAY_INITIALIZER, \
				  BUF_INITIALIZER, 0, 0 }


/*
 * Call this initializer once only at start
 */
void mboxevent_init(void);

/*
 * Configure the event state structure for the given event type.
 * Allocate resources for configured extra parameters.
 *
 * set event_state state to EVENT_READY if notification is enabled
 * for the given type and is successfully initialized
 *
 * return the initialized event state or NULL otherwise
 */
struct event_state *event_newstate(int type, struct event_state *event);

/*
 * Abort the notification and release any allocated resources
 */
void mboxevent_abort(struct event_state *event);

/*
 * Test if given event is enabled for this folder.
 * By default subfolders are disabled for all events.
 */
int mboxevent_enabled_for_folder(const char *event, const char *folder);

/*
 * Send a notification for this event and release any allocated resources
 */
void mboxevent_notify(struct event_state *event);

/*
 * Add this set of system flags to fill flagNames parameter.
 * Exclude system flags present in event_ignored_flags setting.
 */
void mboxevent_add_sysflags(struct event_state *event, bit32 sysflags);

/*
 * Add this set of user flags to fill flagNames parameter.
 * Exclude user flags present in event_ignored_flags setting.
 */
void mboxevent_add_usrflags(struct event_state *event, struct mailbox *mailbox,
			   bit32 *usrflags);
/*
 * Extract data from given record to fill these event parameters :
 * - uidset from UID
 * - midset from Message-Id in ENVELOPE structure
 *
 * Called once per message that has changed
 */
void mboxevent_extract_record(struct event_state *event, struct mailbox *mailbox,
			 struct index_record *record);

/*
 * Extract data from given mailbox to fill these event parameters :
 * - mailboxID
 * - messages
 * - uidnext
 * - vnd.cmu.newMessages
 *
 * Called once per event.
 * Mailbox must be locked to count the number of \Seen flags
 */
void mboxevent_extract_mailbox(struct event_state *event, struct mailbox *mailbox);

/*
 * Return an IMAP URL that identify the given mailbox on the server.
 * UID is added to the URL to identify a message if not zero
 */
char *mboxevent_toURL(struct mailbox *mailbox);

#endif /* _MBOXEVENT_H */
