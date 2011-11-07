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
#include "imapurl.h"
#include "strarray.h"
#include "util.h"

#include "mailbox.h"


/*
 * event types defined in RFC 5423 - Internet Message Store Events
 */
enum  {
    CancelledEvent      = (0),
    /* Message Addition and Deletion */
    MessageAppend       = (1<<0),
    MessageExpire       = (1<<1),
    MessageExpunge      = (1<<2),
    MessageNew          = (1<<3),
    vnd_cmu_MessageCopy = (1<<4), /* additional event type to notify IMAP COPY */
    QuotaExceed         = (1<<5),
    QuotaWithin         = (1<<6),
    QuotaChange         = (1<<7),
    /* Message Flags */
    MessageRead         = (1<<8),
    MessageTrash        = (1<<9),
    FlagsSet            = (1<<10),
    FlagsClear          = (1<<11),
    /* Access Accounting */
    Login               = (1<<12),
    Logout              = (1<<13),
    /* Mailbox Management */
    MailboxCreate       = (1<<14),
    MailboxDelete       = (1<<15),
    MailboxRename       = (1<<16),
    MailboxSubscribe    = (1<<17),
    MailboxUnSubscribe  = (1<<18)
};

#define MAX_PARAM 21 /* messageContent number that is always the last */

enum event_param_type {
    EVENT_PARAM_INT,
    EVENT_PARAM_UINT,
    EVENT_PARAM_MODSEQT,
    EVENT_PARAM_QUOTAT,
    EVENT_PARAM_STRING,
    EVENT_PARAM_DYNSTRING /* must be freed */
};

union event_param_value {
    char *s;      /* string */
    long i;       /* int */
    uint32_t u; /* unsigned 32 bits */
    modseq_t m; /* unsigned 64 bits */
    quota_t q;
};

struct event_parameter {
    char *name;
    const enum event_param_type t;
    union event_param_value value;
    int filled;
};

struct event_state {
    int type;	/* event type */

    /* array of event parameters */
    struct event_parameter params[MAX_PARAM+1];

    struct imapurl *mailboxid; 	/* XXX translate mailbox name to external ? */
    struct imapurl *oldmailboxid;

    strarray_t flagnames;
    struct timeval timestamp;
    struct buf uidset;
    struct buf midset;
    struct buf olduidset;

    struct event_state *next;
};


/*
 * Call this initializer once only at start
 */
void mboxevent_init(void);

/*
 * Create a new event state structure for the given event type.
 * Allocate resources for configured extra parameters.
 *
 * return the initialized event state or NULL if notification is disabled
 */
struct event_state *event_newstate(int type, struct event_state **event);

/*
 * Send a notification for this event
 */
void mboxevent_notify(struct event_state *event);

/*
 * Release any allocated resources
 */
void mboxevent_free(struct event_state **event);

/*
 * Add this set of system flags to flagNames parameter.
 * Exclude system flags present in event_exclude_flags setting.
 *
 * Return the total number of flags added until now
 */
int mboxevent_add_sysflags(struct event_state *event, bit32 sysflags);

/*
 * Add this set of user flags to flagNames parameter.
 * Exclude user flags present in event_exclude_flags setting.
 *
 * Return the total number of flags added until now
 */
int mboxevent_add_usrflags(struct event_state *event, const struct mailbox *mailbox,
			   bit32 *usrflags);

/*
 * Add the given flag to flagNames parameter.
 * event_exclude_flags doesn't apply here
 */
void mboxevent_add_flag(struct event_state *event, const char *flag);

/*
 * Extract data related to message store access accounting
 */
void mboxevent_extract_access(struct event_state *event,
                              const char *serveraddr, const char *clientaddr,
                              const char *userid);
/*
 * Extract data from the given record to fill these event parameters :
 * - uidset from UID
 * - vnd.cmu.midset from Message-Id in ENVELOPE structure
 * - messageSize
 * - bodyStructure
 *
 * Called once per message and always before mboxevent_extract_mailbox
 */
void mboxevent_extract_record(struct event_state *event, struct mailbox *mailbox,
                              struct index_record *record);

/*
 * Fill event parameter about the copied message.
 * Called once per message and always before mboxevent_extract_mailbox
 */
void mboxevent_extract_copied_record(struct event_state *event,
				     const struct mailbox *mailbox, uint32_t uid);

/*
 * Extract message content to include with event notification
 */
void mboxevent_extract_content(struct event_state *event,
                               const struct index_record *record, FILE* content);

/*
 * Extract quota limit and quota usage to include with event notification
 */
void mboxevent_extract_quota(struct event_state *event, const struct quota *quota,
                             enum quota_resource res);

/*
 * Extract meta-data from the given mailbox to fill mailboxID event parameter and
 * optionally these ones depending the type of the event:
 * - messages
 * - uidnext
 * - vnd.cmu.newMessages
 *
 * Must be called once per event or the notification will failed (Except for
 * Login and Logout events)
 * Mailbox must be locked to count the number of \Seen flags
 *
 * It is necessary to call this function after all changes on mailbox to get the
 * right values of messages, uidnext and vnd.cmu.newMessages event parameters
 */
void mboxevent_extract_mailbox(struct event_state *event, struct mailbox *mailbox);

/*
 * Return an IMAP URL that identify the given mailbox on the server
 */
struct imapurl *mboxevent_toURL(const struct mailbox *mailbox);

#endif /* _MBOXEVENT_H */
