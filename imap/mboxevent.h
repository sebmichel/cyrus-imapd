/* mboxevent.h -- interface for message store event notifications
 *
 * Copyright (c) 1994-2012 Carnegie Mellon University.  All rights reserved.
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

#include "mailbox.h"


/*
 * event types defined in RFC 5423 - Internet Message Store Events
 */
enum event_type {
    EVENT_CANCELLED           = (0),
    /* Message Addition and Deletion */
    EVENT_MESSAGE_APPEND      = (1<<0),
    EVENT_MESSAGE_EXPIRE      = (1<<1),
    EVENT_MESSAGE_EXPUNGE     = (1<<2),
    EVENT_MESSAGE_NEW         = (1<<3),
    EVENT_MESSAGE_COPY        = (1<<4), /* additional event type to notify IMAP COPY */
    EVENT_QUOTA_EXCEED        = (1<<5),
    EVENT_QUOTA_WITHIN        = (1<<6),
    EVENT_QUOTA_CHANGE        = (1<<7),
    /* Message Flags */
    EVENT_MESSAGE_READ        = (1<<8),
    EVENT_MESSAGE_TRASH       = (1<<9),
    EVENT_FLAGS_SET           = (1<<10),
    EVENT_FLAGS_CLEAR         = (1<<11),
    /* Access Accounting */
    EVENT_LOGIN               = (1<<12),
    EVENT_LOGOUT              = (1<<13),
    /* Mailbox Management */
    EVENT_MAILBOX_CREATE      = (1<<14),
    EVENT_MAILBOX_DELETE      = (1<<15),
    EVENT_MAILBOX_RENAME      = (1<<16),
    EVENT_MAILBOX_SUBSCRIBE   = (1<<17),
    EVENT_MAILBOX_UNSUBSCRIBE = (1<<18)
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
    const char *name;
    const enum event_param_type t;
    union event_param_value value;
    int filled;
};

struct mboxevent {
    int type;	/* event type */

    /* array of event parameters */
    struct event_parameter params[MAX_PARAM+1];

    struct imapurl *mailboxid; 	/* XXX translate mailbox name to external ? */
    struct imapurl *oldmailboxid;

    strarray_t flagnames;
    struct timeval timestamp;
    struct seqset *uidset;
    strarray_t midset;
    struct seqset *olduidset;

    struct mboxevent *next;
};


/*
 * Call this initializer once only at start
 */
void mboxevent_init(void);

/*
 * Create a new mboxevent structure for the given event type.
 * Allocate resources for configured extra parameters.
 *
 * return the initialized event state or NULL if notification is disabled
 */
struct mboxevent *mboxevent_new(enum event_type type);

/*
 * Create a new mboxevent structure for the given event type.
 * Append this new structure at end of the given mboxevent list.
 * Allocate resources for configured extra parameters.
 *
 * return the initialized event state or NULL if notification is disabled
 */
struct mboxevent *mboxevent_enqueue(enum event_type type,
                                    struct mboxevent **events);

/*
 * Send the queue of event notifications
 */
void mboxevent_notify(struct mboxevent *mboxevents);

/*
 * Release any allocated resources
 */
void mboxevent_free(struct mboxevent **event);

/*
 * Add this set of system flags to flagNames parameter.
 * Exclude system flags present in event_exclude_flags setting.
 *
 * Return the total number of flags added until now
 */
int mboxevent_add_system_flags(struct mboxevent *event, bit32 system_flags);

/*
 * Add this set of user flags to flagNames parameter.
 * Exclude user flags present in event_exclude_flags setting.
 *
 * Return the total number of flags added until now
 */
int mboxevent_add_user_flags(struct mboxevent *event,
                             const struct mailbox *mailbox, bit32 *user_flags);

/*
 * Add the given flag to flagNames parameter.
 * event_exclude_flags doesn't apply here
 */
void mboxevent_add_flag(struct mboxevent *event, const char *flag);

/*
 * Extract data related to message store access accounting
 */
void mboxevent_set_access(struct mboxevent *event,
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
void mboxevent_extract_record(struct mboxevent *event,
                              struct mailbox *mailbox,
                              struct index_record *record);

/*
 * Fill event parameter about the copied message.
 * Called once per message and always before mboxevent_extract_mailbox
 */
void mboxevent_extract_copied_record(struct mboxevent *event,
				     const struct mailbox *mailbox, uint32_t uid);

/*
 * Extract message content to include to event notification
 */
void mboxevent_extract_content(struct mboxevent *event,
                               const struct index_record *record, FILE* content);

/*
 * Extract quota limit, quota usage and quota root to include to event
 * notification
 */
void mboxevent_extract_quota(struct mboxevent *event, const struct quota *quota,
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
void mboxevent_extract_mailbox(struct mboxevent *event, struct mailbox *mailbox);

#endif /* _MBOXEVENT_H */
