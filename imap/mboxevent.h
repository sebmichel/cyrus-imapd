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
    /* Message Addition and Deletion */
    MessageAppend       = (1<<0),
    MessageExpire       = (1<<1),
    MessageExpunge      = (1<<2),
    MessageNew          = (1<<3),
    vnd_cmu_MessageCopy = (1<<4), /* additional event type to notify IMAP COPY */
    /* Message Flags */
    MessageRead         = (1<<5),
    MessageTrash        = (1<<6),
    FlagsSet            = (1<<7),
    FlagsClear          = (1<<8),
    /* Access Accounting */
    Login               = (1<<9),
    Logout              = (1<<10),
    /* Mailbox Management */
    MailboxCreate       = (1<<11),
    MailboxDelete       = (1<<12),
    MailboxRename       = (1<<13),
    MailboxSubscribe    = (1<<14),
    MailboxUnSubscribe  = (1<<15)
};

/*
 * event parameters defined in RFC 5423 - Internet Message Store Events
 */
enum {
    event_bodyStructure_idx = 0,
    event_clientIP_idx,
    event_clientPort_idx,
    event_flagNames_idx,
    event_mailboxID_idx,
    event_messageContent_idx,
    event_messageSize_idx,
    event_messages_idx,
    event_oldMailboxID_idx,
    event_serverDomain_idx,
    event_serverPort_idx,
    event_service_idx,
    event_timestamp_idx,
    event_uidnext_idx,
    event_uidset_idx,
    event_user_idx,
    /* extra event parameters not defined in the RFC */
    event_vnd_cmu_host_idx,
    event_vnd_cmu_midset_idx,
    event_vnd_cmu_newMessages_idx,
    event_vnd_cmu_oldUidset_idx
};

/*
 * event parameters defined in RFC 5423 - Internet Message Store Events
 */
enum event_param {
    event_bodyStructure =        (1<<event_bodyStructure_idx),
    event_clientIP =             (1<<event_clientIP_idx),
    event_clientPort =           (1<<event_clientPort_idx),
    event_flagNames =            (1<<event_flagNames_idx),
    event_mailboxID =            (1<<event_mailboxID_idx),
    event_messageContent =       (1<<event_messageContent_idx),
    event_messageSize =          (1<<event_messageSize_idx),
    event_messages =             (1<<event_messages_idx),
    event_oldMailboxID =         (1<<event_oldMailboxID_idx),
    event_serverDomain =         (1<<event_serverDomain_idx),
    event_serverPort =           (1<<event_serverPort_idx),
    event_service =              (1<<event_service_idx),
    event_timestamp =            (1<<event_timestamp_idx),
    event_uidnext =              (1<<event_uidnext_idx),
    event_uidset =               (1<<event_uidset_idx),
    event_user =                 (1<<event_user_idx),
    event_vnd_cmu_host =         (1<<event_vnd_cmu_host_idx),
    event_vnd_cmu_midset =       (1<<event_vnd_cmu_midset_idx),
    event_vnd_cmu_newMessages =  (1<<event_vnd_cmu_newMessages_idx),
    event_vnd_cmu_oldUidset =    (1<<event_vnd_cmu_oldUidset_idx)
};

/* event_state structure is a chained list to handle several events */
struct event_state {
    int type;			/* event type */
    int aborting;		/* don't send the notification */

    /* standard event parameters */
    struct imapurl *mailboxid; 	/* XXX translate mailbox name to external ? */
    struct imapurl *oldmailboxid;

    char *bodystructure;
    strarray_t flagnames;
    char *messagecontent;
    char messagesize[21]; /* 32bits size until now */
    char messages[21];
    struct timeval timestamp;
    char uidnext[21];
    struct buf uidset;
    const char *user;

    /* come saslprops structure */
    char *iplocalport;
    char *ipremoteport;

    /* private event parameters */
    struct buf midset;
    char newmessages[21];
    struct buf olduidset;

    /* formatted representation of event parameters */
    const char *params[event_vnd_cmu_oldUidset_idx+1];

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
 * Test if the given parameter must be filled for the given event type
 */
int mboxevent_expected_params(int event_type, enum event_param param);

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
int mboxevent_add_usrflags(struct event_state *event, struct mailbox *mailbox,
			   bit32 *usrflags);

/*
 * Add the given flag to flagNames parameter.
 * event_exclude_flags doesn't apply here
 */
void mboxevent_add_flag(struct event_state *event, const char *flag);

/*
 * Extract data from the given record to fill these event parameters :
 * - uidset from UID
 * - midset from Message-Id in ENVELOPE structure
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
				     struct mailbox *mailbox, uint32_t uid);

/*
 * Extract message content to include with the event notification
 */
void mboxevent_extract_content(struct event_state *event,
                               struct index_record *record, FILE* content);

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
struct imapurl *mboxevent_toURL(struct mailbox *mailbox);

#endif /* _MBOXEVENT_H */
