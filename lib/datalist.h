/* datalist.h -- a linked list
 *
 * Copyright (c) 1994-2013 Carnegie Mellon University.  All rights reserved.
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

#ifndef __CYRUS_DATALIST_H__
#define __CYRUS_DATALIST_H__

#include <config.h>


typedef void (*datafree_t)(void *data);
typedef int (*datacomp_t)(const void *data1, const void *data2,
    const void *rock);

typedef struct listnode
{
    struct listnode *prev;
    struct listnode *next;
    void *data;
} listnode_t;

#define listnode_data(ln)	    ((ln)->data)
#define listnode_previous(ln)	    ((ln)->prev)
#define listnode_next(ln)	    ((ln)->next)

typedef struct
{
    int count;

    datafree_t free;
    datacomp_t comp;

    listnode_t *head;
    listnode_t *tail;
} datalist_t;

#define DATALIST_INITIALIZER	{ 0, NULL, NULL, NULL, NULL }
#define datalist_init(dl)   (memset((dl), 0, sizeof(datalist_t)))
void datalist_fini(datalist_t *);

datalist_t *datalist_new(datafree_t, datacomp_t);
void datalist_free(datalist_t *);

void datalist_append(datalist_t *, void *);
void datalist_add(datalist_t *, void *, const void *);
void datalist_prepend(datalist_t *, void *);

#define datalist_head(dl)	    ((dl)->head)
void *datalist_shift(datalist_t *);
#define datalist_unshift(dl, p)	    datalist_prepend((dl), (p))

#define datalist_tail(dl)	    ((dl)->tail)
void *datalist_pop(datalist_t *);
#define datalist_push(dl, p)	    datalist_append((dl), (p))

listnode_t *datalist_find(const datalist_t *dl, void *match,
    listnode_t *starting, const void *rock);

listnode_t *datalist_sort(datalist_t *dl, const void *rock);

#endif /* __CYRUS_DATALIST_H__ */
