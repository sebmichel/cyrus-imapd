/* datalist.c -- a linked list
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

#include "datalist.h"

#include <memory.h>

#include "lsort.h"
#include "xmalloc.h"


/** Dummy pointer comparator. */
static int listnode_comp(void *p1, void *p2,
    const void *rock __attribute__((unused)))
{
    return ((p1 < p2) ? -1 : (p1 > p2) ? 1 : 0);
}

EXPORTED datalist_t *datalist_new(datafree_t pfree, datacomp_t pcomp)
{
    datalist_t *dl = (datalist_t *)xzmalloc(sizeof(datalist_t));

    dl->free = pfree;
    dl->comp = pcomp;

    return dl;
}

EXPORTED void datalist_fini(datalist_t *dl)
{
    listnode_t *node;
    listnode_t *next;

    if (!dl) {
	return;
    }

    node = dl->head;
    while (node) {
	next = node->next;
	if (dl->free) {
	    dl->free(node->data);
	}
	free(node);
	node = next;
    }

    dl->head = NULL;
    dl->tail = NULL;
    dl->count = 0;
}

EXPORTED void datalist_free(datalist_t *dl)
{
    if (!dl) {
	return;
    }

    datalist_fini(dl);
    free(dl);
}

EXPORTED void datalist_add(datalist_t *dl, void *p, const void *rock)
{
    if (!datalist_find(dl, p, NULL, rock)) {
	datalist_append(dl, p);
    }
}

EXPORTED void datalist_append(datalist_t *dl, void *p)
{
    listnode_t *tail = (listnode_t *)xmalloc(sizeof(listnode_t));

    tail->prev = dl->tail;
    tail->next = NULL;
    tail->data = p;
    if (tail->prev) {
	tail->prev->next = tail;
    }
    else {
	/* first link */
	dl->head = tail;
    }
    dl->tail = tail;
    dl->count++;
}

EXPORTED void datalist_prepend(datalist_t *dl, void *p)
{
    listnode_t *head = (listnode_t *)xmalloc(sizeof(listnode_t));

    head->prev = NULL;
    head->next = dl->head;
    head->data = p;
    if (head->next) {
	head->next->prev = head;
    }
    else {
	/* first link */
	dl->tail = head;
    }
    dl->head = head;
    dl->count++;
}

EXPORTED void *datalist_shift(datalist_t *dl)
{
    listnode_t *head;
    void *p;

    if (!dl->count) {
	return NULL;
    }

    head = dl->head;
    p = head->data;
    if (!--dl->count) {
	/* last link */
	dl->head = dl->tail = NULL;
    }
    else {
	dl->head = head->next;
	dl->head->prev = NULL;
    }

    free(head);

    return p;
}

EXPORTED void *datalist_pop(datalist_t *dl)
{
    listnode_t *tail;
    void *p;

    if (!dl->count) {
	return NULL;
    }

    tail = dl->tail;
    p = tail->data;
    if (!--dl->count) {
	/* last link */
	dl->head = dl->tail = NULL;
    }
    else {
	dl->tail = tail->prev;
	dl->tail->next = NULL;
    }

    free(tail);

    return p;
}

/* Getnext function for sorting list. */
static void *_datalist_sort_getnext(listnode_t *node)
{
    return node->next;
}

/* Setnext function for sorting list. */
static void _datalist_sort_setnext(listnode_t *node, listnode_t *next)
{
    node->next = next;
    if (next) {
	next->prev = node;
    }
}

typedef struct sortrock {
    datacomp_t comp;
    const void *rock;
} sortrock_t;

/* Comparison function for sorting list. */
static int _datalist_sort_compare(listnode_t *node1, listnode_t *node2,
	sortrock_t *sortrock)
{
    return sortrock->comp(node1->data, node2->data, sortrock->rock);
}

EXPORTED listnode_t *datalist_find(const datalist_t *dl, void *match,
    listnode_t *starting, const void *rock)
{
    listnode_t *node = starting ? starting : dl->head;
    datacomp_t comp = dl->comp ? dl->comp : (datacomp_t)listnode_comp;

    while (node && comp(match, node->data, rock)) {
	node = node->next;
    }

    return node;
}

EXPORTED listnode_t *datalist_sort(datalist_t *dl, const void *rock)
{
    sortrock_t sortrock;
    listnode_t *tail;

    if (!dl->count) {
	return NULL;
    }

    sortrock.comp = dl->comp ? dl->comp : (datacomp_t)listnode_comp;
    sortrock.rock = rock;

    dl->head = lsort(dl->head,
	(void * (*)(void*)) _datalist_sort_getnext,
	(void (*)(void*,void*)) _datalist_sort_setnext,
	(int (*)(void*,void*,void*)) _datalist_sort_compare,
	&sortrock);

    /* fix the new head: it has no previous node */
    dl->head->prev = NULL;

    /* get the new tail */
    for (tail = dl->head; tail->next; tail = tail->next)
	;
    dl->tail = tail;

    return dl->head;
}
