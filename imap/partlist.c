/* partlist.c - Partition/backend selection functions
 *
 * Copyright (c) 1994-2008 Carnegie Mellon University.  All rights reserved.
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
 * $Id: $
 */

#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include "libconfig.h"
#include "partlist.h"
#include "xmalloc.h"


#define FREE(var) if (var) { free(var); (var) = NULL; }

static void partlist_bump_action(partlist_t *part_list);
static int partlist_selectpart_index(partlist_t *part_list);
static void partlist_compute_quota(partlist_t *part_list);
static void partlist_fill(const char *key, const char *value, void *rock);
static void partition_filldata(partlist_t *part_list, int idx);

typedef struct partlist_conf {
    partlist_t  *part_list;
    const char  *key_prefix;
    size_t      excluded_count;
    const char  **excluded_item;
} partlist_conf_t;

static partlist_t *partlist_local = NULL;


partmode_t partlist_getmode(const char *mode)
{
    if (!strcmp(mode, "freespace-most")) {
	return PART_MODE_FREESPACE_MOST;
    }
    else if (!strcmp(mode, "freespace-percent-most")) {
	return PART_MODE_FREESPACE_PERCENT_MOST;
    }
    else if (!strcmp(mode, "freespace-percent-weighted")) {
	return PART_MODE_FREESPACE_PERCENT_WEIGHTED;
    }
    else if (!strcmp(mode, "freespace-percent-weighted-delta")) {
	return PART_MODE_FREESPACE_PERCENT_WEIGHTED_DELTA;
    }
    else {
	return PART_MODE_RANDOM;
    }
}


void partlist_initialize(partlist_t *part_list,
			 cb_part_filldata filldata,
			 const char *key_prefix,
			 const char *key_value,
			 const char *excluded,
			 int excluded_mandatory,
			 partmode_t mode,
			 int weighted_usage_limit,
			 int reinit)
{
    partlist_conf_t part_list_conf;
    char *excluded_parts = NULL;
    int i;

    srand(time(NULL));
    memset(&part_list_conf, 0, sizeof(part_list_conf));
    memset(part_list, 0, sizeof(partlist_t));

    part_list->mode = mode;
    part_list->filldata = (filldata ? filldata : partition_filldata);
    part_list->size = 0;
    part_list->weighted_usage_limit = weighted_usage_limit;
    part_list->reinit = reinit;

    part_list_conf.part_list = part_list;
    part_list_conf.key_prefix = key_prefix;

    if (excluded && (strlen(excluded) > 0)) {
	char *item = NULL;
	char *lasts;

	excluded_parts = xstrdup(excluded);
	item = strtok_r(excluded_parts, " ,\t", &lasts);
	while (item) {
	    part_list_conf.excluded_item = (const char **)xrealloc(part_list_conf.excluded_item, (part_list_conf.excluded_count+1) * sizeof(const char *));
	    part_list_conf.excluded_item[part_list_conf.excluded_count++] = item;
	    item = strtok_r(NULL, " ,\t", &lasts);
	}
    }

    if (!excluded_mandatory || (part_list_conf.excluded_count>0)) {
	if (key_value) {
	    char *items = xstrdup(key_value);
	    char *item = NULL;
	    char *lasts;

	    item = strtok_r(items, " ,\t", &lasts);
	    while (item) {
		partlist_fill(item, item, &part_list_conf);
		item = strtok_r(NULL, " ,\t", &lasts);
	    }

	    FREE(items);
	}
	else {
	    config_foreachoverflowstring(partlist_fill, &part_list_conf);
	}
    }
    /* excluded items no more necessary */
    FREE(excluded_parts);
    FREE(part_list_conf.excluded_item);

    partlist_compute_quota(part_list);
}


void partlist_free(partlist_t *part_list)
{
    int i;

    if (part_list == NULL) {
	return;
    }

    for (i=0 ; i<part_list->size ; i++) {
	FREE(part_list->items[i].item);
	FREE(part_list->items[i].value);
    }
    FREE(part_list->items);
    part_list->size = -1;
}


static void partlist_bump_action(partlist_t *part_list)
{
    if ((part_list->reinit > 0) && (part_list->reinit_counter++ >= part_list->reinit)) {
	partlist_compute_quota(part_list);
	part_list->reinit_counter = 1;
    }
}


int partlist_getavailable(partlist_t *part_list)
{
    int count = 0;
    int idx;

    for (idx=0 ; idx<part_list->size ; idx++) {
	if (part_list->items[idx].quota != 0.) {
	    count++;
	}
    }

    /* When nothing available, refresh quotas after a while */
    if (!count) {
	partlist_bump_action(part_list);
    }

    return count;
}


const char *partlist_get_value(partlist_t *part_list, const char *item)
{
    int idx;

    for (idx=0 ; idx<part_list->size ; idx++) {
	if (!strcmp(item, part_list->items[idx].item)) {
	    return part_list->items[idx].value;
	}
    }

    return NULL;
}


const char *partlist_select_item(partlist_t *part_list)
{
    int idx = partlist_selectpart_index(part_list);

    return (idx == -1 ? NULL : part_list->items[idx].item);
}


const char *partlist_select_value(partlist_t *part_list)
{
    int idx = partlist_selectpart_index(part_list);

    return (idx == -1 ? NULL : part_list->items[idx].value);
}


static int partlist_selectpart_index(partlist_t *part_list)
{
    int i;
    int do_random = 0;
    int ret = -1;
    int available;

    if (part_list->size <= 0) {
	return -1;
    }

    available = partlist_getavailable(part_list);
    if (!available) {
	return -1;
    }

    partlist_bump_action(part_list);

    if ((part_list->mode == PART_MODE_RANDOM) || part_list->force_random) {
	do_random = 1;
    }
    else {
	double sq = 0.;
	double val = 0.;
	partusage_t max_available = 0;

	switch (part_list->mode) {
	case PART_MODE_FREESPACE_MOST:
	    for (i=0 ; i<part_list->size ; i++) {
		if (part_list->items[i].quota == 0.) {
		    continue;
		}

		if (part_list->items[i].available > max_available) {
		    ret = i;
		    max_available = part_list->items[i].available;
		}
	    }
	    break;

	case PART_MODE_FREESPACE_PERCENT_MOST:
	    for (i=0 ; i<part_list->size ; i++) {
		if (part_list->items[i].quota == 0.) {
		    continue;
		}

		if (part_list->items[i].quota > val) {
		    ret = i;
		    val = part_list->items[i].quota;
		}
	    }
	    break;

	case PART_MODE_FREESPACE_PERCENT_WEIGHTED:
	case PART_MODE_FREESPACE_PERCENT_WEIGHTED_DELTA:
	    /* random in [0,100[ */
	    val = 100. * ((double)rand() / (RAND_MAX + 1.));

	    for (i=0 ; i<part_list->size ; i++) {
		sq += part_list->items[i].quota;
		ret = i;
		if (val < sq) {
		    break;
		}
	    }

	    /* sanity check: make sure we did not pick an unwanted entry
	       and get last wanted one (or -1 if all items are unwanted) */
	    while ((part_list->items[ret].quota == 0.) && (--ret >= 0))
		;
	    break;

	default:
	    /* sanity check */
	    do_random = 1;
	    break;
	}
    }

    if (do_random) {
	i = rand() % available;
	ret = 0;
	while (i--) {
	    while (part_list->items[++ret].quota == 0.)
		;
	}
    }

    return ret;
}


static void partlist_compute_quota(partlist_t *part_list)
{
    int i;
    int j;
    unsigned long id;
    double percent_available;
    double percent_used;
    double quota_total = 0;
    double quota_min = 100.;
    double quota_min_limit = 100.;
    double quota_limit = 100. - part_list->weighted_usage_limit;
    int quota_limit_use = 0;
    partmode_t mode = part_list->mode;

    part_list->force_random = 0;

    if (mode == PART_MODE_RANDOM) {
	/* No need to check items usage */
	for (i=0 ; i<part_list->size ; i++) {
	    part_list->items[i].quota = 50.0;
	}

	return;
    }

    for (i=0 ; i<part_list->size ; i++) {
	part_list->filldata(part_list, i);

	if ((mode == PART_MODE_FREESPACE_MOST) || (mode == PART_MODE_FREESPACE_PERCENT_MOST)) {
	    id = part_list->items[i].id;
	    for (j = i-1 ; j >= 0 ; j--) {
		if (id == part_list->items[j].id) {
		    /* duplicate id, keep only the first of its kind */
		    part_list->items[i].quota = 0.;
		    break;
		}
	    }
	    if (j >= 0) {
		/* duplicate id, skip */
		continue;
	    }
	}
	/* else: other modes does not need id de-duplication */

	percent_available = -1.;
	if (part_list->items[i].total > 0) {
	    percent_available = (part_list->items[i].available * (double)100. / part_list->items[i].total);
	}
	percent_used = 100. - percent_available;

	/* ensure we got a consistent value */
	if ((percent_available<0.) || (percent_available>100.)) {
	    /* fallback to random mode */
	    part_list->force_random = 1;
	    break;
	}

	part_list->items[i].quota = percent_available;
	/* Note: beware floating-point precision between variables stored in
	 * memory and CPU registers. From now on, do not use percent_available.
	 */

	if (part_list->items[i].quota < quota_min) {
	    quota_min = part_list->items[i].quota;
	}

	/* check free space against limit */
	if (part_list->items[i].quota <= quota_limit) {
	    /* entry below limit, will not be taken into account (unless all
	       entries are below limit) */
	    continue;
	}
	/* at least one entry is ok, quota limit can be applied */
	quota_limit_use = 1;
	if (part_list->items[i].quota < quota_min_limit) {
	    quota_min_limit = part_list->items[i].quota;
	}
    }

    if (quota_limit_use) {
	quota_min = quota_min_limit;
    }

    for (i=0 ; i<part_list->size ; i++) {
	if (part_list->force_random) {
	    part_list->items[i].quota = 50.0;
	}
	else if (quota_limit_use && (part_list->items[i].quota <= quota_limit)) {
	    /* entry is below limit, make sure not to select it */
	    part_list->items[i].quota = 0.;
	}
	else if (mode == PART_MODE_FREESPACE_PERCENT_WEIGHTED_DELTA) {
	    /* Note: according to previous tests, current item quota shall be
	     * >= quota_min. Even with differences in floating-point precision
	     * between variables stored in memory and CPU registers, the former
	     * would be slightly under the latter, which would not matter since
	     * we are about to add .5.
	     */

	    /* the goal is to reach the level of the most used volume */
	    part_list->items[i].quota -= quota_min;
	    /* but prevent the most used one to starve */
	    part_list->items[i].quota += .5;

	    /* Sanity check */
	    if (part_list->items[i].quota < 0) {
		/* Guess that may happen considering floating-point precision
		 * issues if current item quota was near quota_limit ?
		 */
		part_list->items[i].quota = 0.;
	    }
	}
    }

    if (part_list->force_random) {
	/* nothing else to do */
	return;
    }

    if ((mode == PART_MODE_FREESPACE_PERCENT_WEIGHTED) || (mode == PART_MODE_FREESPACE_PERCENT_WEIGHTED_DELTA)) {
	/* normalize */
	for (i=0 ; i<part_list->size ; i++) {
	    quota_total += part_list->items[i].quota;
	}
	if (quota_total != 0) {
	    for (i=0 ; i<part_list->size ; i++) {
		part_list->items[i].quota = (part_list->items[i].quota * 100.) / quota_total;
	    }
	}
    }
}


static void partlist_fill(const char *key, const char *value, void *rock)
{
    partlist_conf_t *part_list_conf = (partlist_conf_t *)rock;
    partlist_t *part_list = part_list_conf->part_list;
    int key_prefix_len = (part_list_conf->key_prefix ? strlen(part_list_conf->key_prefix) : 0);
    int i;

    if (key_prefix_len) {
	if ((strncmp(part_list_conf->key_prefix, key, key_prefix_len) != 0) || (strlen(key) <= key_prefix_len)) {
	    return;
	}
    }

    for (i=0 ; i<part_list_conf->excluded_count ; i++) {
	if (!strcmp(key+key_prefix_len, (part_list_conf->excluded_item)[i])) {
	    return;
	}
    }

    part_list->items = (partitem_t *)xrealloc(part_list->items, (part_list->size+1) * sizeof(partitem_t));
    memset(&part_list->items[part_list->size], 0, sizeof(partitem_t));
    part_list->items[part_list->size].item = xstrdup(key + key_prefix_len);
    part_list->items[part_list->size].value = xstrdup(value);
    /* item usage data will be filled later */

    part_list->size++;
}


/**
 * \brief Fills partition data.
 *
 * @param inout part_list   items list structure
 * @param in    idx         item index
 */
void partition_filldata(partlist_t *part_list, int idx)
{
    partitem_t *item = &part_list->items[idx];
    struct statvfs stat;

    item->id = 0;
    item->available = 0;
    item->total = 0;
    item->quota = 0.;

    if (statvfs(item->value, &stat)) {
	/* statvfs error */
	syslog(LOG_ERR, "IOERROR: statvfs[%s]: %m", item->value);
	return;
    }

    if (stat.f_blocks <= 0) {
	/* error retrieving statvfs info */
	syslog(LOG_ERR, "IOERROR: statvfs[%s]: non-positive number of blocks", item->value);
	return;
    }

    item->id = stat.f_fsid;
    item->available = (partusage_t)(stat.f_bavail * (stat.f_frsize / 1024.));
    item->total = (partusage_t)(stat.f_blocks * (stat.f_frsize / 1024.));
}


void partlist_local_init(void)
{
    if (partlist_local) {
	/* already done */
	return;
    }

    partlist_local = calloc(1, sizeof(partlist_t));
    partlist_initialize(
	partlist_local,
	NULL,
	"partition-",
	NULL,
	config_getstring(IMAPOPT_PARTITION_MODE_EXCLUDE),
	0,
	partlist_getmode(config_getstring(IMAPOPT_PARTITION_MODE)),
	config_getint(IMAPOPT_PARTITION_MODE_WEIGHTED_USAGE_LIMIT),
	config_getint(IMAPOPT_PARTITION_MODE_USAGE_REINIT)
    );
}


const char *partlist_local_select(void)
{
    /* lazy loading */
    if (!partlist_local) {
	partlist_local_init();
    }

    return (char *)partlist_select_item(partlist_local);
}


const char *partlist_local_find_freespace_most(int percent,
					       partusage_t *available,
					       partusage_t *total,
					       partusage_t *tavailable,
					       partusage_t *ttotal)
{
    const char *item = NULL;
    unsigned long id;
    partusage_t available_tmp;
    partusage_t total_tmp;
    double percent_available;
    partusage_t available_max = 0;
    double percent_available_max = 0.;
    int i;
    int j;

    /* lazy loading */
    if (!partlist_local) {
	partlist_local_init();
    }

    if (available) *available = 0;
    if (total) *total = 0;
    if (tavailable) *tavailable = 0;
    if (ttotal) *ttotal = 0;

    partlist_bump_action(partlist_local);

    for (i=0 ; i<partlist_local->size ; i++) {
	if (partlist_local->items[i].quota == 0.) {
	    continue;
	}

	id = partlist_local->items[i].id;
	for (j = i-1 ; j >= 0 ; j--) {
	    if (id == partlist_local->items[j].id) {
		/* duplicate id */
		break;
	    }
	}
	if (j >= 0) {
	    /* duplicate id, skip */
	    continue;
	}

	available_tmp = partlist_local->items[i].available;
	total_tmp = partlist_local->items[i].total;

	if (tavailable) *tavailable += available_tmp;
	if (ttotal) *ttotal += total_tmp;

	if (percent) {
	    percent_available = 0.;
	    if (total_tmp > 0) {
		percent_available = (available_tmp * (double)100. / total_tmp);
	    }
	    if ((percent_available > percent_available_max) && (percent_available <= 100.)) {
		percent_available_max = percent_available;
		item = partlist_local->items[i].item;
		if (available) *available = available_tmp;
		if (total) *total = total_tmp;
	    }
	}
	else {
	    if (available_tmp > available_max) {
		available_max = available_tmp;
		item = partlist_local->items[i].item;
		if (available) *available = available_tmp;
		if (total) *total = total_tmp;
	    }
	}
    }

    return item;
}


void partlist_local_done(void)
{
    if (partlist_local) {
	partlist_free(partlist_local);
	free(partlist_local);
	partlist_local = NULL;
    }
}
