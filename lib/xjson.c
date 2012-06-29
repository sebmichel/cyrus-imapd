/*
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
 */

#include "xjson.h"

#define ADD_SEP(json) if (buf_cstring(json)[buf_len(json) - 1] != '{') \
	buf_putc(json, ',')

static char *json_escape_str(const char *str)
{
    struct buf buffer = BUF_INITIALIZER;
    int pos = 0;
    unsigned char c;

    do {
	c = str[pos++];
	switch(c) {
	case '\0':
	    break;
	case '\b':
	    buf_appendcstr(&buffer, "\\b");
	    break;
	case '\n':
	    buf_appendcstr(&buffer, "\\n");
	    break;
	case '\r':
	    buf_appendcstr(&buffer, "\\r");
	    break;
	case '\t':
	    buf_appendcstr(&buffer, "\\t");
	    break;
	case '"':
	    buf_appendcstr(&buffer, "\\\"");
	    break;
	case '\\':
	    buf_appendcstr(&buffer, "\\\\");
	    break;
	default:
	    if(c < ' ')
		buf_printf(&buffer, "\\u%04x", (unsigned int)c);
	    else
		buf_putc(&buffer, c);
	    break;
	}
    }
    while(c);

    return buf_release(&buffer);
}

void xjson_start(struct buf *json)
{
    buf_printf(json, "{");
}

void xjson_end(struct buf *json)
{
    buf_printf(json, "}");
}

void xjson_add_str(struct buf *json, const char *key, const char *val)
{
    ADD_SEP(json);
    buf_printf(json, "\"%s\":\"%s\"", key, json_escape_str(val));
}

void xjson_add_str_len(struct buf *json, const char *key,
                       const char *val, size_t len)
{
    ADD_SEP(json);
    buf_printf(json, "\"%s\":\"%.*s\"", key, (int)len, json_escape_str(val));
}

void xjson_add_int(struct buf *json, const char *key, bit64 val)
{
    ADD_SEP(json);
    buf_printf(json, "\"%s\":%lld", key, val);
}

void xjson_add_uint(struct buf *json, const char *key, bit64 val)
{
    ADD_SEP(json);
    buf_printf(json, "\"%s\":%llu", key, val);
}

void xjson_add_strint(struct buf *json, const char *key, const char *val)
{
    ADD_SEP(json);
    buf_printf(json, "\"%s\":%s", key, val);
}
