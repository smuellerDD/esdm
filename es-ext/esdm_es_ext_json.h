/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * The status of an external source, checked alike by the ESDM and by the
 * provider server wrapping the status of its source. It comes from another
 * process and becomes part of the ESDM status: a JSON object, or nothing.
 * json-c alone is not strict enough, even in strict mode: it takes NaN and
 * Infinity and writes them out again, and member names of any bytes.
 */

#ifndef _ESDM_ES_EXT_JSON_H
#define _ESDM_ES_EXT_JSON_H

#include <json-c/json.h>
#include <limits.h>
#include <math.h>

#include "esdm_es_ext_proto.h"

/*
 * Nesting of the status of a source, the object itself counted; the server
 * wraps it in one level more
 */
#define ESDM_ES_EXT_STATUS_MAX_DEPTH 8

/*
 * Finite numbers only, and strings - escapes resolved - and member names
 * without what steers a terminal
 */
static inline bool esdm_es_ext_json_clean(struct json_object *obj)
{
	size_t i;

	switch (json_object_get_type(obj)) {
	case json_type_double:
		return isfinite(json_object_get_double(obj));
	case json_type_string:
		return esdm_es_ext_utf8_valid(
			json_object_get_string(obj),
			(size_t)json_object_get_string_len(obj),
			ESDM_ES_EXT_UTF8_SHOWN);
	case json_type_array:
		for (i = 0; i < json_object_array_length(obj); i++) {
			if (!esdm_es_ext_json_clean(
				    json_object_array_get_idx(obj, i)))
				return false;
		}
		return true;
	case json_type_object: {
		json_object_object_foreach(obj, key, val)
		{
			if (!esdm_es_ext_utf8_valid(key, strlen(key),
						    ESDM_ES_EXT_UTF8_SHOWN) ||
			    !esdm_es_ext_json_clean(val))
				return false;
		}
		return true;
	}
	case json_type_null:
	case json_type_boolean:
	case json_type_int:
	default:
		return true;
	}
}

/*
 * The JSON object of the @len bytes at @text: UTF-8 without NUL, at most @max
 * bytes, nested no deeper than @depth, clean, with only white space after it.
 *
 * @return the object, to be released with json_object_put(), or NULL
 */
static inline struct json_object *esdm_es_ext_json_object(const char *text,
							  size_t len,
							  size_t max,
							  unsigned int depth)
{
	struct json_tokener *tok;
	struct json_object *obj;
	size_t end;

	if (!len || len > max || memchr(text, '\0', len) ||
	    !esdm_es_ext_utf8_valid(text, len, ESDM_ES_EXT_UTF8))
		return NULL;

	/* json-c takes one level less than the depth it is given */
	tok = json_tokener_new_ex((int)depth + 1);
	if (!tok)
		return NULL;
	json_tokener_set_flags(tok, JSON_TOKENER_STRICT);

	obj = json_tokener_parse_ex(tok, text, (int)len);
	end = obj && json_tokener_get_error(tok) == json_tokener_success &&
			      json_object_is_type(obj, json_type_object) &&
			      esdm_es_ext_json_clean(obj) ?
		      json_tokener_get_parse_end(tok) :
		      0;
	json_tokener_free(tok);
	/* @text holds no NUL, which strchr() would find */
	while (end && end < len && strchr(" \t\n\r", text[end]))
		end++;
	if (end != len) {
		json_object_put(obj);
		return NULL;
	}

	return obj;
}

/*
 * A string for the status of a source, NULL for none: what is no UTF-8 and
 * each control character replaced by a '?', as nothing holds a token or reader
 * to a clean name. Shortened to PATH_MAX bytes.
 */
static inline struct json_object *esdm_es_ext_json_text(const char *text)
{
	char copy[PATH_MAX];
	size_t i = 0, j = 0, k, len = text ? strlen(text) : 0;
	uint32_t cp;

	if (!len)
		return NULL;
	while (i < len && j + 4 < sizeof(copy)) {
		k = i;
		if (!esdm_es_ext_utf8_next((const unsigned char *)text, len, &i,
					   &cp)) {
			copy[j++] = '?';
			i++;
		} else if (!esdm_es_ext_utf8_allowed(cp,
						     ESDM_ES_EXT_UTF8_NAME)) {
			copy[j++] = '?';
		} else {
			memcpy(copy + j, text + k, i - k);
			j += i - k;
		}
	}
	copy[j] = '\0';
	return json_object_new_string(copy);
}

#endif /* _ESDM_ES_EXT_JSON_H */
