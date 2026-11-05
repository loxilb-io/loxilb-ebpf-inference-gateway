/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef __SOCKPROXY_JSON_SCAN_H__
#define __SOCKPROXY_JSON_SCAN_H__

#include <stddef.h>
#include <stdint.h>

/* Fixed storage regardless of request length, schema size or nesting depth. */
enum {
  SP_JSON_NOT_OBJECT = -7,
  SP_JSON_DUPLICATE_MODEL = -6,
  SP_JSON_INVALID = -5,
};
typedef struct sp_json_scan {
  uint32_t depth;
  uint8_t phase, string_kind, escaped, key, overflow;
  uint8_t model_seen, model_ready, user_seen, done, model_invalid;
  uint8_t salt_seen, salt_invalid;
  int error;
  size_t raw_len;
  char raw[128 * 6];
  char model[128];
  char user[128];
  char salt[64];
} sp_json_scan_t;

void sp_json_scan_init(sp_json_scan_t *scan);
int sp_json_scan_feed(sp_json_scan_t *scan, const char *data, size_t len);
int sp_json_scan_finish(sp_json_scan_t *scan);
#endif
