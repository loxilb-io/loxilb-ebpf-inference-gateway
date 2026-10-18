/* SPDX-License-Identifier: BSD-3-Clause */
#include "sockproxy_pd_terminal.h"
#define JSMN_STATIC
#include "jsmn.h"

static int next_token(const jsmntok_t *tokens, int count, int at)
{
  int end = tokens[at].end;
  for (at++; at < count && tokens[at].start < end; at++) {
  }
  return at;
}

static int key_is(const char *json, const jsmntok_t *token, const char *key)
{
  return token->type == JSMN_STRING && token->end - token->start == (int)strlen(key) &&
         !memcmp(json + token->start, key, strlen(key));
}

/* Only direct choices[].finish_reason strings count. Text inside content,
 * nested metadata, null, error and not_finished do not prove completion. */
static int last_event_finished(const char *json, size_t len)
{
  jsmn_parser parser;
  jsmntok_t tokens[256];
  int array = -1, choices = 0;
  jsmn_init(&parser);
  int count = jsmn_parse(&parser, json, len, tokens, 256);
  if (count < 1 || tokens[0].type != JSMN_OBJECT)
    return 0;
  for (size_t i = tokens[0].end; i < len; i++)
    if (json[i] != ' ' && json[i] != '\r' && json[i] != '\n' && json[i] != '\t')
      return 0;
  for (int i = 1; i + 1 < count && tokens[i].start < tokens[0].end;) {
    if (key_is(json, &tokens[i], "choices")) {
      if (array >= 0 || tokens[i + 1].type != JSMN_ARRAY)
        return 0;
      array = i + 1;
    }
    i = next_token(tokens, count, i + 1);
  }
  if (array < 0)
    return 0;
  for (int i = array + 1; i < count && tokens[i].start < tokens[array].end;) {
    int finish = 0, seen = 0;
    if (tokens[i].type != JSMN_OBJECT)
      return 0;
    for (int k = i + 1; k + 1 < count && tokens[k].start < tokens[i].end;) {
      if (key_is(json, &tokens[k], "finish_reason")) {
        if (seen++)
          return 0;
        jsmntok_t *v = &tokens[k + 1];
        size_t n = v->end - v->start;
        finish = v->type == JSMN_STRING && n > 0 &&
                 !(n == 5 && !memcmp(json + v->start, "error", 5)) &&
                 !(n == 12 && !memcmp(json + v->start, "not_finished", 12));
      }
      k = next_token(tokens, count, k + 1);
    }
    if (!finish)
      return 0;
    choices++;
    i = next_token(tokens, count, i);
  }
  return choices > 0;
}

static void finish_line(sp_pd_finish_t *s)
{
  size_t n = s->line_len;
  if (n && s->line[n - 1] == '\r')
    n--;
  if (!n && !s->line_overflow) {
    if (s->has_data)
      s->finished = !s->event_bad && last_event_finished(s->event, s->event_len);
    s->event_len = 0;
    s->has_data = s->event_bad = 0;
  } else if (s->line_overflow) {
    s->event_bad = 1;
    s->finished = 0;
  } else if ((n == 4 && !memcmp(s->line, "data", 4)) ||
             (n >= 5 && !memcmp(s->line, "data:", 5))) {
    size_t start = n == 4 ? 4 : 5;
    if (start < n && s->line[start] == ' ')
      start++;
    if (s->event_len + n - start + 1 > sizeof(s->event)) {
      s->event_bad = 1;
    } else {
      if (s->has_data)
        s->event[s->event_len++] = '\n';
      memcpy(s->event + s->event_len, s->line + start, n - start);
      s->event_len += n - start;
    }
    s->has_data = 1;
  }
  s->line_len = s->line_overflow = 0;
}

void sp_pd_finish_feed(sp_pd_finish_t *s, const char *data, size_t len)
{
  for (size_t i = 0; i < len; i++) {
    if (data[i] == '\n') {
      finish_line(s);
    } else if (s->line_len < sizeof(s->line)) {
      s->line[s->line_len++] = data[i];
      if (s->line_len == 4 && !memcmp(s->line, "data", 4))
        s->finished = 0;
    } else {
      s->line_overflow = 1;
      s->finished = 0;
    }
  }
}

int sp_pd_idle_policy(int deadline_due, int finished)
{
  return !deadline_due ? 0 : finished ? 2 : 1;
}
