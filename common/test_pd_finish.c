/* SPDX-License-Identifier: BSD-3-Clause
 * The real terminal observer TU, with every byte split and D1 negative twins. */
#include "sockproxy_pd_terminal.h"
#include <assert.h>
#include <stdio.h>

static void feed(sp_pd_finish_t *s, const char *event)
{
  for (size_t i = 0; i < strlen(event); i++)
    sp_pd_finish_feed(s, event + i, 1);
}

int main(void)
{
  sp_pd_finish_t s = {0};
  const char *stop = "data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\r\n\r\n";
  assert(sp_pd_idle_policy(0, 0) == 0 && sp_pd_idle_policy(0, 1) == 0);
  assert(sp_pd_idle_policy(1, 0) == 1 && sp_pd_idle_policy(1, 1) == 2);
  for (size_t cut = 0; cut <= strlen(stop); cut++) {
    memset(&s, 0, sizeof(s));
    sp_pd_finish_feed(&s, stop, cut);
    if (cut < strlen(stop))
      assert(!s.finished);
    sp_pd_finish_feed(&s, stop + cut, strlen(stop) - cut);
    assert(s.finished);
  }
  const char *negative[] = {
      "data\n\n",
      "data",
      "data: {\"choices\":[{\"finish_reason\":null}]}\n\n",
      "data: {\"choices\":[]}\n\n",
      "data: {\"choices\":[{\"delta\":{\"content\":\"finish_reason: stop\"}}]}\n\n",
      "data: {\"choices\":[{\"delta\":{\"finish_reason\":\"stop\"}}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"error\"}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"not_finished\"}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\"},{\"finish_reason\":null}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\",\"finish_reason\":null}]}\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\"}]} garbage\n\n",
      "data: {\"choices\":[{\"finish_reason\":\"stop\"}]}\n",
      "data: {\"error\":\"InternalServerError\"}\n\n",
      "data: {\"usage\":{\"completion_tokens\":10}}\n\n"};
  for (size_t i = 0; i < sizeof(negative) / sizeof(*negative); i++) {
    memset(&s, 0, sizeof(s));
    feed(&s, stop);
    assert(s.finished);
    feed(&s, negative[i]);
    assert(!s.finished);
  }
  memset(&s, 0, sizeof(s));
  feed(&s, "data: {\"choices\":\n");
  feed(&s, "data: [{\"finish_reason\":\"length\"}]}\n\n");
  assert(s.finished);
  feed(&s, ": keepalive\n\n");
  assert(s.finished);
  feed(&s, "data:");
  assert(!s.finished);
  memset(&s, 0, sizeof(s));
  feed(&s, stop);
  feed(&s, "data: ");
  for (size_t i = 0; i < SP_PD_EVENT_MAX + 100; i++)
    feed(&s, "x");
  feed(&s, "\n\n");
  assert(!s.finished);
  feed(&s, stop);
  assert(s.finished);
  puts("D1: complete last finish_reason event only; "
       "partial/null/error/overflow/late-data refuse success: PASS");
  return 0;
}
