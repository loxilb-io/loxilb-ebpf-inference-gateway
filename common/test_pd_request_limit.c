#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_pd.h"

static int refusal_status;
static size_t refusal_drain;
int sp_pd_send_refusal(proxy_fd_ent_t *p, int stage, uint16_t status,
                          const char *code, const void *body, size_t len, size_t drain)
{
  (void)p;
  (void)stage;
  assert(code && body && len);
  refusal_status = status;
  refusal_drain = drain;
  return 0;
}

int main(int argc, char **argv)
{
  assert(argc == 2);
  size_t expected = (size_t)strtoull(argv[1], NULL, 10);
  assert(pd_max_request_body_bytes() == expected);
  proxy_fd_ent_t *p = calloc(1, sizeof(*p));
  assert(p);
  p->rcvbuf = calloc(1, SP_SOCK_MSG_LEN);
  assert(p->rcvbuf);
  size_t body_len = expected < 1024 ? expected : 1024;
  size_t hdr = (size_t)sprintf((char *)p->rcvbuf,
      "POST / HTTP/1.1\r\nAccept: application/json\r\nContent-Length: %zu\r\n\r\n", body_len);
  p->http_content_length = body_len;
  p->rcv_off = hdr + body_len;
  memset(p->rcvbuf + hdr, ' ', body_len);
  p->rcvbuf[hdr] = '{';
  p->rcvbuf[hdr + body_len - 1] = '}';
  assert(pd_check_request_body(p) < 0 && refusal_status == 415);
  p->http_body_media = SP_H1_MEDIA_JSON;
  refusal_status = 0;
  assert(pd_check_request_body(p) == 0 && !refusal_status);
  p->rcv_off = expected + hdr + 128; /* following pipelined bytes are not this body */
  assert(pd_check_request_body(p) == 0 && !refusal_status);
  /* Request 2 has different headers. A complete first body must not be
   * mistaken for an incomplete upload and drained using request 2's length. */
  p->http_pipelined = 1;
  p->http_first_content_length = body_len;
  p->http_first_body_media = SP_H1_MEDIA_JSON;
  p->http_first_chunked = 0;
  p->http_content_length = expected + 1024;
  p->http_body_media = 0;
  p->json_guard_chunked = 1;
  assert(pd_check_request_body(p) < 0 && refusal_status == 400);
  assert(refusal_drain == 0);
  free(p->rcvbuf);
  free(p);
  assert(pd_max_request_body_bytes() == expected);
  printf("PASS P/D request byte limit %zu\n", expected);
  return 0;
}
