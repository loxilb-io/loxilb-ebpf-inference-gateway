/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_fixture.h - a real HTTP/2 gateway connection for unit tests.
 *
 * The fixture runs the product's own HTTP/2 code (sockproxy_h2.c, built with
 * ASan) between two nghttp2 peers the test drives:
 *   - a test client on one end of a socketpair, whose frames reach the
 *     gateway the way a read delivers them;
 *   - fake backends: proxy_setup_ep_connect hands the gateway one end of a
 *     new socketpair and the fixture runs an HTTP/2 server session on the
 *     other, advertising the stream window the test asks for (0 holds every
 *     request body at the gateway until the test opens it).
 * The rest of the gateway the forward path calls is faked here with working
 * answers (one healthy endpoint, a pooled shell, a registration that
 * succeeds) or, in test_h2_fixture_links.c, stood in for: a function no test
 * has reached aborts with its name.
 *
 * A test sets the hooks below for the decisions it is about (admission, the
 * L7 dispatch, the pool lookup, CHWBL); left NULL each gives the plain
 * answer. Every binary linking the fixture is linked with -Wl,--wrap=calloc:
 * h2fx_fail_calloc_size makes the next calloc of that size fail once.
 *
 * h2fx_fini tears everything down, so the leak check reads only the code
 * under test.
 */
#ifndef __TEST_H2_FIXTURE_H__
#define __TEST_H2_FIXTURE_H__

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <nghttp2/nghttp2.h>

#include "uthash.h"
#include "sockproxy.h"
#include "sockproxy_h2.h"
#include "sockproxy_pool.h"
#include "sockproxy_ai_admit.h"

extern int h2fx_checks, h2fx_failures;

#define CHECK(cond, ...) do {                                        \
    h2fx_checks++;                                                   \
    if (cond) {                                                      \
      printf("ok %d - ", h2fx_checks); printf(__VA_ARGS__); printf("\n"); \
    } else {                                                         \
      h2fx_failures++;                                               \
      printf("FAIL %d - ", h2fx_checks); printf(__VA_ARGS__);        \
      printf("  (%s:%d)\n", __FILE__, __LINE__);                     \
    }                                                                \
  } while (0)

/* The listener rule, the gateway's client connection and the test client.
 * h2fx_status[id / 2] is the :status the client got on stream id. */
extern proxy_map_ent_t h2fx_ent;
extern proxy_fd_ent_t *h2fx_pfe;
extern nghttp2_session *h2fx_cl;
#define H2FX_MAX_STREAMS 64
extern int h2fx_status[H2FX_MAX_STREAMS];
/* The value of response header <name> on stream id, NULL when it did not
 * arrive. Regular headers only, the first 16 of a stream, values under 256
 * bytes. */
const char *h2fx_header(int32_t id, const char *name);
/* The response body the client got on stream id, as a string ("" when none;
 * a body of 512 bytes or more is not kept past what fitted). */
const char *h2fx_body(int32_t id);
/* What ai_gw_class_on() answers (0: classes off, as with nothing configured). */
extern int h2fx_class_on;
/* The two completion-record stand-ins (test_h2_fixture_links.c) abort
 * unless a test set h2fx_allow_completion; then they count their calls. */
extern int h2fx_allow_completion, h2fx_completion_requests, h2fx_completion_usage_missing;

void h2fx_init(void);
void h2fx_fini(void);
int h2fx_result(void);   /* prints the totals; the exit code */

/* Everything the gateway wrote, into the client. */
void h2fx_deliver(void);
/* The client's pending frames into the gateway session, through the
 * product's receive callbacks only (nothing is forwarded). */
void h2fx_to_gateway(void);
/* The client's pending frames as a read delivers them: through
 * proxy_h2_handle_client_data, which forwards every complete request. */
int h2fx_gw_read(void);
proxy_h2_stream_t *h2fx_stream(int32_t id);

/* A POST /v1/chat/completions to all.example naming model in x-model, its
 * body len bytes (none: END_STREAM on HEADERS). Queued on the client only:
 * h2fx_gw_read or h2fx_to_gateway sends it. Returns the stream id. */
int32_t h2fx_submit(const char *model, const uint8_t *body, size_t len);

/* A pool of n_eps endpoints 10.0.9.(i+1):8000+i keyed key, linked to the
 * rule; h2fx_fini unlinks and frees it. */
proxy_epval_t *h2fx_pool(const char *key, int n_eps);

/* The product's decisions, set by the test. */
extern proxy_epval_t *h2fx_lpm;   /* find_endpoint_lpm's answer */
extern int h2fx_lpm_calls;
extern void (*h2fx_admit)(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res);
extern int h2fx_admit_calls;      /* NULL hook: unmetered */
extern int (*h2fx_l7)(proxy_fd_ent_t *pfe, proxy_map_ent_t *ent,
                      proxy_epval_t **tepval_out);
extern int h2fx_l7_calls;         /* NULL hook: fall through */
extern int (*h2fx_chwbl)(proxy_epval_t *epv, llm_prefix_key_t *key, int *ep);
                                  /* NULL hook: aborts (not reached) */

/* The fake backends, in connect order. */
#define H2FX_MAX_BACKENDS 4
#define H2FX_BODY_CAP (1 << 16)
typedef struct {
  int gw_fd;                /* the gateway's end, the leg's fd */
  int fd;                   /* the backend's end */
  nghttp2_session *srv;
  int32_t stream;           /* the last stream the backend saw opened */
  int streams;              /* streams opened */
  int end_stream;           /* the last stream's request ended */
  size_t body_len;          /* the last stream's request body */
  uint8_t body[H2FX_BODY_CAP];
} h2fx_backend_t;
extern h2fx_backend_t h2fx_be[H2FX_MAX_BACKENDS];
extern int h2fx_n_be;
extern int h2fx_connect_calls;
extern int32_t h2fx_be_window;    /* the stream window the next backend advertises */

/* The gateway's pending bytes into backend i. */
void h2fx_be_pump(int i);
/* Backend i's pending frames into the gateway, as a read of the leg
 * delivers them (proxy_h2_handle_backend_data); then whatever the gateway
 * sends on is pumped to backend i and delivered to the client. */
int h2fx_be_send(int i);
/* The gateway's leg to backend i (NULL before the connect). */
proxy_fd_ent_t *h2fx_leg(int i);
/* The stream mapping of client stream id on the leg to backend i. */
stream_mapping_t *h2fx_mapping(int i, int32_t id);

/* Fails the next calloc of this size once (0: none armed). */
extern size_t h2fx_fail_calloc_size;
extern int h2fx_calloc_failed;

#endif
