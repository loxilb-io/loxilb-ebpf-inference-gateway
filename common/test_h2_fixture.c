/* SPDX-License-Identifier: BSD-3-Clause
 *
 * test_h2_fixture.c - see test_h2_fixture.h.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "test_h2_fixture.h"
#include "sockproxy_qsbr.h"
#include "sockproxy_l7policy.h"
#include "sockproxy_internal.h"

/* The gateway's globals the linked code uses. */
proxy_global_stats_t global_stats;
proxy_struct_t *proxy_struct;
static proxy_struct_t ps;

int h2fx_checks, h2fx_failures;

proxy_map_ent_t h2fx_ent;
proxy_fd_ent_t *h2fx_pfe;
nghttp2_session *h2fx_cl;
int h2fx_status[H2FX_MAX_STREAMS];
#define H2FX_MAX_HDRS 16
/* A value holds a whole request ID (255 bytes). */
static struct { char name[48]; char value[256]; } h2fx_hdrs[H2FX_MAX_STREAMS][H2FX_MAX_HDRS];
static int h2fx_nhdrs[H2FX_MAX_STREAMS];
#define H2FX_CL_BODY_CAP 512
static struct { char data[H2FX_CL_BODY_CAP]; size_t len; } h2fx_cl_body[H2FX_MAX_STREAMS];

const char *
h2fx_header(int32_t id, const char *name)
{
  int i = id / 2;

  if (i < 0 || i >= H2FX_MAX_STREAMS)
    return NULL;
  for (int k = 0; k < h2fx_nhdrs[i]; k++)
    if (!strcmp(h2fx_hdrs[i][k].name, name))
      return h2fx_hdrs[i][k].value;
  return NULL;
}

const char *
h2fx_body(int32_t id)
{
  int i = id / 2;

  if (i < 0 || i >= H2FX_MAX_STREAMS)
    return NULL;
  return h2fx_cl_body[i].data;
}

proxy_epval_t *h2fx_lpm;
int h2fx_lpm_calls;
void (*h2fx_admit)(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res);
int h2fx_admit_calls;
int (*h2fx_l7)(proxy_fd_ent_t *pfe, proxy_map_ent_t *ent, proxy_epval_t **tepval_out);
int h2fx_l7_calls;
int (*h2fx_chwbl)(proxy_epval_t *epv, llm_prefix_key_t *key, int *ep);

h2fx_backend_t h2fx_be[H2FX_MAX_BACKENDS];
int h2fx_n_be;
int h2fx_connect_calls;
int32_t h2fx_be_window = 65535;

size_t h2fx_fail_calloc_size;
int h2fx_calloc_failed;

/* ---- allocation failure injection (-Wl,--wrap=calloc) ---- */

void *__real_calloc(size_t n, size_t size);

void *
__wrap_calloc(size_t n, size_t size)
{
  if (h2fx_fail_calloc_size && n * size == h2fx_fail_calloc_size) {
    h2fx_fail_calloc_size = 0;
    h2fx_calloc_failed++;
    return NULL;
  }
  return __real_calloc(n, size);
}

/* ---- the test client ---- */

static int sv[2];              /* [0] the gateway's client fd, [1] the client's */
#define C2G_CAP (1 << 20)
static uint8_t *c2g;           /* the client's frames, until the gateway reads them */
static size_t c2g_len;

static ssize_t
cl_send(nghttp2_session *s, const uint8_t *data, size_t len, int flags, void *u)
{
  (void)s; (void)flags; (void)u;
  assert(c2g_len + len <= C2G_CAP);
  memcpy(c2g + c2g_len, data, len);
  c2g_len += len;
  return (ssize_t)len;
}

static int
cl_on_header(nghttp2_session *s, const nghttp2_frame *f, const uint8_t *name,
             size_t namelen, const uint8_t *value, size_t valuelen,
             uint8_t flags, void *u)
{
  (void)s; (void)flags; (void)u;
  if (f->hd.type == NGHTTP2_HEADERS && namelen == 7 &&
      !memcmp(name, ":status", 7) && f->hd.stream_id / 2 < H2FX_MAX_STREAMS) {
    char v[8] = { 0 };
    memcpy(v, value, valuelen < 7 ? valuelen : 7);
    h2fx_status[f->hd.stream_id / 2] = atoi(v);
  } else if (f->hd.type == NGHTTP2_HEADERS && namelen && name[0] != ':' &&
             f->hd.stream_id / 2 < H2FX_MAX_STREAMS) {
    int i = f->hd.stream_id / 2, k = h2fx_nhdrs[i];

    if (k < H2FX_MAX_HDRS && namelen < 48 && valuelen < 256) {
      memcpy(h2fx_hdrs[i][k].name, name, namelen);
      h2fx_hdrs[i][k].name[namelen] = 0;
      memcpy(h2fx_hdrs[i][k].value, value, valuelen);
      h2fx_hdrs[i][k].value[valuelen] = 0;
      h2fx_nhdrs[i] = k + 1;
    }
  }
  return 0;
}

static int
cl_on_data(nghttp2_session *s, uint8_t flags, int32_t id, const uint8_t *data,
           size_t len, void *u)
{
  int i = id / 2;

  (void)s; (void)flags; (void)u;
  if (i >= 0 && i < H2FX_MAX_STREAMS &&
      h2fx_cl_body[i].len + len < H2FX_CL_BODY_CAP) {
    memcpy(h2fx_cl_body[i].data + h2fx_cl_body[i].len, data, len);
    h2fx_cl_body[i].len += len;
    h2fx_cl_body[i].data[h2fx_cl_body[i].len] = 0;
  }
  return 0;
}

void
h2fx_deliver(void)
{
  uint8_t b[65536];
  ssize_t n;

  while ((n = read(sv[1], b, sizeof(b))) > 0)
    assert(nghttp2_session_mem_recv(h2fx_cl, b, (size_t)n) == n);
  assert(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

void
h2fx_to_gateway(void)
{
  assert(nghttp2_session_send(h2fx_cl) == 0);
  ssize_t rv = nghttp2_session_mem_recv(h2fx_pfe->h2_session->session, c2g, c2g_len);
  assert(rv == (ssize_t)c2g_len);
  c2g_len = 0;
  assert(nghttp2_session_send(h2fx_pfe->h2_session->session) == 0);
  h2fx_deliver();
}

int
h2fx_gw_read(void)
{
  int rc;

  assert(nghttp2_session_send(h2fx_cl) == 0);
  h2fx_pfe->rcvbuf = c2g;
  h2fx_pfe->rcv_off = c2g_len;
  rc = proxy_h2_handle_client_data(h2fx_pfe);
  h2fx_pfe->rcvbuf = NULL;
  h2fx_pfe->rcv_off = 0;
  c2g_len = 0;
  h2fx_deliver();
  for (int i = 0; i < h2fx_n_be; i++)
    h2fx_be_pump(i);
  return rc;
}

proxy_h2_stream_t *
h2fx_stream(int32_t id)
{
  proxy_h2_stream_t *st = NULL;

  HASH_FIND_INT(h2fx_pfe->h2_session->streams, &id, st);
  return st;
}

/* Request bodies the client sends, one per submitted stream. */
typedef struct {
  uint8_t *data;
  size_t len, off;
} cl_body_t;
static cl_body_t cl_bodies[H2FX_MAX_STREAMS];
static int cl_n_bodies;

static ssize_t
cl_body_read(nghttp2_session *s, int32_t id, uint8_t *buf, size_t len,
             uint32_t *flags, nghttp2_data_source *src, void *u)
{
  cl_body_t *b = src->ptr;
  size_t n = b->len - b->off;

  (void)s; (void)id; (void)u;
  if (n > len)
    n = len;
  memcpy(buf, b->data + b->off, n);
  b->off += n;
  if (b->off == b->len)
    *flags |= NGHTTP2_DATA_FLAG_EOF;
  return (ssize_t)n;
}

int32_t
h2fx_submit(const char *model, const uint8_t *body, size_t len)
{
  nghttp2_nv req[] = {
    { (uint8_t *)":method", (uint8_t *)"POST", 7, 4, 0 },
    { (uint8_t *)":path", (uint8_t *)"/v1/chat/completions", 5, 20, 0 },
    { (uint8_t *)":scheme", (uint8_t *)"http", 7, 4, 0 },
    { (uint8_t *)":authority", (uint8_t *)"all.example", 10, 11, 0 },
    { (uint8_t *)"x-model", (uint8_t *)model, 7, strlen(model), 0 },
  };
  nghttp2_data_provider prd;
  int32_t id;

  if (!len) {
    id = nghttp2_submit_request(h2fx_cl, NULL, req, 5, NULL, NULL);
  } else {
    cl_body_t *b;

    assert(cl_n_bodies < H2FX_MAX_STREAMS);
    b = &cl_bodies[cl_n_bodies++];
    b->data = malloc(len);
    assert(b->data);
    memcpy(b->data, body, len);
    b->len = len;
    b->off = 0;
    prd.source.ptr = b;
    prd.read_callback = cl_body_read;
    id = nghttp2_submit_request(h2fx_cl, NULL, req, 5, &prd, NULL);
  }
  assert(id > 0 && id / 2 < H2FX_MAX_STREAMS);
  return id;
}

/* ---- pools ---- */

static proxy_epval_t *fx_pools[8];
static int fx_n_pools;

static void
no_final(proxy_epval_t *p)
{
  (void)p;
}

proxy_epval_t *
h2fx_pool(const char *key, int n_eps)
{
  proxy_epval_t *p = sp_pool_alloc();

  assert(p && fx_n_pools < (int)(sizeof(fx_pools) / sizeof(fx_pools[0])));
  snprintf(p->ephash_key, sizeof(p->ephash_key), "%s", key);
  p->n_eps = n_eps;
  for (int i = 0; i < n_eps; i++) {
    p->eps[i].xip = htonl(0x0a000900u + (uint32_t)i + 1);
    p->eps[i].xport = htons((uint16_t)(8000 + i));
    p->eps[i].protocol = IPPROTO_TCP;
  }
  assert(sp_pool_link(&h2fx_ent, p) == 0);
  fx_pools[fx_n_pools++] = p;
  return p;
}

/* ---- the fake backends ---- */

static h2fx_backend_t *
be_of(void *u)
{
  return (h2fx_backend_t *)u;
}

static int
be_on_begin_headers(nghttp2_session *s, const nghttp2_frame *f, void *u)
{
  h2fx_backend_t *b = be_of(u);

  (void)s;
  if (f->hd.type == NGHTTP2_HEADERS && f->headers.cat == NGHTTP2_HCAT_REQUEST) {
    b->stream = f->hd.stream_id;
    b->streams++;
    b->end_stream = 0;
    b->body_len = 0;
  }
  return 0;
}

static int
be_on_frame_recv(nghttp2_session *s, const nghttp2_frame *f, void *u)
{
  h2fx_backend_t *b = be_of(u);

  (void)s;
  if ((f->hd.type == NGHTTP2_HEADERS || f->hd.type == NGHTTP2_DATA) &&
      f->hd.stream_id == b->stream && (f->hd.flags & NGHTTP2_FLAG_END_STREAM))
    b->end_stream = 1;
  return 0;
}

static int
be_on_data(nghttp2_session *s, uint8_t flags, int32_t id, const uint8_t *data,
           size_t len, void *u)
{
  h2fx_backend_t *b = be_of(u);

  (void)s; (void)flags;
  if (id == b->stream) {
    assert(b->body_len + len <= H2FX_BODY_CAP);
    memcpy(b->body + b->body_len, data, len);
    b->body_len += len;
  }
  return 0;
}

void
h2fx_be_pump(int i)
{
  h2fx_backend_t *b = &h2fx_be[i];
  uint8_t buf[65536];
  ssize_t n;

  while ((n = read(b->fd, buf, sizeof(buf))) > 0)
    assert(nghttp2_session_mem_recv(b->srv, buf, (size_t)n) == n);
  assert(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
}

proxy_fd_ent_t *
h2fx_leg(int i)
{
  for (int k = 0; k < MAX_PROXY_EP; k++) {
    proxy_fd_ent_t *leg = h2fx_pfe->rfd_ent[k];
    if (leg && leg->fd == h2fx_be[i].gw_fd)
      return leg;
  }
  return NULL;
}

stream_mapping_t *
h2fx_mapping(int i, int32_t id)
{
  proxy_fd_ent_t *leg = h2fx_leg(i);
  backend_h2_session_t *bs = leg ? leg->backend_h2_session : NULL;
  stream_mapping_t *m = NULL;

  if (bs)
    HASH_FIND_INT(bs->stream_map, &id, m);
  return m;
}

int
h2fx_be_send(int i)
{
  h2fx_backend_t *b = &h2fx_be[i];
  proxy_fd_ent_t *leg = h2fx_leg(i);
  static uint8_t buf[1 << 18];
  size_t n = 0;
  const uint8_t *d;
  ssize_t k;
  int rc = 0;

  assert(leg);
  while ((k = nghttp2_session_mem_send(b->srv, &d)) > 0) {
    assert(n + (size_t)k <= sizeof(buf));
    memcpy(buf + n, d, (size_t)k);
    n += (size_t)k;
  }
  assert(k == 0);
  if (n) {
    leg->rcvbuf = buf;
    leg->rcv_off = n;
    rc = proxy_h2_handle_backend_data(leg);
    leg->rcvbuf = NULL;
    leg->rcv_off = 0;
  }
  h2fx_be_pump(i);
  h2fx_deliver();
  return rc;
}

/* ---- the gateway's seams: working fakes ---- */

/* The backend connection: a socketpair, its far end served by an HTTP/2
 * server session advertising h2fx_be_window. */
int
proxy_setup_ep_connect(uint32_t epip, uint16_t epport, uint8_t protocol,
                       void *ssl_ctx, void **ssl, proxy_fd_ent_t *pfe,
                       const void *pp2hdr, int pp2len)
{
  nghttp2_session_callbacks *cb;
  nghttp2_settings_entry win = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE,
                                 (uint32_t)h2fx_be_window };
  h2fx_backend_t *b;
  int p[2];

  (void)epip; (void)epport; (void)protocol; (void)ssl_ctx; (void)pfe;
  (void)pp2hdr; (void)pp2len;
  h2fx_connect_calls++;
  assert(h2fx_n_be < H2FX_MAX_BACKENDS);
  if (ssl)
    *ssl = NULL;
  b = &h2fx_be[h2fx_n_be++];
  memset(b, 0, sizeof(*b));
  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, p) == 0);
  assert(fcntl(p[1], F_SETFL, O_NONBLOCK) == 0);
  b->gw_fd = p[0];
  b->fd = p[1];
  nghttp2_session_callbacks_new(&cb);
  nghttp2_session_callbacks_set_on_begin_headers_callback(cb, be_on_begin_headers);
  nghttp2_session_callbacks_set_on_frame_recv_callback(cb, be_on_frame_recv);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(cb, be_on_data);
  assert(nghttp2_session_server_new(&b->srv, cb, b) == 0);
  nghttp2_session_callbacks_del(cb);
  assert(nghttp2_submit_settings(b->srv, NGHTTP2_FLAG_NONE, &win, 1) == 0);
  return b->gw_fd;
}

int
select_healthy_endpoint(proxy_epval_t *tepval, int algorithm_selection)
{
  return algorithm_selection >= 0 && algorithm_selection < tepval->n_eps ?
    algorithm_selection : -1;
}

void circuit_breaker_record_success(proxy_epval_t *tepval, int ep_index)
{ (void)tepval; (void)ep_index; }
void circuit_breaker_record_failure(proxy_epval_t *tepval, int ep_index)
{ (void)tepval; (void)ep_index; }

/* The legs' shells: h2fx_fini frees them. */
static proxy_fd_ent_t *fx_legs[H2FX_MAX_BACKENDS];
static int fx_n_legs;

proxy_fd_ent_t *
pfe_alloc(void)
{
  proxy_fd_ent_t *p = __real_calloc(1, sizeof(*p));

  assert(p && fx_n_legs < H2FX_MAX_BACKENDS);
  fx_legs[fx_n_legs++] = p;
  return p;
}

void
pfe_recycle(proxy_fd_ent_t *pfe)
{
  (void)pfe;
  puts("test_h2_fixture: pfe_recycle reached");
  abort();
}

int proxy_conn_list_add(struct proxy_map_ent *ent, struct proxy_fd_ent *pfe, const char *what)
{ (void)ent; (void)pfe; (void)what; return 0; }
void proxy_conn_list_del(struct proxy_map_ent *ent, struct proxy_fd_ent *pfe)
{ (void)ent; (void)pfe; }
int proxy_notify_add_fd(int fd, int type, void *priv)
{ (void)fd; (void)type; (void)priv; return 0; }
int proxy_notify_add_fd_pinned(int fd, int type, void *priv, int pin_fd)
{ (void)fd; (void)type; (void)priv; (void)pin_fd; return 0; }
int proxy_leg_tls_stale(const proxy_map_ent_t *ent, const proxy_fd_ent_t *bpfe)
{ (void)ent; (void)bpfe; return 0; }
int ai_security_should_strip_api_key(uint8_t policy)
{ (void)policy; return 0; }

/* ---- the gateway's decisions: the test's hooks ---- */

int
ai_gw_admit(const ai_gw_req_ctx_t *req, ai_gw_admit_result_t *res)
{
  h2fx_admit_calls++;
  memset(res, 0, sizeof(*res));
  if (h2fx_admit)
    h2fx_admit(req, res);
  else
    res->verdict = AI_GW_ADMIT_UNMETERED;
  return 0;
}

int
l7_route_dispatch(struct proxy_fd_ent *pfe, struct proxy_map_ent *ent,
                  struct proxy_epval **tepval_out)
{
  h2fx_l7_calls++;
  *tepval_out = NULL;
  return h2fx_l7 ? h2fx_l7(pfe, ent, tepval_out) : L7_DISPATCH_FALLTHROUGH;
}

proxy_epval_t *
find_endpoint_lpm(proxy_map_ent_t *ent, const char *host, const char *path,
                  const char *model)
{
  (void)ent; (void)host; (void)path; (void)model;
  h2fx_lpm_calls++;
  return h2fx_lpm;
}

int
chwbl_hash_and_select_runtime(proxy_epval_t *tepval, llm_prefix_key_t *key,
                              int *ep_idx)
{
  if (!h2fx_chwbl) {
    puts("test_h2_fixture: chwbl_hash_and_select_runtime reached with no hook");
    abort();
  }
  return h2fx_chwbl(tepval, key, ep_idx);
}

/* ---- set up, tear down ---- */

void
h2fx_init(void)
{
  nghttp2_session_callbacks *ccb;

  setvbuf(stdout, NULL, _IONBF, 0);
  c2g = malloc(C2G_CAP);
  h2fx_pfe = __real_calloc(1, sizeof(*h2fx_pfe));
  assert(c2g && h2fx_pfe);
  pthread_rwlock_init(&ps.lock, NULL);
  ps.head = &h2fx_ent;
  proxy_struct = &ps;
  sp_pool_init(no_final);
  assert(sp_pool_index_publish(&h2fx_ent) == 0);

  assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);
  assert(fcntl(sv[1], F_SETFL, O_NONBLOCK) == 0);
  h2fx_pfe->fd = sv[0];
  h2fx_pfe->head = &h2fx_ent;
  assert(proxy_setup_h2_session(h2fx_pfe, 0) == 0);

  nghttp2_session_callbacks_new(&ccb);
  nghttp2_session_callbacks_set_send_callback(ccb, cl_send);
  nghttp2_session_callbacks_set_on_header_callback(ccb, cl_on_header);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(ccb, cl_on_data);
  assert(nghttp2_session_client_new(&h2fx_cl, ccb, NULL) == 0);
  nghttp2_session_callbacks_del(ccb);
  assert(nghttp2_submit_settings(h2fx_cl, NGHTTP2_FLAG_NONE, NULL, 0) == 0);
  h2fx_deliver();          /* the gateway's preface */
  h2fx_to_gateway();       /* the client's, and the acknowledgements */
}

void
h2fx_fini(void)
{
  /* The client connection's streams and backend sessions (their mappings
   * and request body sources), the product's way. */
  proxy_h2_cleanup_session(h2fx_pfe);
  for (int i = 0; i < fx_n_legs; i++) {
    sp_pool_hold(&fx_legs[i]->epv, NULL);
    free(fx_legs[i]);
  }
  sp_pool_hold(&h2fx_pfe->epv, NULL);
  for (int i = 0; i < h2fx_n_be; i++) {
    nghttp2_session_del(h2fx_be[i].srv);
    close(h2fx_be[i].gw_fd);
    close(h2fx_be[i].fd);
  }
  nghttp2_session_del(h2fx_cl);
  for (int i = 0; i < cl_n_bodies; i++)
    free(cl_bodies[i].data);
  /* The rule's pools, unlinked and freed after the grace period. */
  for (int i = 0; i < fx_n_pools; i++)
    assert(sp_pool_unlink(&h2fx_ent, fx_pools[i]) == 0);
  for (int i = 0; i < 16 && sp_qsbr_pending(); i++)
    sp_qsbr_run_ready();
  close(sv[0]);
  close(sv[1]);
  free(c2g);
  free(h2fx_pfe);
}

int
h2fx_result(void)
{
  printf("%d checks, %d failures\n", h2fx_checks, h2fx_failures);
  return h2fx_failures ? 1 : 0;
}
