/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include "uthash.h"
#include "sockproxy_internal.h"
#include "sockproxy_hold.h"
#include "sockproxy_refusal.h"

/* Exercise the real writer with only I/O/notifier boundaries substituted.
 * The kernel-backpressure case uses real nonblocking socketpair I/O. */
static proxy_struct_t context;
proxy_struct_t *proxy_struct = &context;
static proxy_fd_ent_t *registered;
static uint64_t registration_gen, now_ns = 1000000000ULL;
static int begun_answer, ended_answer;
static int arm_error, deletes, shuts, notes, denies, arms, wanted;
static int script[64], script_len, script_at, tls_error, real_io;
static int fail_alloc, shutdown_at, drain_eof;
static size_t drain_available, drained;
static unsigned char accepted[1024];
static size_t accepted_len;
static const void *retry_buf;
static int retry_len;

int sp_answer_started(proxy_fd_ent_t *p) { (void)p; return begun_answer; }
void sp_end_started_answer(proxy_fd_ent_t *p, const void *b, size_t n) {
  (void)p;(void)b;(void)n;ended_answer++;
}
int notify_worker_id(void) { return 0; }
void *notify_priv_of_fd(void *ns, int fd, uint64_t *gen) {
  (void)ns;
  if (!registered || registered->fd != fd) return NULL;
  *gen = registration_gen;
  return registered;
}
int sp_notify_arm(void *ns, int fd, notify_type_t type, proxy_fd_ent_t *p, uint64_t gen) {
  (void)ns; (void)fd; (void)p; (void)gen;
  arms++; wanted = type;
  return arm_error ? -1 : 0;
}
int notify_delete_ent(void *ns, int fd, int evict) {
  (void)ns; (void)fd; assert(!evict);
  deletes++; registered->pd_reply.active = 0; registered = NULL;
  return 0;
}
int proxy_note_local_refusal(proxy_fd_ent_t *p, uint16_t status) {
  (void)p; assert(status == 413); notes++; return 0;
}
void proxy_record_local_deny(proxy_fd_ent_t *p, int stage, int status, const char *code) {
  (void)p; (void)stage; assert(status == 413 && code); denies++;
}
int __real_clock_gettime(clockid_t, struct timespec *);
int __wrap_clock_gettime(clockid_t id, struct timespec *t) {
  if (id != CLOCK_MONOTONIC) return __real_clock_gettime(id, t);
  t->tv_sec = now_ns / 1000000000ULL; t->tv_nsec = now_ns % 1000000000ULL;
  return 0;
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t n) { return fail_alloc ? NULL : __real_malloc(n); }
ssize_t __real_send(int, const void *, size_t, int);
static ssize_t attempt(const void *buf, size_t n) {
  int step = script_at < script_len ? script[script_at++] : (int)n;
  if (step <= 0) { errno = step ? -step : EPIPE; return step ? -1 : 0; }
  if ((size_t)step > n) step = (int)n;
  assert(accepted_len + step <= sizeof(accepted));
  memcpy(accepted + accepted_len, buf, step); accepted_len += step;
  return step;
}
ssize_t __wrap_send(int fd, const void *buf, size_t n, int flags) {
  assert((flags & (MSG_DONTWAIT | MSG_NOSIGNAL)) == (MSG_DONTWAIT | MSG_NOSIGNAL));
  return real_io ? __real_send(fd, buf, n, flags) : attempt(buf, n);
}
int __real_shutdown(int, int);
int __wrap_shutdown(int fd, int how) {
  assert(how == SHUT_WR); shuts++; shutdown_at = (int)accepted_len;
  return real_io ? __real_shutdown(fd, how) : 0;
}
int __wrap_SSL_write(SSL *s, const void *buf, int n) {
  (void)s;
  if (retry_buf) { assert(buf == retry_buf && n == retry_len); retry_buf = NULL; }
  int rc = (int)attempt(buf, (size_t)n);
  if (rc < 0 && (errno == EAGAIN || errno == EINTR)) {
    retry_buf = buf; retry_len = n;
    tls_error = errno == EINTR ? SSL_ERROR_WANT_READ : SSL_ERROR_WANT_WRITE;
  } else tls_error = SSL_ERROR_SSL;
  return rc;
}
int __wrap_SSL_get_error(const SSL *s, int n) { (void)s; (void)n; return tls_error; }
ssize_t __real_recv(int, void *, size_t, int);
ssize_t __wrap_recv(int fd, void *buf, size_t n, int flags) {
  if (real_io) return __real_recv(fd,buf,n,flags);
  if (!drain_available) { errno=EAGAIN; return drain_eof ? 0 : -1; }
  if(n>drain_available)n=drain_available;
  drain_available-=n;drained+=n;return (ssize_t)n;
}
int __wrap_SSL_read(SSL *s, void *buf, int n) {
  (void)s; tls_error=SSL_ERROR_WANT_READ;
  return (int)__wrap_recv(123,buf,(size_t)n,MSG_DONTWAIT);
}
int __wrap_SSL_shutdown(SSL *s) { (void)s; return 0; }

static const char reply[] = "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 9\r\nConnection: close\r\n\r\nrefused\r\n";
static void reset(proxy_fd_ent_t *p) {
  registered = NULL; sp_pd_refusal_tick(); /* discard prior dead generation */
  memset(p, 0, sizeof(*p)); p->fd = 123; p->gen = ++registration_gen;
  registered = p; context.ns = &context;
  begun_answer=ended_answer=0;
  arm_error = deletes = shuts = notes = denies = arms = wanted = 0;
  script_len = script_at = accepted_len = fail_alloc = real_io = 0;
  drain_eof=0; drain_available=drained=0;
  retry_buf = NULL; now_ns += 1000000000ULL;
}
static int begin(proxy_fd_ent_t *p) {
  return sp_pd_send_refusal(p, 0, 413, "pd_body_too_large", reply, sizeof(reply)-1, 0);
}
static void complete(proxy_fd_ent_t *p) {
  sp_pd_refusal_event(p, wanted);
  assert(deletes == 1 && shuts == 1 && !p->pd_reply.active);
  assert(accepted_len == sizeof(reply)-1 && shutdown_at == (int)accepted_len);
  assert(!memcmp(accepted, reply, accepted_len));
  assert(notes == 1 && denies == 1);
  sp_pd_refusal_tick();
}
int main(void) {
  proxy_fd_ent_t *p = calloc(1, sizeof(*p)); assert(p);
  reset(p); assert(begin(p) == 0 && shuts == 1 && !arms);
  assert(shutdown_at == sizeof(reply)-1);
  puts("PASS immediate full response before SHUT_WR");

  reset(p); script[0]=7; script[1]=-EAGAIN; script_len=2;
  assert(begin(p)==1 && p->pd_reply.off==7 && !shuts && wanted==NOTI_TYPE_OUT);
  assert(begin(p)==1 && notes==1); /* no duplicate audit / overwrite */
  sp_pd_refusal_event(p, NOTI_TYPE_IN); assert(!shuts);
  complete(p); puts("PASS partial/EAGAIN resume, one refusal receipt");

  reset(p); for(int i=0;i<40;i++) script[i]=1; script_len=40;
  assert(begin(p)==1 && p->pd_reply.off==16 && !shuts);
  sp_pd_refusal_event(p, NOTI_TYPE_OUT); assert(p->pd_reply.off==32 && !shuts);
  complete(p); puts("PASS per-event write budget");

  reset(p); script[0]=-EINTR; script_len=1;
  assert(begin(p)==1 && !shuts); complete(p);
  puts("PASS EINTR retry");

  reset(p); script[0]=7; script[1]=-EAGAIN; script[2]=-EPIPE; script_len=3;
  assert(begin(p)==1); sp_pd_refusal_event(p, wanted);
  assert(deletes==1 && !shuts && accepted_len==7);
  puts("PASS fatal partial write closes without successful half-close");
  reset(p); script[0]=0; script_len=1;
  assert(begin(p)==-1 && !shuts); puts("PASS zero write fails closed");

  reset(p); script[0]=-EAGAIN; script_len=1; assert(begin(p)==1);
  now_ns += SP_PD_REPLY_TIMEOUT_NS-1; sp_pd_refusal_tick(); assert(!deletes);
  now_ns++; sp_pd_refusal_tick(); assert(deletes==1 && !shuts);
  sp_pd_refusal_tick(); assert(deletes==1); puts("PASS 200ms owner-tick deadline");

  reset(p); script[0]=-EAGAIN; script_len=1; assert(begin(p)==1);
  registration_gen++; p->gen=registration_gen; p->pd_reply.active=0;
  now_ns+=SP_PD_REPLY_TIMEOUT_NS; sp_pd_refusal_tick(); assert(!deletes);
  puts("PASS stale fd generation cannot close reused connection");

  reset(p); script[0]=-EAGAIN; script_len=1; fail_alloc=1;
  assert(begin(p)==-1 && !p->pd_reply.active && !shuts); fail_alloc=0;
  reset(p); script[0]=-EAGAIN; script_len=1; arm_error=1;
  assert(begin(p)==-1 && !p->pd_reply.active && !shuts);
  reset(p); script[0]=-EAGAIN; script[1]=-EAGAIN; script_len=2;
  assert(begin(p)==1); arm_error=1; sp_pd_refusal_event(p,wanted);
  assert(deletes==1 && !shuts); puts("PASS allocation/arm/rearm failures");

  for(int i=0;i<2;i++) {
    reset(p); p->ssl=(SSL *)p;
    script[0]=11; script[1]=i ? -EINTR : -EAGAIN; script_len=2;
    assert(begin(p)==1 && !shuts);
    assert(wanted==(i ? NOTI_TYPE_IN : NOTI_TYPE_OUT));
    complete(p);
  }
  puts("PASS TLS partial/WANT_READ/WANT_WRITE stable retry arguments");

  reset(p); p->ssl=(SSL *)p; script[0]=-EPIPE; script_len=1;
  assert(begin(p)==-1 && !shuts); puts("PASS fatal TLS write fails closed");

  reset(p); drain_available=7;
  assert(sp_pd_send_refusal(p,0,413,"limit",reply,sizeof(reply)-1,32)==1);
  assert(shuts==1 && p->pd_reply.draining && wanted==NOTI_TYPE_IN && drained==7);
  drain_available=25; sp_pd_refusal_event(p,NOTI_TYPE_IN);
  assert(!deletes && shuts==1 && drained==32 && p->pd_reply.draining);
  drain_eof=1;sp_pd_refusal_event(p,NOTI_TYPE_IN);
  assert(deletes==1 && shuts==1);
  puts("PASS linger survives body end then closes on peer EOF");

  reset(p); drain_eof=1;
  assert(sp_pd_send_refusal(p,0,413,"limit",reply,sizeof(reply)-1,32)==0 && shuts==1);
  reset(p);
  assert(sp_pd_send_refusal(p,0,413,"limit",reply,sizeof(reply)-1,32)==1);
  now_ns+=SP_PD_REPLY_TIMEOUT_NS;sp_pd_refusal_tick();assert(deletes==1 && shuts==1);
  puts("PASS linger EOF / 200ms deadline closes after complete output");

  reset(p);drain_available=5*1024*1024;
  assert(sp_pd_send_refusal(p,0,413,"limit",reply,sizeof(reply)-1,10*1024*1024)==1);
  assert(drained==16*8192); /* finite work per readiness event */
  for(int i=0;i<40 && !deletes;i++)sp_pd_refusal_event(p,NOTI_TYPE_IN);
  assert(deletes==1 && drained==4*1024*1024 && shuts==1);
  puts("PASS linger 4MiB cap and per-event read budget");

  reset(p);p->ssl=(SSL *)p;script[0]=-EAGAIN;script_len=1;
  assert(sp_pd_send_refusal(p,0,413,"limit",reply,sizeof(reply)-1,32)==1);
  now_ns+=SP_PD_REPLY_TIMEOUT_NS-1000000;
  sp_pd_refusal_event(p,NOTI_TYPE_OUT);
  assert(p->pd_reply.draining && wanted==NOTI_TYPE_IN && shuts==1);
  now_ns+=2000000;sp_pd_refusal_tick();assert(!deletes);
  now_ns+=SP_PD_REPLY_TIMEOUT_NS;sp_pd_refusal_tick();assert(deletes==1 && shuts==1);
  puts("PASS independent output/drain deadlines and TLS read readiness");

  reset(p);begun_answer=1;assert(begin(p)==-1);
  assert(ended_answer==1 && !accepted_len && !shuts && !arms);
  puts("PASS begun answer receives no second status line");

  reset(p); real_io=1;
  int fds[2]; assert(socketpair(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK,0,fds)==0);
  p->fd=fds[0]; int small=1024; assert(!setsockopt(fds[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small)));
  char pad[4096]={0}; size_t padding=0; ssize_t n;
  while((n=__real_send(fds[0],pad,sizeof(pad),MSG_DONTWAIT|MSG_NOSIGNAL))>0) padding+=n;
  assert(errno==EAGAIN && padding>0);
  assert(begin(p)==1 && !shuts && !p->pd_reply.off);
  size_t got=0; while(got<padding) { n=read(fds[1],pad,sizeof(pad)); assert(n>0); got+=n; }
  sp_pd_refusal_event(p,NOTI_TYPE_OUT); assert(deletes==1 && shuts==1);
  n=read(fds[1],pad,sizeof(pad)); assert(n==sizeof(reply)-1 && !memcmp(pad,reply,n));
  assert(read(fds[1],pad,sizeof(pad))==0);
  close(fds[0]); close(fds[1]); sp_pd_refusal_tick();
  puts("PASS real kernel send-buffer EAGAIN and complete client EOF");
  registered=NULL; sp_pd_refusal_tick(); free(p);
  puts("PASS D10 refusal writer (17 groups)");
  return 0;
}
