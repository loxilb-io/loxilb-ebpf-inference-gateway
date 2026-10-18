/* Only I18 owner-wake generation/overflow checks; no notifier benchmarks. */
#define _GNU_SOURCE
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "notify.c"
__thread volatile sig_atomic_t g_llb_proxy_worker=0;
static int resumed;
static void resume_cb(int fd){assert(fd>0);resumed++;}
int main(void){
 notify_cbs_t cb={.resume=resume_cb};notify_ctx_t*t=notify_ctx_new(&cb,1);assert(t);
 int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM,0,pair));int fd=pair[0];int private=7;
 assert(!notify_add_ent(t,fd,NOTI_TYPE_IN|NOTI_TYPE_HUP,&private,1));
 assert(!notify_wake_worker_gen(t,0,fd,1));notify_drain_resume(t,0);assert(resumed==1);
 /* Queued generation1 must not resume the new generation2 on the same fd. */
 assert(!notify_wake_worker_gen(t,0,fd,1));assert(!notify_deregister_ent(t,fd));
 assert(!notify_add_ent(t,fd,NOTI_TYPE_IN|NOTI_TYPE_HUP,&private,2));notify_drain_resume(t,0);assert(resumed==1);
 assert(!notify_wake_worker_gen(t,0,fd,2));notify_drain_resume(t,0);assert(resumed==2);
 assert(!notify_wake_worker_gen(t,0,fd,2));assert(!notify_deregister_ent(t,fd));notify_drain_resume(t,0);assert(resumed==2);
 assert(!notify_add_ent(t,fd,NOTI_TYPE_IN|NOTI_TYPE_HUP,&private,3));
 assert(!notify_wake_worker(t,0,fd));notify_drain_resume(t,0);assert(resumed==3);
 for(int i=0;i<MAX_NOTIFY_RESUME_PENDING;i++)assert(!notify_wake_worker_gen(t,0,fd,2));
 assert(notify_wake_worker_gen(t,0,fd,3)==-ENOSPC);notify_drain_resume(t,0);assert(resumed==3);
 assert(notify_wake_worker_gen(t,-1,fd,3)==-EINVAL);
 assert(!notify_wake_worker_gen(t,0,fd,3));notify_drain_resume(t,0);assert(resumed==4);
 puts("PASS actual notifier ring: qualified wake, pending fd recycle, canceled fd, legacy API, full-ring rejection/recovery");
 close(pair[0]);close(pair[1]);fflush(stdout);
 /* Production notifier has no context-destroy API. No leak-freedom claim. */
 _exit(0);
}
