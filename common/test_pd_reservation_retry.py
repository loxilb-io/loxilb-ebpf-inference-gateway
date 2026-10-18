#!/usr/bin/env python3
"""Compile the production vLLM retry body; inject dial/rewrite/alloc/send failures.

Selector/CAS and whole-client cleanup are separate tests/native gates. Here dial,
notifier and cleanup are fixtures; no engine or Gateway process is modified.
"""
import os
from pathlib import Path
import subprocess
import tempfile
r=Path(__file__).resolve().parent
s=(r/'sockproxy_pd_vllm.c').read_text();start=s.index('void\npd_retry_prefill(');opening=s.index('{',start);end=opening+1;depth=1
while depth:
 depth+=(s[end]=='{')-(s[end]=='}');end+=1
body=s[start:end]
prefix=r'''
#define _GNU_SOURCE
#define TEST_PD_CACHE_AWARE 1
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#define MAX_PROXY_EP 4
#define PD_PHASE_PREFILL_SENDING 1
#define PD_PHASE_PREFILL_WAITING 2
#define PD_PHASE_ERROR 3
#define PD_ENGINE_TRTLLM 2
#define PROXY_SOCK_ACTIVE 1
#define HTTP_BOTH 1
#define NOTI_TYPE_IN 1
#define NOTI_TYPE_HUP 2
#define PROXY_LOCK() ((void)0)
#define PROXY_UNLOCK() ((void)0)
#define log_error(...) ((void)0)
#define log_info(...) ((void)0)
#define log_debug(...) ((void)0)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
typedef struct {int n_eps,n_prefill_eps,pd_engine;uint8_t ep_role[4];struct{_Atomic uint32_t active_conns;}pd_ep_loads[4];struct{uint32_t xip;uint16_t xport,nixl_port;}eps[4];}proxy_epval_t;
#include "sockproxy_pd_reservation.h"
typedef struct proxy_fd_ent {
 void *epv,*head,*ssl;int fd,seltype,sse_mode,max_stream_duration_sec,backend_keepalive_sec;
 int has_user_id,has_conv_id;char user_id[128],conversation_id[128];
 int pd_phase,pd_decode_ep_idx,pd_prefill_ep_idx,pd_kv_params_len;
 uint32_t pd_prefill_load_token,pd_decode_load_token;
 uint8_t *pd_saved_headers;size_t pd_saved_headers_len,pd_prefill_resp_len;
 int n_rfd,rfd[4];struct proxy_fd_ent *rfd_ent[4];
 int stype,ep_num,odir,used,parser;uint64_t gen,pd_prefill_start_ns;time_t pd_phase_start_ts;
 struct{void(*on_message_complete)(void);void*uarg;}settings;
}proxy_fd_ent_t;
typedef struct {struct{int ppv2;}val;}proxy_map_ent_t;
typedef int(*pd_body_rewrite_t)(uint8_t*,size_t,uint8_t*,size_t*,size_t);
static struct {_Atomic uint64_t pd_connect_failover;}global_stats;
static struct{void*ns;}context,*proxy_struct=&context;
static int malloc_n,malloc_fail,alloc_fail,rewrite_fail,send_fail,dial_mask,attempts,cleanups,responses,registrations,deleted,closed;
static proxy_fd_ent_t *backend;
static int pd_reserve_prefill(proxy_epval_t*t,proxy_fd_ent_t*p,int*ep,uint32_t mask,int park){
 (void)p;assert(park==0);
 for(int i=1;i<3;i++)if(!(mask&(1u<<i))&&pd_load_try_reserve(t,i,1)){*ep=i;return 0;}return -2;
}
static int proxy_build_ppv2_v4(void*b,size_t n,uint32_t a,uint16_t c,uint32_t d,uint16_t e){(void)b;(void)n;(void)a;(void)c;(void)d;(void)e;return 0;}
static int proxy_setup_ep_connect(uint32_t ip,uint16_t port,int protocol,void*a,void*b,proxy_fd_ent_t*p,void*h,int hn){
 (void)port;(void)protocol;(void)a;(void)b;(void)h;(void)hn;
 proxy_epval_t*t=p->epv;assert(atomic_load(&t->pd_ep_loads[ip].active_conns)==1);attempts++;
 return dial_mask&(1u<<ip)?-1:100+(int)ip;
}
static void circuit_breaker_record_failure(proxy_epval_t*t,int ep){(void)t;(void)ep;}
static int fixture_rewrite(uint8_t*b,size_t n,uint8_t*out,size_t*len,size_t cap){assert(cap>=n);memcpy(out,b,n);*len=n;return rewrite_fail?-1:0;}
#define pd_prepare_prefill_body fixture_rewrite
#define pd_trt_prepare_prefill_body fixture_rewrite
static void pd_update_content_length(uint8_t*b,size_t*n,size_t cap,size_t len){(void)b;(void)n;(void)cap;(void)len;}
static int pd_receipt_rewrite(uint8_t*b,size_t*n,size_t cap,const char*a){(void)b;(void)n;(void)cap;(void)a;return 0;}
static proxy_fd_ent_t*pfe_alloc(void){if(alloc_fail)return NULL;backend=calloc(1,sizeof(*backend));return backend;}
static int pd_framing_v2_on(void){return 0;}
static void pd_resp_parser_init(proxy_fd_ent_t*p){(void)p;}
static void llhttp_init(void*p,int n,void*s){(void)p;(void)n;(void)s;}
static void handle_on_message_complete(void){}
static void proxy_fdlist_link(void*e,proxy_fd_ent_t*p,const char*s){(void)e;(void)p;(void)s;}
static int notify_add_ent_pinned(void*n,int fd,int ty,void*p,uint64_t gen,int own){(void)n;(void)fd;(void)ty;(void)p;(void)gen;(void)own;registrations++;return 0;}
static void pd_session_store(proxy_epval_t*t,const char*k,int p,int d){(void)t;(void)k;(void)p;(void)d;}
static const char*proxy_effective_model(proxy_fd_ent_t*p){(void)p;return "fixture";}
static void llb_ai_pd_record(char*m,int a,int b,int c,int d){(void)m;(void)a;(void)b;(void)c;(void)d;}
static int SSL_write(void*p,const void*b,int n){(void)p;(void)b;responses++;return n;}
static ssize_t fixture_send(int fd,const void*b,size_t n,int flags){(void)fd;(void)b;(void)flags;responses++;return (ssize_t)n;}
static void pd_cleanup(proxy_fd_ent_t*p){
 proxy_epval_t*t=p->epv;pd_load_release(t,&p->pd_prefill_load_token);pd_load_release(t,&p->pd_decode_load_token);cleanups++;
 free(p->pd_saved_headers);p->pd_saved_headers=NULL;
}
static int notify_delete_ent(void*n,int fd,int full){(void)n;(void)fd;(void)full;deleted++;return 0;}
static void*fixture_malloc(size_t n){malloc_n++;return malloc_n==malloc_fail?NULL:malloc(n);}
static int fixture_close(int fd){assert(fd>=100);closed++;return 0;}
static ssize_t fixture_write(int fd,const void*b,size_t n){(void)fd;(void)b;if(send_fail){errno=EIO;return -1;}return (ssize_t)n;}
#define malloc fixture_malloc
#define close fixture_close
#define send fixture_send
#define write fixture_write
'''
suffix=r'''
#undef malloc
#undef close
#undef send
#undef write
static void init(proxy_epval_t*t,proxy_fd_ent_t*p){
 memset(t,0,sizeof(*t));memset(p,0,sizeof(*p));t->n_eps=4;t->n_prefill_eps=3;
 for(int i=0;i<3;i++){t->ep_role[i]=1;t->eps[i].xip=(uint32_t)i;}t->ep_role[3]=2;
 p->epv=t;p->fd=9;p->pd_phase=PD_PHASE_PREFILL_WAITING;p->pd_prefill_ep_idx=0;p->pd_decode_ep_idx=3;
 assert(pd_load_try_reserve(t,0,1));pd_load_commit(t,&p->pd_prefill_load_token,0);
 assert(pd_load_try_reserve(t,3,0));pd_load_commit(t,&p->pd_decode_load_token,3);
 p->pd_saved_headers=malloc(8);memcpy(p->pd_saved_headers,"HEAD",5);
 malloc_n=malloc_fail=alloc_fail=rewrite_fail=send_fail=dial_mask=attempts=cleanups=responses=registrations=deleted=closed=0;backend=NULL;
}
static void run(proxy_fd_ent_t*p){
 static proxy_map_ent_t ent;p->head=&ent;
 uint8_t*h=malloc(8),*b=malloc(8);memcpy(h,"HEAD",5);memcpy(b,"BODY",5);
 pd_retry_prefill(p,0,h,4,b,4);
}
static void zero(proxy_epval_t*t,proxy_fd_ent_t*p){
 pd_cleanup(p);for(int i=0;i<4;i++)assert(!atomic_load(&t->pd_ep_loads[i].active_conns));free(backend);backend=NULL;
}
int main(void){
 proxy_epval_t t;proxy_fd_ent_t p;
 for(int stage=1;stage<=2;stage++){
  init(&t,&p);malloc_fail=stage;run(&p);assert(cleanups==1&&responses==1&&deleted==1&&closed==1);zero(&t,&p);
 }
 puts("PASS actual retry body: prefill/request allocation failures rollback temporary and original P/D units");
 init(&t,&p);alloc_fail=1;run(&p);assert(cleanups==1&&closed==1);zero(&t,&p);
 init(&t,&p);rewrite_fail=1;run(&p);assert(cleanups==1&&closed==1);zero(&t,&p);
 puts("PASS actual retry body: backend-shell allocation and rewrite failure rollback");
 init(&t,&p);dial_mask=6;run(&p);assert(attempts==2&&cleanups==1&&!registrations);zero(&t,&p);
 puts("PASS actual retry body: every replacement dial fails, all temporary reservations returned before exhaustion503");
 init(&t,&p);dial_mask=2;run(&p);assert(attempts==2&&!cleanups&&registrations==1&&p.pd_prefill_ep_idx==2);
 assert(!atomic_load(&t.pd_ep_loads[0].active_conns)&&!atomic_load(&t.pd_ep_loads[1].active_conns)&&atomic_load(&t.pd_ep_loads[2].active_conns)==1);zero(&t,&p);
 puts("PASS actual retry body: failed dial then replacement commit; cancellation cleanup returns final pair once");
 init(&t,&p);send_fail=1;run(&p);assert(registrations==1&&!cleanups&&p.pd_prefill_load_token==2);zero(&t,&p);
 puts("PASS actual retry body: registered-send failure retains client ownership until backend/client cleanup");
 init(&t,&p);atomic_store(&t.pd_ep_loads[1].active_conns,1);atomic_store(&t.pd_ep_loads[2].active_conns,1);run(&p);
 assert(!attempts&&cleanups==1&&atomic_load(&t.pd_ep_loads[1].active_conns)==1&&atomic_load(&t.pd_ep_loads[2].active_conns)==1);
 atomic_store(&t.pd_ep_loads[1].active_conns,0);atomic_store(&t.pd_ep_loads[2].active_conns,0);zero(&t,&p);
 puts("PASS actual retry body: saturated replacements never dial/steal reservations or park mid-request");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='i18-retry-body-') as folder:
 p=Path(folder)/'retry.c';binary=Path(folder)/'retry';p.write_text(prefix+body+suffix)
 subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-fsanitize=address,undefined','-g','-pthread','-I'+str(r),str(p),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
