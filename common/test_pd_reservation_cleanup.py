#!/usr/bin/env python3
"""Production cleanup + slot-free wake bodies with actual FIFO/token primitives.

Notifier lookup/enqueue and SGLang drain shutdown are fixtures, not runtime proof.
"""
import os
from pathlib import Path
import subprocess
import tempfile
r=Path(__file__).resolve().parent
def extract(file,name):
 s=(r/file).read_text();start=s.index('void\n'+name+'(') if name in ('pd_cleanup','pd_wake_parked_one') else s.index('int\n'+name+'(')
 opening=s.index('{',start);end=opening+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
prefix=r'''
#define _GNU_SOURCE
#define TEST_PD_CACHE_AWARE 1
#include <assert.h>
#include <stdint.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PD_MAX_QUEUE_DEPTH 64
#define PD_PHASE_NONE 0
#define log_debug(...) ((void)0)
#define log_warn(...) ((void)0)
#define log_info(...) ((void)0)
typedef struct{int fd;uint64_t gen,enqueue_ns;}pd_parked_ent_t;
typedef struct{pd_parked_ent_t slot[64];uint16_t head,tail,count;}pd_parked_fifo_t;
typedef struct{int n_eps;uint8_t ep_role[4];struct{_Atomic uint32_t active_conns;}pd_ep_loads[4];pd_parked_fifo_t pd_parked[4];pthread_mutex_t pd_parked_lock;}proxy_epval_t;
void pd_wake_parked_one(proxy_epval_t*,int);
#define PD_LOAD_WAKE(t,e) pd_wake_parked_one(t,e)
#include "sockproxy_pd_reservation.h"
typedef struct{
 void*epv;int fd;_Atomic uint64_t gen;
 int pd_phase,pd_prefill_ep_idx,pd_decode_ep_idx,pd_sg_active,park_ep_idx;
 uint64_t park_start_ts,pd_sg_room,pd_prefill_start_ns,pd_decode_start_ns;
 uint32_t pd_prefill_load_token,pd_decode_load_token;
 uint8_t *pd_saved_body,*pd_saved_headers,*pd_prefill_resp_buf;
 size_t pd_saved_body_len,pd_saved_headers_len,pd_prefill_resp_len,pd_prefill_resp_cap;
 int pd_prefill_truncated,kv_sr_load_held,kv_sr_ep_idx,pd_kv_params_len,pd_prefill_body_len;
 uint64_t pd_phase_start_ts,pd_decode_content_length,pd_decode_bytes_received;
 int pd_prefill_retries;char pd_kv_params[32];
}proxy_fd_ent_t;
static struct{void*ns;}ps={(void*)1},*proxy_struct=&ps;
static uint64_t reg[64];static int wakes,wakefd,wakerc,drains;
static uint32_t pd_queue_depth_per_ep(void){return 2;}
static void*notify_priv_of_fd(void*ns,int fd,uint64_t*gen){(void)ns;*gen=reg[fd];return reg[fd]?(void*)1:NULL;}
static int notify_owner_thr(void*ns,int fd){(void)ns;(void)fd;return 0;}
static int notify_wake_worker_gen(void*ns,int owner,int fd,uint64_t gen){(void)ns;assert(owner==0&&gen==reg[fd]);wakes++;wakefd=fd;return wakerc;}
static void pd_sg_close_drain(proxy_fd_ent_t*p,int reason){(void)p;(void)reason;drains++;}
static void pd_free_claim(uint8_t**p){uint8_t*b=__atomic_exchange_n(p,NULL,__ATOMIC_ACQ_REL);free(b);}
'''
suffix=r'''
static void init(proxy_epval_t*t,proxy_fd_ent_t*p){
 memset(t,0,sizeof(*t));memset(p,0,sizeof(*p));memset(reg,0,sizeof(reg));t->n_eps=4;t->ep_role[0]=1;t->ep_role[1]=1;t->ep_role[2]=2;t->ep_role[3]=2;
 pthread_mutex_init(&t->pd_parked_lock,NULL);p->epv=t;p->fd=10;p->gen=5;p->park_ep_idx=-1;p->pd_prefill_ep_idx=-1;p->pd_decode_ep_idx=-1;wakes=wakefd=wakerc=drains=0;
}
static void push(proxy_epval_t*t,int fd,uint64_t gen){pd_parked_fifo_t*q=&t->pd_parked[0];q->slot[q->tail]=(pd_parked_ent_t){fd,gen,1};q->tail++;q->count++;}
int main(void){
 proxy_epval_t t;proxy_fd_ent_t p;
 init(&t,&p);assert(pd_load_try_reserve(&t,0,0));pd_load_commit(&t,&p.pd_prefill_load_token,0);assert(pd_load_try_reserve(&t,2,0));pd_load_commit(&t,&p.pd_decode_load_token,2);
 assert(pd_load_try_reserve(&t,0,0)&&pd_load_try_reserve(&t,2,0));p.pd_prefill_ep_idx=0;p.pd_decode_ep_idx=2;p.pd_phase=2;
 p.pd_saved_body=malloc(8);p.pd_saved_headers=malloc(8);p.pd_prefill_resp_buf=malloc(8);pd_cleanup(&p);pd_cleanup(&p);
 assert(atomic_load(&t.pd_ep_loads[0].active_conns)==1&&atomic_load(&t.pd_ep_loads[2].active_conns)==1);assert(!p.pd_prefill_load_token&&!p.pd_decode_load_token&&!p.pd_saved_body&&!p.pd_saved_headers&&!p.pd_prefill_resp_buf);pthread_mutex_destroy(&t.pd_parked_lock);
 puts("PASS actual cleanup body: owned P/D returned once, duplicate cleanup preserves other requests and frees buffers once");
 init(&t,&p);assert(pd_load_try_reserve(&t,2,0));pd_load_commit(&t,&p.pd_decode_load_token,2);assert(pd_load_try_reserve(&t,3,0));p.pd_decode_ep_idx=3;pd_cleanup(&p);
 assert(!atomic_load(&t.pd_ep_loads[2].active_conns)&&atomic_load(&t.pd_ep_loads[3].active_conns)==1);pthread_mutex_destroy(&t.pd_parked_lock);
 puts("PASS actual cleanup body: mutable decode hint never substitutes for owned reservation");
 init(&t,&p);assert(pd_load_try_reserve(&t,0,0)&&pd_load_try_reserve(&t,2,0));p.park_ep_idx=0;p.park_start_ts=1;p.pd_decode_ep_idx=2;push(&t,10,5);push(&t,11,6);reg[11]=6;
 pd_cleanup(&p);pd_cleanup(&p);assert(t.pd_parked[0].count==1&&atomic_load(&t.pd_ep_loads[0].active_conns)==1&&atomic_load(&t.pd_ep_loads[2].active_conns)==1&&!wakes);
 pd_load_put(&t,0);assert(wakes==1&&wakefd==11&&!t.pd_parked[0].count);pthread_mutex_destroy(&t.pd_parked_lock);
 puts("PASS actual cleanup/wake bodies: parked cancel returns FIFO position only; next live waiter wakes on held-slot release");
 init(&t,&p);push(&t,20,3);reg[20]=4;push(&t,21,3);push(&t,22,3);reg[22]=3;pd_wake_parked_one(&t,0);
 assert(wakes==1&&wakefd==22&&!t.pd_parked[0].count);pthread_mutex_destroy(&t.pd_parked_lock);
 puts("PASS actual wake body: recycled and closed FIFO heads skipped without stranding next live waiter");
 init(&t,&p);p.park_ep_idx=0;push(&t,10,6);pd_cleanup(&p);assert(t.pd_parked[0].count==1);pthread_mutex_destroy(&t.pd_parked_lock);
 puts("PASS actual cleanup body: wrong generation cannot remove another queued identity");
 init(&t,&p);push(&t,12,7);reg[12]=7;wakerc=-1;pd_wake_parked_one(&t,0);assert(wakes==1&&!t.pd_parked[0].count);pthread_mutex_destroy(&t.pd_parked_lock);
 puts("PASS actual wake body: failed notify enqueue is bounded by existing max-park reap, no duplicate slot return");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='i18-cleanup-body-') as folder:
 code=Path(folder)/'cleanup.c';binary=Path(folder)/'cleanup'
 code.write_text(prefix+extract('sockproxy_pd.c','pd_parked_pop_head')+extract('sockproxy_pd.c','pd_parked_remove_fd')+extract('sockproxy_http.c','pd_wake_parked_one')+extract('sockproxy_http.c','pd_cleanup')+suffix)
 subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g','-pthread','-I'+str(r),str(code),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
