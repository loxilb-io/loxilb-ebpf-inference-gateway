#!/usr/bin/env python3
"""Gateway SGLang pair-retry production body, reservation rollback only.

No SGLang engine changes or native SGLang qualification. Reuses dial/cleanup
fixtures from the vLLM retry-body test; actual selector/cleanup have own gates.
"""
import ast
import os
from pathlib import Path
import subprocess
import tempfile
r=Path(__file__).resolve().parent
code=ast.parse((r/'test_pd_reservation_retry.py').read_text())
prefix=next(ast.literal_eval(n.value) for n in code.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='prefix' for t in n.targets))
prefix=prefix.replace('n_prefill_eps,pd_engine;','n_prefill_eps,pd_engine,pd_bootstrap_port;').replace('ep_role[4]','ep_role[5]').replace('pd_ep_loads[4]','pd_ep_loads[5]').replace('eps[4]','eps[5]')
prefix=prefix.replace(' int has_user_id,has_conv_id;', ' int pd_sg_active,pd_sg_drain,is_pd_decode_backend;uint64_t pd_sg_room,pd_decode_start_ns;\n int has_user_id,has_conv_id;')
prefix=prefix.replace('pd_connect_failover;}global_stats;', 'pd_connect_failover,pd_sg_room_retry;}global_stats;')
prefix=prefix.replace('static proxy_fd_ent_t *backend;','static proxy_fd_ent_t *backend,*backends[2];static int nbackend;')
prefix=prefix.replace('assert(atomic_load(&t->pd_ep_loads[ip].active_conns)==1);','if(ip<3)assert(atomic_load(&t->pd_ep_loads[ip].active_conns)==1);')
prefix=prefix.replace('if(alloc_fail)return NULL;backend=calloc(1,sizeof(*backend));return backend;', 'if(++nbackend==alloc_fail)return NULL;backend=calloc(1,sizeof(*backend));assert(nbackend<=2);backends[nbackend-1]=backend;return backend;')
extra=r'''
#define PD_PHASE_DECODE_SENDING 4
#define PROXY_ENT_LOCK(x) ((void)0)
#define PROXY_ENT_UNLOCK(x) ((void)0)
static int select_decode_fail;
static int pd_select_decode(proxy_epval_t*t,proxy_fd_ent_t*p,int*ep){(void)t;if(select_decode_fail)return -1;*ep=4;p->pd_decode_ep_idx=4;return 0;}
static int pd_sg_decode_untouched(proxy_fd_ent_t*p){(void)p;return 1;}
static int pd_sg_room_id(uint64_t*room){*room=42;return 0;}
static int pd_sg_inject_bootstrap(uint8_t*b,size_t n,uint8_t*out,size_t*len,size_t cap,const char*host,int port,uint64_t room){(void)host;(void)port;(void)room;return fixture_rewrite(b,n,out,len,cap);}
static void pd_sg_drain_parser_init(proxy_fd_ent_t*p){(void)p;}
static void pd_sg_abort_pair(proxy_fd_ent_t*p,const char*why,int reason){(void)why;(void)reason;responses++;pd_cleanup(p);}
'''
prefix=prefix.replace('#define malloc fixture_malloc',extra+'\n#define malloc fixture_malloc',1)
s=(r/'sockproxy_pd_sglang.c').read_text();start=s.index('void\npd_sg_retry_pair(');opening=s.index('{',start);end=opening+1;depth=1
while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
body=s[start:end]
suffix=r'''
#undef malloc
#undef close
#undef send
#undef write
static void init(proxy_epval_t*t,proxy_fd_ent_t*p){
 memset(t,0,sizeof(*t));memset(p,0,sizeof(*p));t->n_eps=5;t->n_prefill_eps=3;
 for(int i=0;i<5;i++){t->ep_role[i]=i<3?1:2;t->eps[i].xip=(uint32_t)i;}
 p->epv=t;p->fd=9;p->pd_phase=PD_PHASE_DECODE_SENDING;p->pd_sg_active=1;p->pd_sg_room=7;p->pd_prefill_ep_idx=0;p->pd_decode_ep_idx=3;
 assert(pd_load_try_reserve(t,0,1));pd_load_commit(t,&p->pd_prefill_load_token,0);
 assert(pd_load_try_reserve(t,3,0));pd_load_commit(t,&p->pd_decode_load_token,3);
 p->pd_saved_headers=malloc(8);memcpy(p->pd_saved_headers,"HEAD",5);
 malloc_n=malloc_fail=alloc_fail=rewrite_fail=send_fail=dial_mask=attempts=cleanups=responses=registrations=deleted=closed=0;
 nbackend=select_decode_fail=0;backend=NULL;memset(backends,0,sizeof(backends));
}
static void run(proxy_fd_ent_t*p){static proxy_map_ent_t ent;p->head=&ent;uint8_t*h=malloc(8),*b=malloc(8);memcpy(h,"HEAD",5);memcpy(b,"BODY",5);pd_sg_retry_pair(p,0,h,4,b,4);}
static void zero(proxy_epval_t*t,proxy_fd_ent_t*p){pd_cleanup(p);for(int i=0;i<5;i++)assert(!atomic_load(&t->pd_ep_loads[i].active_conns));for(int i=0;i<2;i++)free(backends[i]);}
int main(void){
 proxy_epval_t t;proxy_fd_ent_t p;
 for(int failure=0;failure<7;failure++){
  init(&t,&p);
  if(failure==0)dial_mask=6;
  if(failure==1)select_decode_fail=1;
  if(failure==2)dial_mask=1u<<4;
  if(failure==3)rewrite_fail=1;
  if(failure==4)malloc_fail=2;
  if(failure==5)alloc_fail=1;
  if(failure==6)alloc_fail=2;
  run(&p);assert(cleanups==1&&responses==1&&!registrations);zero(&t,&p);
 }
 puts("PASS actual SGLang retry body: P dial/decode selection/D dial/injection/request allocation/both shell allocation failures rollback all reservations");
 init(&t,&p);dial_mask=2;run(&p);assert(!cleanups&&registrations==2&&p.pd_prefill_ep_idx==2&&p.pd_decode_ep_idx==4);
 assert(!atomic_load(&t.pd_ep_loads[0].active_conns)&&!atomic_load(&t.pd_ep_loads[1].active_conns)&&atomic_load(&t.pd_ep_loads[2].active_conns)==1&&!atomic_load(&t.pd_ep_loads[3].active_conns)&&atomic_load(&t.pd_ep_loads[4].active_conns)==1);zero(&t,&p);
 puts("PASS actual SGLang retry body: failed candidate, replacement pair commit, both old units returned, final cancellation balanced");
 init(&t,&p);send_fail=1;run(&p);assert(!cleanups&&registrations==2&&p.pd_prefill_load_token==2&&p.pd_decode_load_token==5);zero(&t,&p);
 puts("PASS actual SGLang retry body: send failure leaves only the committed pair for later client/backend cleanup");
 return 0;
}
'''
with tempfile.TemporaryDirectory(prefix='i18-sg-retry-body-') as folder:
 p=Path(folder)/'sg.c';binary=Path(folder)/'sg';p.write_text(prefix+body+suffix)
 subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-fsanitize=address,undefined','-g','-pthread','-I'+str(r),str(p),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
