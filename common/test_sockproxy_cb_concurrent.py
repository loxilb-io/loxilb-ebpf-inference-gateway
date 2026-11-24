#!/usr/bin/env python3
"""Stress current production CB code with real threads and sanitizer checks.

Run with SANITIZERS=thread for race detection. --mutation-check deliberately
removes the extracted guard and requires ThreadSanitizer to identify a race.
The temporary harness never edits production files or qualifies Gateway traffic.
"""
from pathlib import Path
import os,subprocess,tempfile,sys
mutation = sys.argv[1:] == ['--mutation-check']
if sys.argv[1:] and not mutation:
 raise SystemExit('usage: test_sockproxy_cb_concurrent.py [--mutation-check]')
R=Path(__file__).resolve().parent
if not (R/'sockproxy_health.c').exists():
 R=R/'common'
s=(R/'sockproxy_health.c').read_text();a=s.index('static pthread_mutex_t cb_transition_lock');b=s.index('// ============================================================================\n// P2: Universal Endpoint',a);impl=s[a:b]
if mutation:
 assert impl.count('pthread_mutex_lock(&cb_transition_lock);') == 1
 assert impl.count('pthread_mutex_unlock(&cb_transition_lock);') == 1
 impl=impl.replace('pthread_mutex_lock(&cb_transition_lock);','(void)cb_transition_lock;').replace('pthread_mutex_unlock(&cb_transition_lock);','(void)cb_transition_lock;')
assert 'circuit_breaker_configure_pool(tepval, enabled, failure_threshold, open_timeout_sec);' in (R/'sockproxy_http.c').read_text()
h=(R/'sockproxy.h').read_text();a=h.index('typedef enum {\n  CB_STATE_CLOSED');b=h.index('} circuit_breaker_t;',a)+len('} circuit_breaker_t;');types=h[a:b]
prefix=r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <sched.h>
#define MAX_PROXY_EP 32
'''+types+r'''
#include "circuit_breaker_origin.h"
#include "circuit_breaker_heal.h"
typedef struct {int n_eps;_Atomic uint8_t cb_enabled;circuit_breaker_t circuit_breakers[32];void*pd_trie;pthread_rwlock_t pd_trie_lock;void*radix;int fc;} proxy_epval_t;
static struct {_Atomic uint64_t pd_cb_flips;} global_stats;
static _Atomic unsigned drains,warms;
static _Atomic int recover_callback;
void circuit_breaker_init(circuit_breaker_t*);
void circuit_breaker_lock(void);void circuit_breaker_unlock(void);
int circuit_breaker_candidate(proxy_epval_t*,int);
static void pd_trie_remove_ep(void*t,int ep){(void)t;(void)ep;circuit_breaker_lock();circuit_breaker_unlock();}
static void pd_parked_drain_ep(proxy_epval_t*p,int ep,const char*why){(void)why;atomic_fetch_add(&drains,1);if(atomic_exchange(&recover_callback,0))circuit_breaker_init(&p->circuit_breakers[ep]);(void)circuit_breaker_candidate(p,ep);}
typedef struct radix_pool radix_pool_t;
static radix_pool_t*sp_radix_active(const proxy_epval_t*p){return (radix_pool_t*)p->radix;}
static void radix_pool_purge_ep(void*t,unsigned ep){(void)t;(void)ep;}
static void fc_ep_warm_start(void*fc,int ep,int ts){(void)fc;(void)ep;(void)ts;atomic_fetch_add(&warms,1);}
#define log_info(...) ((void)0)
#define log_warn(...) ((void)0)
'''
# Assert atomic qualification preserves actual existing CB layout.
legacy=types.replace('_Atomic ','').replace('circuit_breaker_state_t','legacy_state_t').replace('circuit_breaker_t','legacy_cb_t').replace('CB_STATE_','LEGACY_STATE_').replace('struct circuit_breaker','struct legacy_cb')
prefix+=legacy+'\n_Static_assert(sizeof(circuit_breaker_t)==sizeof(legacy_cb_t),"CB ABI size");\n'
for field in ['state','failure_count','success_count','last_failure_ts','open_ts','failure_threshold','success_threshold','open_timeout_sec','half_open_max_requests','half_open_requests','origin_err_streak','origin_tripped']:
 prefix+=f'_Static_assert(offsetof(circuit_breaker_t,{field})==offsetof(legacy_cb_t,{field}),"CB ABI offset {field}");\n'
suffix=r'''
static proxy_epval_t pool;
static _Atomic int ready,go,allowed;
static int mode,iterations;
static void *work(void*arg){intptr_t id=(intptr_t)arg;atomic_fetch_add(&ready,1);while(!atomic_load(&go)){sched_yield();}
 for(int i=0;i<iterations;i++){
  if(mode==0)circuit_breaker_record_failure(&pool,0);
  else if(mode==1){if(!circuit_breaker_should_skip(&pool,0))atomic_fetch_add(&allowed,1);}
  else switch(id%8){
   case 0:circuit_breaker_record_failure(&pool,0);break;
   case 1:circuit_breaker_record_success(&pool,0);break;
   case 2:circuit_breaker_record_origin_error(&pool,0);break;
   case 3:circuit_breaker_record_origin_success(&pool,0);break;
   case 4:(void)circuit_breaker_should_skip(&pool,0);break;
   case 5:(void)circuit_breaker_candidate(&pool,0);break;
   case 6:{int state=pool.circuit_breakers[0].state;assert(state>=0&&state<=2);
    circuit_breaker_t snapshot;circuit_breaker_lock();memcpy(&snapshot,&pool.circuit_breakers[0],sizeof(snapshot));
    assert(snapshot.half_open_requests<=3);assert((snapshot.failure_threshold==5&&snapshot.open_timeout_sec==30)||(snapshot.failure_threshold==7&&snapshot.open_timeout_sec==11));circuit_breaker_unlock();break;}
   case 7:circuit_breaker_configure_pool(&pool,(uint8_t)(i%3!=0),7,11);break;
  }
 }return NULL;
}
static void run(int m,int n,int reps){pthread_t threads[64];mode=m;iterations=reps;ready=go=0;
 for(int i=0;i<n;i++)assert(!pthread_create(&threads[i],NULL,work,(void*)(intptr_t)i));
 while(atomic_load(&ready)!=n){sched_yield();}atomic_store(&go,1);
 for(int i=0;i<n;i++)assert(!pthread_join(threads[i],NULL));
}
int main(void){pool.n_eps=1;pool.cb_enabled=1;pool.pd_trie=&pool;pthread_rwlock_init(&pool.pd_trie_lock,NULL);
 circuit_breaker_init(&pool.circuit_breakers[0]);pool.circuit_breakers[0].failure_threshold=UINT32_MAX;
 run(0,8,10000);assert(pool.circuit_breakers[0].failure_count==80000&&drains==0);
 circuit_breaker_init(&pool.circuit_breakers[0]);drains=0;run(0,32,1);
 assert(pool.circuit_breakers[0].state==CB_STATE_OPEN&&pool.circuit_breakers[0].failure_count==5&&drains==1);
 assert(!circuit_breaker_candidate(&pool,0));assert(circuit_breaker_should_skip(&pool,0));
 circuit_breaker_lock();pool.circuit_breakers[0].state=CB_STATE_HALF_OPEN;circuit_breaker_unlock();
 recover_callback=1;circuit_breaker_record_failure(&pool,0);assert(pool.circuit_breakers[0].state==CB_STATE_CLOSED); /* reentrant callback recovery */
 for(int cycle=0;cycle<100;cycle++){
  circuit_breaker_init(&pool.circuit_breakers[0]);circuit_breaker_lock();
  pool.circuit_breakers[0].state=CB_STATE_OPEN;pool.circuit_breakers[0].open_ts=time(NULL)-31;
  circuit_breaker_unlock();allowed=0;run(1,32,1);
  assert(allowed==3&&pool.circuit_breakers[0].half_open_requests==3);
  circuit_breaker_record_failure(&pool,0);assert(pool.circuit_breakers[0].state==CB_STATE_OPEN);
 }
 circuit_breaker_lock();pool.circuit_breakers[0].open_ts=time(NULL)-31;circuit_breaker_unlock();
 assert(circuit_breaker_heal_guarded(&pool.circuit_breakers[0],time(NULL))==1);
 allowed=0;run(1,32,1);assert(allowed==3);circuit_breaker_record_success(&pool,0);
 assert(pool.circuit_breakers[0].state==CB_STATE_CLOSED);
 run(2,16,10000); /* init/raw snapshots/origin/connect transitions and reentrant trip callbacks */
 assert(circuit_breaker_should_skip(&pool,-1)&&circuit_breaker_should_skip(&pool,32));
 pthread_rwlock_destroy(&pool.pd_trie_lock);puts("PASS production CB exact80000 failures, 100x32 bounded3 probes, 160000 mixed transitions/copy/init/callbacks, ABI unchanged");return 0;}
'''
with tempfile.TemporaryDirectory(prefix='uc8-cb-') as d:
 c=Path(d)/'test.c';exe=Path(d)/'test';c.write_text(prefix+impl+suffix)
 sanitizers='thread' if mutation else os.environ.get('SANITIZERS','address,undefined')
 subprocess.run([os.environ.get('CC','clang'),'-std=c11','-Wall','-Wextra','-Werror','-g','-fsanitize='+sanitizers,'-fno-omit-frame-pointer','-pthread','-I',str(R),str(c),'-o',str(exe)],check=True)
 if mutation:
  result=subprocess.run([str(exe)],capture_output=True,text=True,timeout=180)
  if result.returncode == 0 or 'ThreadSanitizer: data race' not in result.stderr:
   raise SystemExit('Mutation was not detected as a data race:\n'+result.stdout+result.stderr)
  print('PASS removed-guard mutation detected by ThreadSanitizer')
 else:
  subprocess.run([str(exe)],check=True,timeout=180)
