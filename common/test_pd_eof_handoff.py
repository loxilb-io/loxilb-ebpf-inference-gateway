#!/usr/bin/env python3
"""Execute actual EOF detach/failure bodies with notifier/metric fixtures."""
import os,subprocess,tempfile
from pathlib import Path
r=Path(__file__).resolve().parent;s=(r/'sockproxy_health.c').read_text()
def extract(marker):
 start=s.index(marker);begin=s.index('{',start);end=begin+1;depth=1
 while depth:depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[start:end]
code=r"""
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#define PD_PHASE_PREFILL_WAITING 2
#define PD_PHASE_DECODE_SENDING 4
#define PD_PHASE_DECODE_STREAMING 5
#define PD_PHASE_ERROR 6
#define PD_PHASE_COMPLETE 7
#define SP_REAP_PD_DECODE_EOF 9
#define PROXY_LOCK() (locked++)
#define PROXY_UNLOCK() (locked--)
#define log_warn(...) ((void)0)
typedef struct pfe {
 int fd,odir,n_rfd,rfd[2],pd_phase,sse_active,pd_kv_params_len;
 struct pfe *rfd_ent[2];void *backend_h2_session;
 time_t stream_end_ts;char vllm_request_id[4];
 unsigned reservation;
} proxy_fd_ent_t;
static int locked,ends,records,wakes,expected_phase=2;static proxy_fd_ent_t *recipient;
static const char *proxy_effective_model(proxy_fd_ent_t *p) {(void)p;return "m";}
static void llb_ai_stream_end(char *t,char *m){(void)t;(void)m;ends++;}
static void llb_ai_pd_record(char *m,int p,int d,int k,int fail){(void)m;(void)p;(void)d;(void)k;assert(fail==expected_phase);records++;}
static void pd_reap_respond(proxy_fd_ent_t *p,uint8_t kind){assert(locked==1&&kind==SP_REAP_PD_DECODE_EOF);recipient=p;wakes++;}
"""+extract('static void sp_pd_stream_failed(')+'\n'+extract('int sp_pd_backend_end(')+r"""
static void reset(proxy_fd_ent_t *cl,proxy_fd_ent_t *pre,proxy_fd_ent_t *dec) {
 *cl=(proxy_fd_ent_t){.fd=10,.n_rfd=2,.pd_phase=PD_PHASE_DECODE_STREAMING,.sse_active=1,.reservation=1};
 *pre=(proxy_fd_ent_t){.fd=11,.odir=1,.n_rfd=1,.rfd={10},.rfd_ent={cl}};
 *dec=(proxy_fd_ent_t){.fd=12,.odir=1,.n_rfd=1,.rfd={10},.rfd_ent={cl}};
 cl->rfd_ent[0]=pre;cl->rfd_ent[1]=dec;cl->rfd[0]=11;cl->rfd[1]=12;
 locked=ends=records=wakes=0;recipient=NULL;
}
int main(void) {
 proxy_fd_ent_t cl,pre,dec;
 reset(&cl,&pre,&dec);assert(sp_pd_backend_end(&dec)==1);
 assert(!locked&&ends==1&&records==1&&wakes==1&&recipient==&cl);
 assert(cl.pd_phase==PD_PHASE_ERROR&&!cl.sse_active&&cl.stream_end_ts);
 assert(cl.rfd_ent[0]==&pre&&cl.rfd[0]==11&&!cl.rfd_ent[1]&&cl.rfd[1]==-1);
 assert(!dec.n_rfd&&!dec.rfd_ent[0]&&dec.rfd[0]==-1&&cl.reservation==1);
 assert(!sp_pd_backend_end(&dec)&&ends==1&&records==1&&wakes==1);
 reset(&cl,&pre,&dec);assert(!sp_pd_backend_end(&pre));assert(!wakes&&cl.pd_phase==PD_PHASE_DECODE_STREAMING);
 reset(&cl,&pre,&dec);cl.pd_phase=PD_PHASE_PREFILL_WAITING;assert(!sp_pd_backend_end(&pre)&&!wakes);
 reset(&cl,&pre,&dec);cl.pd_phase=PD_PHASE_COMPLETE;assert(!sp_pd_backend_end(&dec)&&!wakes);
 reset(&cl,&pre,&dec);cl.stream_end_ts=1;assert(!sp_pd_backend_end(&dec)&&!wakes);
 reset(&cl,&pre,&dec);dec.backend_h2_session=&dec;assert(!sp_pd_backend_end(&dec)&&!wakes);
 reset(&cl,&pre,&dec);cl.n_rfd=1;cl.rfd_ent[0]=&dec;cl.rfd[0]=12;
 assert(sp_pd_backend_end(&dec)&&wakes==1&&!cl.rfd_ent[0]);
 reset(&cl,&pre,&dec);cl.pd_phase=PD_PHASE_DECODE_SENDING;cl.sse_active=0;
 assert(sp_pd_backend_end(&dec)&&ends==0&&records==1&&wakes==1);
 reset(&cl,&pre,&dec);expected_phase=3;sp_pd_stream_failed(&cl,3);assert(ends==1&&records==1&&cl.pd_phase==PD_PHASE_ERROR);
 assert(!sp_pd_backend_end(NULL));
 puts("PASS actual EOF handoff: decode detaches once, preserves reservation/prefill, normal/preheaders/H2 controls");
}
"""
with tempfile.TemporaryDirectory(prefix='pd-eof-handoff-') as folder:
 p=Path(folder)/'handoff.c';binary=Path(folder)/'handoff';p.write_text(code)
 subprocess.run([os.environ.get('CC','cc'),'-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g',str(p),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
