#!/usr/bin/env python3
"""Run production H1 local-answer code (backend failure, outage, refusal) with callback capture."""
from pathlib import Path
import os, subprocess, tempfile
root = Path(__file__).resolve().parent
source = (root / 'sockproxy_http.c').read_text()
if os.environ.get('AUDIT_TEST_SOURCE'):
    source = Path(os.environ['AUDIT_TEST_SOURCE']).read_text()
a = source.index('static int\nproxy_owes_completion(')
b = source.index('/* One P/D lifecycle record', a)
c = source.index('/* ---- responses the gateway writes itself ----')
d = source.index('\nstatic int\nproxy_send_local_100_continue', c)
prefix = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "sockproxy_end_cause.h"
#include "sockproxy_refusal_mark.h"
typedef struct {
 int odir, ai_gw_mode, metric_ai_recorded, metric_response_status, fc, noted;
 uint64_t metric_req_start_ns;
 long stream_start_ts;
 int usage_prompt_toks, usage_complet_toks, auth_src, adm_priority;
 int adm_class_set, adm_class, adm_objective_denied, adm_hint_not_applied;
 char tenant_id[32], auth_user_id[32], auth_key_id[32], l7_peer_ip[32];
 char auth_net_identity[32], adm_objective[32], request_id[32], model[32];
 char effective_model[32], x_model_header[32];
 /* request_id is the audit key (proxy_request_id: the live field, else the
  * snapshot of an earlier forward); vllm_request_id is the live field alone,
  * the only thing an answer may echo. */
 char vllm_request_id[300];
 struct { char model[32]; } prefix_key;
} proxy_fd_ent_t;
static int emitted, released, sent, send_rc, observed_status;
static char observed_request[32], observed_tenant[32], observed_key[32], observed_code[64];
static uint64_t get_timestamp_ns(void){return 2000000;}
static const char *proxy_effective_model(proxy_fd_ent_t *p){return p->model;}
static const char *proxy_request_id(proxy_fd_ent_t *p){return p->request_id;}
static const char *proxy_origin_ip(proxy_fd_ent_t *p){return p->l7_peer_ip;}
static int proxy_origin_trusted_hops(proxy_fd_ent_t *p){(void)p;return 0;}
static int notify_worker_id(void){return 2;}
static void proxy_pfe_svc_ident(proxy_fd_ent_t *p,char *s,size_t n){(void)p;snprintf(s,n,"lab-service");}
static void fc_permit_release(int *p){if(*p){released++;*p=0;}}
#define AI_GW_CLASS_INFO(a,b,c,d) 0
/* The response record (status and class, no TTFB): every call counted. The
 * product's writer is modelled where the request records depend on it: once
 * per request (the latch), on the client leg only, and it sets the status. */
static int local_notes, last_note_status;
static int proxy_note_local_answer(proxy_fd_ent_t *p,uint16_t s){
 local_notes++;last_note_status=s;
 if(p->odir||p->noted) return 0;
 p->noted=1;p->metric_response_status=s;return 1;
}
static int denies, deny_stage, deny_status;
static char deny_code[48], deny_model[32], deny_tenant[32], deny_request[32];
static void ai_gw_record_local_deny(int stage,const char *rid,int prod,const char *svc,const char *model,
 const char *tenant,const char *key,const char *user,int status,const char *code,const char *cip,
 const char *oip,int hops,int auth,const char *net,int prio,int cls,const char *obj){
 (void)prod;(void)svc;(void)key;(void)user;(void)cip;(void)oip;(void)hops;(void)auth;(void)net;(void)prio;(void)cls;(void)obj;
 denies++;deny_stage=stage;deny_status=status;
 snprintf(deny_code,sizeof(deny_code),"%s",code);snprintf(deny_model,sizeof(deny_model),"%s",model);
 snprintf(deny_tenant,sizeof(deny_tenant),"%s",tenant);snprintf(deny_request,sizeof(deny_request),"%s",rid);
}
static int observed_stream;
static void capture(const char *t,int status,const char *r,const char *k,int stream,const char *c){
 emitted++;observed_status=status;observed_stream=stream;
 snprintf(observed_code,sizeof(observed_code),"%s",c);
 snprintf(observed_tenant,sizeof(observed_tenant),"%s",t);
 snprintf(observed_request,sizeof(observed_request),"%s",r);
 snprintf(observed_key,sizeof(observed_key),"%s",k);
}
#define llb_ai_record_request(t,m,st,lat,ti,to,a,b,c,r,u,k,svc,stream,worker,peer,origin,hops,auth,net,prio,cls,obj) \
 ((void)(m),(void)(lat),(void)(ti),(void)(to),(void)(svc),(void)(worker),(void)(origin),(void)(hops),capture(t,st,r,k,stream,c))
static char last_sent[2048];
static int proxy_send_local_response(proxy_fd_ent_t *p,const void *buf,size_t n){
 (void)p;sent++;
 assert(n==strlen(buf));
 assert(n<sizeof(last_sent));memcpy(last_sent,buf,n+1);
 if(strstr(buf,"backend_unreachable")){
  assert(strstr(buf,"HTTP/1.1 502 Bad Gateway\r\n"));assert(strstr(buf,"Content-Length:"));
 }
 return send_rc;
}
static const char outage503[]="HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n{\"error\":\"no_healthy_backend\"}\r\n";
static const char route503[]="HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n{\"error\":\"model_unavailable\"}\r\n";
'''
suffix = r'''
static proxy_fd_ent_t request(void){
 proxy_fd_ent_t p={.ai_gw_mode=1,.metric_req_start_ns=1000000,.fc=1};
 strcpy(p.tenant_id,"tenant-a");strcpy(p.auth_key_id,"opaque-key-id");
 strcpy(p.request_id,"test-request-a");strcpy(p.vllm_request_id,"test-request-a");
 strcpy(p.model,"model-a");return p;
}
int main(void){
 proxy_fd_ent_t p=request();
 assert(proxy_send_backend_unreachable(&p,"connect failed")==0);
 /* an outage names no stage and carries the request's own ID */
 assert(strstr(last_sent,"\r\nContent-Length: 59\r\nX-Request-Id: test-request-a\r\nConnection: close\r\n\r\n{"));
 assert(!strstr(last_sent,"X-Loxilb-Refusal-"));
 assert(emitted==1 && observed_status==502 && p.metric_response_status==502);
 assert(!strcmp(observed_request,"test-request-a"));
 assert(!strcmp(observed_tenant,"tenant-a") && !strcmp(observed_key,"opaque-key-id"));
 assert(released==1 && p.metric_ai_recorded && !p.fc);
 proxy_ai_record_completion(&p); /* teardown or next-request boundary */
 proxy_send_backend_unreachable(&p,"another terminal notification");
 assert(emitted==1 && released==1);
 p=request();send_rc=-1;
 assert(proxy_send_backend_unreachable(&p,"TLS refused")==-1);
 assert(emitted==2 && observed_status==502 && released==2);
 p=request();p.ai_gw_mode=0;proxy_send_backend_unreachable(&p,"raw proxy");
 p=request();p.odir=1;proxy_send_backend_unreachable(&p,"backend leg");
 p=request();p.metric_response_status=200;p.noted=1;proxy_send_backend_unreachable(&p,"response began");
 assert(p.metric_response_status==200);
 p=request();p.metric_ai_recorded=1;proxy_send_backend_unreachable(&p,"already recorded");
 assert(emitted==2 && sent==7);
 /* every one of those answers is a response its client received: the
  * class record is not limited to the AI population */
 assert(local_notes==7 && last_note_status==502);

 /* An outage: no backend could take it. Completed with its status. */
 p=request();send_rc=0;
 assert(sp_send_local_outage(&p,503,outage503,strlen(outage503))==0);
 /* an outage is not a refusal: no stage. It carries the request's own ID
  * after its status line, and the rest is the text as built. */
 assert(!strncmp(last_sent,"HTTP/1.1 503 Service Unavailable\r\nX-Request-Id: test-request-a\r\n",64));
 assert(!strcmp(last_sent+64,strchr(outage503,'\n')+1) && !strstr(last_sent,"X-Loxilb-Refusal-"));
 assert(emitted==3 && observed_status==503 && p.metric_response_status==503);
 assert(released==3 && p.metric_ai_recorded && local_notes==8 && last_note_status==503);
 assert(denies==0);
 /* answered when the request has no ID of its own left (forwarded, then no
  * backend): as built. The audit key still has the snapshot, the wire not. */
 {int e0=emitted,r0=released,n0=local_notes,s0=sent,st0=last_note_status;
 p=request();p.vllm_request_id[0]=0;send_rc=0;
 sp_send_local_outage(&p,503,outage503,strlen(outage503));
 assert(!strcmp(last_sent,outage503) && !strcmp(observed_request,"test-request-a"));
 proxy_send_backend_unreachable(&p,"no id left");
 assert(!strstr(last_sent,"X-Request-Id"));
 assert(denies==0 && emitted==e0+1 && local_notes==n0+2);
 /* the two answers above, taken back out of the running counts */
 emitted=e0;released=r0;local_notes=n0;sent=s0;last_note_status=st0;}
 p=request();p.ai_gw_mode=0;sp_send_local_outage(&p,503,outage503,strlen(outage503));
 assert(emitted==3 && local_notes==9);

 /* A refusal before any backend was chosen: a deny record at its stage,
  * never a completion; the model is the one this request named. */
 p=request();strcpy(p.effective_model,"model-unknown");
 assert(sp_send_local_refusal(&p,7,503,"model_unavailable",route503,strlen(route503))==0);
 /* the answer names the stage of its deny record and the request, right
  * after its status line; the rest is the text the caller built */
 assert(!strcmp(last_sent,"HTTP/1.1 503 Service Unavailable\r\n"
   "X-Loxilb-Refusal-Stage: route\r\nX-Request-Id: test-request-a\r\n"
   "Connection: close\r\n\r\n{\"error\":\"model_unavailable\"}\r\n"));
 assert(denies==1 && deny_stage==7 && deny_status==503);
 assert(!strcmp(deny_code,"model_unavailable") && !strcmp(deny_model,"model-unknown"));
 assert(!strcmp(deny_tenant,"tenant-a") && !strcmp(deny_request,"test-request-a"));
 assert(emitted==3 && p.fc==1 && local_notes==10 && p.metric_response_status==503);
 /* and no completion is owed beside it: the next request on the connection,
  * or its teardown, must not count the refusal again as completed */
 assert(p.metric_ai_recorded);
 proxy_ai_record_completion(&p);
 assert(emitted==3);
 /* no model named: none is invented from the previous response */
 p=request();
 sp_send_local_refusal(&p,7,503,"no_route",route503,strlen(route503));
 assert(denies==2 && deny_model[0]=='\0');
 p=request();strcpy(p.prefix_key.model,"body-model");
 sp_send_local_refusal(&p,8,400,"invalid_cache_salt",route503,strlen(route503));
 assert(denies==3 && deny_stage==8 && deny_status==400 && !strcmp(deny_model,"body-model"));
 assert(strstr(last_sent,"\r\nX-Loxilb-Refusal-Stage: framing\r\nX-Request-Id: test-request-a\r\n"));
 /* a request with no ID of its own names its stage alone, even when the
  * audit key falls back to an earlier request's ID on the connection: the
  * record keeps that key (the pin's behaviour), the wire never shows it */
 p=request();p.vllm_request_id[0]=0;strcpy(p.request_id,"previous-request");
 sp_send_local_refusal(&p,5,429,"pd_overloaded",route503,strlen(route503));
 assert(strstr(last_sent,"\r\nX-Loxilb-Refusal-Stage: capacity\r\nConnection: close\r\n"));
 assert(!strstr(last_sent,"X-Request-Id") && !strstr(last_sent,"previous-request"));
 assert(!strcmp(deny_request,"previous-request"));
 /* an ID that cannot be one header value is left out, never cut */
 p=request();strcpy(p.vllm_request_id,"a\rb");
 sp_send_local_refusal(&p,7,503,"no_route",route503,strlen(route503));
 assert(strstr(last_sent,"\r\nX-Loxilb-Refusal-Stage: route\r\nConnection: close\r\n"));
 /* a stage with no wire name: no stage line, the ID all the same */
 p=request();
 sp_send_local_refusal(&p,0,503,"no_route",route503,strlen(route503));
 assert(!strncmp(last_sent,"HTTP/1.1 503 Service Unavailable\r\nX-Request-Id: test-request-a\r\nConnection: close\r\n",83));
 assert(!strstr(last_sent,"X-Loxilb-Refusal-"));
 /* an answer that is not a response goes out as built */
 p=request();
 sp_send_local_refusal(&p,7,503,"no_route","not a response\r\n\r\n",18);
 assert(!strcmp(last_sent,"not a response\r\n\r\n"));
 denies-=4;local_notes-=4;
 /* outside the AI population and on the backend leg: no request record */
 p=request();p.ai_gw_mode=0;sp_send_local_refusal(&p,7,503,"no_route",route503,strlen(route503));
 p=request();p.odir=1;sp_send_local_refusal(&p,7,503,"no_route",route503,strlen(route503));
 assert(denies==3 && local_notes==14);
 /* a refusal after the request's response was recorded leaves that
  * response's completion owed, and it is the one written */
 p=request();p.noted=1;p.metric_response_status=200;
 sp_send_local_refusal(&p,7,503,"no_route",route503,strlen(route503));
 assert(denies==4 && !p.metric_ai_recorded);
 proxy_ai_record_completion(&p);
 assert(emitted==4 && observed_status==200);
 assert(observed_stream==0);
 /* An answer a reaper ended after its 200 (the sweep's terminator, a cut):
  * its request record is written once, with the status the client received
  * and the reaper's end ("" for the sweep's clean end), as a stream when it
  * was sent as one; not again, and not for a connection outside the AI
  * population. */
 assert(emitted==4 && observed_code[0]==0);
 p=request();p.noted=1;p.metric_response_status=200;p.stream_start_ts=100;
 proxy_record_reaped_answer(&p,SP_END_STREAM_TIMEOUT);
 assert(emitted==5 && observed_status==200 && observed_stream==1 && p.metric_ai_recorded);
 assert(strcmp(observed_code,"pd_decode_stream_timeout")==0);
 proxy_record_reaped_answer(&p,SP_END_STREAM_TIMEOUT);
 proxy_ai_record_completion(&p);
 assert(emitted==5);
 p=request();p.noted=1;p.metric_response_status=200;
 proxy_record_reaped_answer(&p,SP_END_NONE);
 assert(emitted==6 && observed_status==200 && observed_stream==0 && observed_code[0]==0);
 p=request();p.ai_gw_mode=0;p.metric_response_status=200;proxy_record_reaped_answer(&p,SP_END_IDLE_TIMEOUT);
 p=request();proxy_record_reaped_answer(&p,SP_END_IDLE_TIMEOUT); /* no status seen: nothing owed */
 assert(emitted==6);
 puts("backend-failure audit: identity/status, once-only, send failure, non-AI/backend/started guards PASS");
 puts("reaped answer: recorded once, with the status the client received and the reaper's end, as a stream when sent as one PASS");
 puts("local answers: an outage completes with its status, a refusal is one deny record at its stage and never a completion, both record the response PASS");
}
'''
with tempfile.TemporaryDirectory() as td:
    p=Path(td);(p/'test.c').write_text(prefix+source[a:b]+source[c:d]+suffix)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-I',str(root),'-o',str(p/'test'),str(p/'test.c')],check=True)
    subprocess.run([str(p/'test')],check=True)
