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
#include <stdlib.h>
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
 /* resp_request_id is the ID a forwarded request was forwarded under
  * (proxy_forwarded_request_id): what an answer in its response phase names. */
 char resp_request_id[300];
 /* what the snapshot is worth to an answer (RID_FWD_*), and whether an
  * earlier answer was owed when the request that began last began */
 unsigned char rid_fwd, rid_prev_owed, resp_kernel;
 struct { char model[32]; } prefix_key;
} proxy_fd_ent_t;
static int emitted, released, sent, send_rc, observed_status;
static char observed_request[32], observed_tenant[32], observed_key[32], observed_code[64];
static uint64_t get_timestamp_ns(void){return 2000000;}
static const char *proxy_effective_model(proxy_fd_ent_t *p){return p->model;}
static const char *proxy_request_id(proxy_fd_ent_t *p){return p->request_id;}
static const char *proxy_forwarded_request_id(const proxy_fd_ent_t *p){return p->resp_request_id;}
/* sockproxy.h's two, as they are there */
static void proxy_request_id_snapshot(proxy_fd_ent_t *p){
 strncpy(p->resp_request_id,p->vllm_request_id,sizeof(p->resp_request_id)-1);
 p->resp_request_id[sizeof(p->resp_request_id)-1]=0;
}
static void proxy_request_id_response_done(proxy_fd_ent_t *p){p->resp_request_id[0]=0;}
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
/* The source under test before these helpers existed (AUDIT_TEST_SOURCE):
 * the rule as it was then, so that every case below can be seen to fail on
 * it. The snapshot was the plain copy and the begin forgot it when nothing
 * was owed; the sender echoed the snapshot whatever its state. */
#ifndef RID_FWD_TAKEN
#define RID_FWD_TAKEN 0x01
#define RID_FWD_UNSURE 0x02
#define RID_FWD_PREV_SEEN 0x04
static void proxy_request_id_forward_snapshot(proxy_fd_ent_t *p){proxy_request_id_snapshot(p);}
static void proxy_request_id_request_begin(proxy_fd_ent_t *p){if(!p->rid_prev_owed) proxy_request_id_response_done(p);}
#endif
/* A request with this ID is handed to a backend and the keep-alive reset
 * runs: the product's forward snapshot twice, then the live field cleared. */
static void fwd(proxy_fd_ent_t *p,const char *id){
 strcpy(p->vllm_request_id,id);
 proxy_request_id_forward_snapshot(p);
 proxy_request_id_forward_snapshot(p);
 p->vllm_request_id[0]=0;
}
/* The next request begins: the request framer's reading of "an earlier
 * answer is owed" (owed), the response status seen since the request before
 * it began (status), then the product's begin, then its own ID is read. */
static void begin_next(proxy_fd_ent_t *p,const char *id,int owed,int status){
 p->rid_prev_owed=(unsigned char)owed;p->metric_response_status=status;
 proxy_request_id_request_begin(p);
 p->metric_response_status=0;p->noted=0;p->metric_ai_recorded=0;p->fc=1;
 strcpy(p->vllm_request_id,id);
}
static void rid_case(int which){
 proxy_fd_ent_t p=request();
 send_rc=0;
 switch(which){
 case 1:
  /* S1. A pipelining client: request A is unanswered, request B arrives
   * whole and is handed to the backend too, then the leg goes away. The one
   * 502 is positionally A's. It carries no ID: not B's, which the snapshot
   * now holds, and A's is gone. */
  fwd(&p,"request-a");begin_next(&p,"request-b",1,0);fwd(&p,"request-b");
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id") && !strstr(last_sent,"request-b"));
  /* and it stays so for a third request begun under the owed answers */
  begin_next(&p,"request-c",1,0);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id"));
  /* until a request begins with nothing owed: the echo is back */
  p=request();fwd(&p,"request-a");begin_next(&p,"request-b",1,0);fwd(&p,"request-b");
  begin_next(&p,"request-d",0,200);fwd(&p,"request-d");
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(strstr(last_sent,"\r\nX-Request-Id: request-d\r\n"));
  break;
 case 2:
  /* S5. Request A was answered; request B has begun (its ID is read) and is
   * not yet handed over when the kept leg closes. The 502 is B's and
   * carries B's own ID; its completion is keyed by it. */
  fwd(&p,"request-a");begin_next(&p,"request-b",0,200);strcpy(p.request_id,"request-b");
  assert(p.resp_request_id[0]==0);      /* A's key was forgotten at B's begin */
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(strstr(last_sent,"\r\nX-Request-Id: request-b\r\nConnection: close\r\n"));
  assert(!strcmp(observed_request,"request-b"));
  break;
 case 3:
  /* S4. A request begins with nothing owed and its first write to a
   * backend fails before the plain branch's snapshot could have run (the
   * SGLang dispatch): the state is the one the request's begin left, and
   * the 502 carries the request's ID. (That the dispatch branch takes the
   * snapshot first is held in the source by make test_ridjoin.) */
  fwd(&p,"request-a");begin_next(&p,"request-b",0,200);strcpy(p.request_id,"request-b");
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(strstr(last_sent,"\r\nX-Request-Id: request-b\r\n"));
  break;
 case 4:
  /* The counters are behind (a response the framer did not count): request
   * A was answered, yet "owed" reads 1 when B begins, so A's key is kept.
   * The kept leg closes before B is handed over. The 502 is B's; it must
   * not carry A's ID. The gateway cannot tell this from a pipelining
   * client: no ID. */
  fwd(&p,"request-a");begin_next(&p,"request-b",1,200);
  assert(!strcmp(p.resp_request_id,"request-a"));
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id") && !strstr(last_sent,"request-a"));
  /* where the answers go by the kernel no status is ever seen: the same
   * state without one, and no ID either (not A's) */
  p=request();p.resp_kernel=1;fwd(&p,"request-a");begin_next(&p,"request-b",1,0);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id"));
  break;
 case 5:
  /* What must not change. The backend drops request A after the client sent
   * the start of B: the 502 is A's, by A's snapshot ... */
  fwd(&p,"request-a");begin_next(&p,"request-b",1,0);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(strstr(last_sent,"\r\nX-Request-Id: request-a\r\n") && !strstr(last_sent,"request-b"));
  /* ... an ordinary connection, nothing after A: A's ... */
  p=request();fwd(&p,"request-a");
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(strstr(last_sent,"\r\nX-Request-Id: request-a\r\n"));
  /* ... and a first write that fails before the reset, live field still set */
  p=request();strcpy(p.vllm_request_id,"request-a");proxy_request_id_forward_snapshot(&p);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(strstr(last_sent,"\r\nX-Request-Id: request-a\r\n"));
  break;
 case 6:
  /* Pipelining three deep. A is unanswered when B is handed over (unsure);
   * A's answer then begins, and C begins under B's owed answer with A's
   * status seen. That status is not B's: the mark stays, no ID, whether C
   * is handed over or not. */
  fwd(&p,"request-a");begin_next(&p,"request-b",1,0);fwd(&p,"request-b");
  begin_next(&p,"request-c",1,200);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id"));
  fwd(&p,"request-c");p.noted=0;p.metric_ai_recorded=0;p.metric_response_status=0;
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id"));
  break;
 case 7:
  /* Two requests in one read: the request framer has seen B begin before
   * the routing parser reaches A, so A's begin reads "owed", and B's begin
   * runs before A is handed over, after A's completion cleared the status.
   * The live field may already be B's when A's snapshot is taken: no ID. */
  fwd(&p,"request-z");begin_next(&p,"request-a",1,200);
  begin_next(&p,"request-b",1,0);
  proxy_request_id_forward_snapshot(&p);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id") && !strstr(last_sent,"request-b"));
  break;
 case 8:
  /* A is unanswered at the backend. B arrives under it and the gateway
   * answers B itself on the kept connection (the capacity 429): B is never
   * handed over, and its 429 leaves a status. C begins: the counters say an
   * answer is owed (A's), and a status was seen (B's, not A's). The kept
   * leg goes away: the 502 is A's by position. Not C's ID, handed over or
   * not, and A's cannot be told from here: none. */
  fwd(&p,"request-a");begin_next(&p,"request-b",1,0);
  begin_next(&p,"request-c",1,429);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id"));
  p=request();fwd(&p,"request-a");begin_next(&p,"request-b",1,0);
  begin_next(&p,"request-c",1,429);fwd(&p,"request-c");
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id"));
  /* the same when B left no status at all (not handed over, dropped):
   * C's begin finds a snapshot that is two requests old. Not echoed. */
  p=request();fwd(&p,"request-a");begin_next(&p,"request-b",1,0);
  begin_next(&p,"request-c",1,0);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id") && !strstr(last_sent,"request-a"));
  /* A request relayed under A's running stream has no begin of its own:
   * A's status is still there when C begins under the relayed request's
   * owed answer. The 502 is the relayed request's: no ID, not A's, not C's. */
  p=request();fwd(&p,"request-a");begin_next(&p,"request-c",1,200);
  assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
  assert(!strstr(last_sent,"X-Request-Id"));
  break;
 }
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
 /* A request that WAS forwarded and whose backend leg went away before it
  * answered. The 502 and its completion name that request, by the ID it was
  * forwarded under. Not by the live field: a client that has already sent
  * the head of its next request has put the next request's ID there, and
  * the connection's key (proxy_request_id) reads that field first. */
 {int e0=emitted,r0=released,n0=local_notes,s0=sent,st0=last_note_status;
 p=request();send_rc=0;fwd(&p,"test-request-a");
 begin_next(&p,"next-request-b",1,0);strcpy(p.request_id,"next-request-b");
 assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
 assert(strstr(last_sent,"\r\nContent-Length: 53\r\nX-Request-Id: test-request-a\r\nConnection: close\r\n\r\n{"));
 assert(!strstr(last_sent,"next-request-b") && !strstr(last_sent,"X-Loxilb-Refusal-"));
 assert(emitted==e0+1 && observed_status==502 && p.metric_response_status==502);
 assert(!strcmp(observed_request,"test-request-a"));
 assert(p.metric_ai_recorded && !p.fc && local_notes==n0+1);
 proxy_ai_record_completion(&p);        /* once: the boundary owes nothing more */
 assert(emitted==e0+1);
 /* the ordinary connection: nothing came after it, the live field is empty */
 p=request();fwd(&p,"test-request-a");
 assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
 assert(strstr(last_sent,"\r\nX-Request-Id: test-request-a\r\nConnection: close\r\n"));
 assert(emitted==e0+2 && !strcmp(observed_request,"test-request-a"));
 /* forwarded with no ID at all: no header, and never the next request's;
  * the record keeps the connection's key */
 p=request();fwd(&p,"");begin_next(&p,"next-request-b",1,0);
 strcpy(p.request_id,"connection-key");
 assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
 assert(!strstr(last_sent,"X-Request-Id") && !strstr(last_sent,"next-request-b"));
 assert(emitted==e0+3 && !strcmp(observed_request,"connection-key"));
 /* an ID that cannot be one header value is left out; the record has it */
 p=request();fwd(&p,"a\rb");
 assert(proxy_send_backend_unreachable_forwarded(&p,"leg gone")==0);
 assert(!strstr(last_sent,"X-Request-Id") && !strcmp(observed_request,"a\rb"));
 /* the guards of the plain sender hold: an answer begun, a request recorded */
 p=request();fwd(&p,"test-request-a");p.metric_response_status=200;p.noted=1;
 proxy_send_backend_unreachable_forwarded(&p,"response began");
 assert(p.metric_response_status==200 && emitted==e0+4);
 p=request();fwd(&p,"test-request-a");p.ai_gw_mode=0;
 proxy_send_backend_unreachable_forwarded(&p,"raw proxy");
 assert(emitted==e0+4);
 emitted=e0;released=r0;local_notes=n0;sent=s0;last_note_status=st0;}
 {int e0=emitted,r0=released,n0=local_notes,s0=sent,st0=last_note_status;
 const char *only=getenv("RID_ONLY");
 for(int i=1;i<=8;i++) if(!only||atoi(only)==i) rid_case(i);
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
 puts("forwarded request: its 502 and its completion name it by the ID it was forwarded under, never the next request's PASS");
 puts("leg gone: no ID under a pipelined forward or when it cannot be told whose answer it is, the request's own before its forward PASS");
 puts("local answers: an outage completes with its status, a refusal is one deny record at its stage and never a completion, both record the response PASS");
}
'''
with tempfile.TemporaryDirectory() as td:
    p=Path(td);(p/'test.c').write_text(prefix+source[a:b]+source[c:d]+suffix)
    subprocess.run([os.environ.get('CC','cc'),'-std=c11','-Wall','-Wextra','-Werror','-I',str(root),'-o',str(p/'test'),str(p/'test.c')],check=True)
    subprocess.run([str(p/'test')],check=True)
