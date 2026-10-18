/* Parse the actual concatenated wire with llhttp at every EOF cut. */
#include <assert.h>
#include <stdio.h>
#include "llhttp.h"
#include "sockproxy_pd_terminal.h"
typedef struct { char body[SP_PD_TERMINAL_PAD_MAX+1024]; size_t len; int ended; } observed;
static int body(llhttp_t *p,const char *at,size_t n) {
  observed *o=p->data; assert(o->len+n<sizeof(o->body));
  memcpy(o->body+o->len,at,n);o->len+=n;o->body[o->len]=0;return 0;
}
static int end(llhttp_t *p) { ((observed *)p->data)->ended++; return 0; }
static void check(const char *wire,size_t n,const char *code) {
  sp_pd_wire_t w={.chunked=1};char terminal[SP_PD_TERMINAL_PAD_MAX+512];
  /* Bytewise input covers header, size, extension, payload and CRLF cuts. */
  for(size_t j=0;j<n;j++) sp_pd_wire_feed(&w,wire+j,1);
  size_t k=sp_pd_terminal_format(&w,code,terminal,sizeof(terminal));assert(k);
  observed o={0};llhttp_t p;llhttp_settings_t s;
  llhttp_settings_init(&s);s.on_body=body;s.on_message_complete=end;
  llhttp_init(&p,HTTP_RESPONSE,&s);p.data=&o;
  assert(llhttp_execute(&p,wire,n)==HPE_OK);
  for(size_t j=0;j<k;j++) { int err=llhttp_execute(&p,terminal+j,1); if(err!=HPE_OK) fprintf(stderr,"cut=%zu state=%u left=%llu size=%llu j=%zu err=%s\n",n,w.state,(unsigned long long)w.left,(unsigned long long)w.size,j,llhttp_errno_name(err)); assert(err==HPE_OK); }
  assert(o.ended==1 && strstr(o.body,code));assert(!strstr(o.body,"[DONE]"));
}
int main(void) {
  const char header[]="HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
  const char body[]="10;foo=bar\r\ndata: {\"a\":1}\n\nx\r\n";
  char wire[1024];snprintf(wire,sizeof(wire),"%s%s",header,body);
  size_t h=strlen(header), n=strlen(wire);
  /* Do not cut an incomplete zero-sized size line (HTTP cannot be extended). */
  for(size_t cut=h;cut<=n;cut++) {
    check(wire,cut,"pd_decode_eof");check(wire,cut,"pd_decode_idle_timeout");
  }
  sp_pd_wire_t s={.headers=1};char out[SP_PD_TERMINAL_PAD_MAX+512];
  assert(sp_pd_terminal_format(&s,"pd_decode_eof",out,sizeof(out)));
  s.fixed=1;assert(!sp_pd_terminal_format(&s,"pd_decode_eof",out,sizeof(out)));
  s.fixed=0;s.chunked=1;s.state=SP_PD_END;assert(!sp_pd_terminal_format(&s,"x",out,sizeof(out)));
  s.state=SP_PD_DATA;s.left=SP_PD_TERMINAL_PAD_MAX+1;
  assert(!sp_pd_terminal_format(&s,"x",out,sizeof(out)));
  s.left=SP_PD_TERMINAL_PAD_MAX;assert(sp_pd_terminal_format(&s,"x",out,sizeof(out)));
  s.bad=1;assert(!sp_pd_terminal_format(&s,"x",out,sizeof(out)));
  s.bad=0;s.state=SP_PD_SIZE;s.size=0;s.digits=0;
  assert(!sp_pd_terminal_format(&s,"x",out,1));
  puts("PD terminal: idle/no-content, partial content/EOF, all chunk cuts, bounds PASS");
  return 0;
}
