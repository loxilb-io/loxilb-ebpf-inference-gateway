#!/usr/bin/env python3
"""Execute the production read-error classification with transport fixtures."""
import os,subprocess,tempfile
from pathlib import Path
r=Path(__file__).resolve().parent
s=(r/'sockproxy_http.c').read_text();start=s.index('proxy_sock_read_err(proxy_fd_ent_t *pfe, int rval)')
a=s.index('  if (rval<=0',start);b=s.index('  if (!pfe->ssl || pfe->ktls_enabled)',a)
plain=s[a:b]
a=s.index('    int ssl_error = SSL_get_error(pfe->ssl, rval);',b);b=s.index('#ifdef HAVE_PROXY_EXTRA_DEBUG',a)
tls=s[a:b]
code=r"""
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#define SSL_ERROR_SSL 1
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_SYSCALL 5
#define SSL_ERROR_ZERO_RETURN 6
typedef struct {void *ssl;int ktls_enabled;}proxy_fd_ent_t;
static int ends,ssl_result;
static int sp_pd_backend_end(proxy_fd_ent_t *p) {(void)p;ends++;return 1;}
static int SSL_get_error(void *p,int n) {(void)p;(void)n;return ssl_result;}
static int classify(proxy_fd_ent_t *pfe,int rval) {
"""+plain+'if(pfe->ssl && !pfe->ktls_enabled && rval<=0) {\n'+tls+'}\nreturn 0;\n}\n'+r"""
static void check(int tls,int ktls,int rc,int error,int ssl_error,int want) {
 proxy_fd_ent_t p={.ssl=tls?(void *)1:NULL,.ktls_enabled=ktls};
 ends=0;ssl_result=ssl_error;errno=error;
 assert(classify(&p,rc)==(want?-1:0));assert(ends==want);
}
int main(void) {
 check(0,0,0,EAGAIN,0,1); /* stale errno cannot hide actual EOF */
 check(0,0,-1,EAGAIN,0,0);check(0,0,-1,EWOULDBLOCK,0,0);
 check(0,0,-1,EINTR,0,0);check(0,0,-1,ECONNRESET,0,1);
 check(0,0,1,ECONNRESET,0,0);
 check(1,1,0,EAGAIN,0,1);check(1,1,-1,EINTR,0,0);
 check(1,0,-1,0,SSL_ERROR_WANT_READ,0);
 check(1,0,-1,EIO,SSL_ERROR_WANT_WRITE,0);
 check(1,0,0,EAGAIN,SSL_ERROR_ZERO_RETURN,1);
 check(1,0,-1,EINTR,SSL_ERROR_SYSCALL,0);
 check(1,0,-1,ECONNRESET,SSL_ERROR_SYSCALL,1);
 check(1,0,-1,EIO,SSL_ERROR_SSL,1);
 puts("PASS actual read classification: plain/kTLS/TLS EOF, reset, EAGAIN, EINTR, WANT_READ/WRITE");
}
"""
with tempfile.TemporaryDirectory(prefix='pd-terminal-read-') as folder:
 p=Path(folder)/'classify.c';binary=Path(folder)/'classify';p.write_text(code)
 subprocess.run([os.environ.get('CC','cc'),'-Wall','-Wextra','-Werror','-fsanitize=address,undefined','-g',str(p),'-o',str(binary)],check=True)
 subprocess.run([str(binary)],check=True)
