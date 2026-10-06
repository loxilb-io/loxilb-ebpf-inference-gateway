/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sockproxy_betls_state.h - the backend TLS policy a listener has installed.
 *
 * A listener's backend context is built once and then serves every backend
 * connection. A rule update re-sends the whole rule, usually with the same
 * policy, so the listener remembers what its context was built from and a
 * new context is built only when that differs. The record includes the
 * identity of the certificate files, not only the IDs that name them: a
 * certificate that was replaced under the same ID is a different policy.
 *
 * Standalone (no OpenSSL, no sockproxy.h).
 */
#ifndef __SOCKPROXY_BETLS_STATE_H__
#define __SOCKPROXY_BETLS_STATE_H__

#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

/* A file as it was when the context read it. All zero: no such file. */
struct betls_fp {
  uint64_t ino;
  uint64_t size;
  uint64_t mtime_ns;
};

#define BETLS_FP_CA          0
#define BETLS_FP_CLIENT_CERT 1
#define BETLS_FP_CLIENT_KEY  2

struct betls_installed {
  uint8_t verify;               /* the endpoint's certificate is verified */
  uint8_t client_cert_loaded;   /* a client certificate is presented */
  char ca_id[64];
  char client_id[64];
  char server_name[256];
  struct betls_fp fp[3];
};

static inline void
betls_fp_stat(const char *path, struct betls_fp *fp)
{
  struct stat st;

  memset(fp, 0, sizeof(*fp));
  if (!path || path[0] == '\0' || stat(path, &st) != 0) {
    return;
  }
  fp->ino = (uint64_t)st.st_ino;
  fp->size = (uint64_t)st.st_size;
  fp->mtime_ns = (uint64_t)st.st_mtim.tv_sec * 1000000000ull + (uint64_t)st.st_mtim.tv_nsec;
}

/* 1 when a context built from b would behave as the one built from a. */
static inline int
betls_installed_same(const struct betls_installed *a, const struct betls_installed *b)
{
  return a->verify == b->verify &&
         strncmp(a->ca_id, b->ca_id, sizeof(a->ca_id)) == 0 &&
         strncmp(a->client_id, b->client_id, sizeof(a->client_id)) == 0 &&
         strncmp(a->server_name, b->server_name, sizeof(a->server_name)) == 0 &&
         memcmp(a->fp, b->fp, sizeof(a->fp)) == 0;
}

#endif /* __SOCKPROXY_BETLS_STATE_H__ */
