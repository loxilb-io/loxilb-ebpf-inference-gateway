/* SPDX-License-Identifier: BSD-3-Clause
 *
 * sockproxy_pfe_clear.h - preparing a pooled connection shell for reuse.
 */
#ifndef __SOCKPROXY_PFE_CLEAR_H__
#define __SOCKPROXY_PFE_CLEAR_H__

#include <stddef.h>
#include <string.h>

#include "sockproxy.h"

/* Three quarters of proxy_fd_ent is one field: the transfer-params buffer the
 * disaggregated prefill/decode path extracts into. It is written on that path
 * alone, so a plain sizeof-wide clear charges every connection -- on both of
 * its legs -- for a buffer most of them never touch, and that clear is the
 * single largest item in the per-connection CPU cost of accept-and-tear-down
 * churn.
 *
 * So the buffer is skipped, and the shell is cleared as the two runs around
 * it. What makes that safe is that no reader of the buffer looks at it on its
 * own: every one of them is handed the (buffer, length) pair, and the length
 * lies outside the skipped span and so is still cleared here. A shell whose
 * previous user left bytes in the buffer therefore reports a length of zero,
 * and those bytes stay unreachable until the extract path writes both together.
 * The assertions hold exactly that contract; a shell that has never been used
 * is allocated zeroed, so the fresh and the recycled case agree.
 */
#define PFE_SKIP_OFF  offsetof(proxy_fd_ent_t, pd_kv_params)
#define PFE_SKIP_END  (PFE_SKIP_OFF + sizeof(((proxy_fd_ent_t *)0)->pd_kv_params))

_Static_assert(offsetof(proxy_fd_ent_t, pd_kv_params_len) < PFE_SKIP_OFF ||
               offsetof(proxy_fd_ent_t, pd_kv_params_len) >= PFE_SKIP_END,
               "pd_kv_params_len must lie outside the skipped span: it is what "
               "bounds every read of pd_kv_params, so it has to be cleared");
_Static_assert(PFE_SKIP_END <= sizeof(proxy_fd_ent_t),
               "the skipped span must lie within the shell");
/* The pool restores a linked shell's list fields after the clear and relies
 * on the clear to zero them otherwise; a field inside the skipped span would
 * survive the clear on the unlinked path and read as a stale link. */
_Static_assert(offsetof(proxy_fd_ent_t, next) < PFE_SKIP_OFF ||
               offsetof(proxy_fd_ent_t, next) >= PFE_SKIP_END,
               "next must lie outside the skipped span");
_Static_assert(offsetof(proxy_fd_ent_t, prev) < PFE_SKIP_OFF ||
               offsetof(proxy_fd_ent_t, prev) >= PFE_SKIP_END,
               "prev must lie outside the skipped span");
_Static_assert(offsetof(proxy_fd_ent_t, fdlist_rule) < PFE_SKIP_OFF ||
               offsetof(proxy_fd_ent_t, fdlist_rule) >= PFE_SKIP_END,
               "fdlist_rule must lie outside the skipped span");

static inline void
pfe_clear(proxy_fd_ent_t *pfe)
{
  memset(pfe, 0, PFE_SKIP_OFF);
  memset((char *)pfe + PFE_SKIP_END, 0, sizeof(*pfe) - PFE_SKIP_END);
}

#endif /* __SOCKPROXY_PFE_CLEAR_H__ */
