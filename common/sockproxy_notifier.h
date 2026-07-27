/*
 * Copyright (c) 2024-2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_NOTIFIER_H__
#define __SOCKPROXY_NOTIFIER_H__

/*
 * sockproxy_notifier.h — extraction
 *
 * proxy_notify_add_fd, proxy_notify_delete_fd, and proxy_main are declared
 * in sockproxy.h (the public API).  This header exists as the canonical
 * per-module guard so that sockproxy.c (and any future consumer) can
 * #include it to document the dependency explicitly.
 *
 * Functions defined in sockproxy_notifier.c:
 *   int  proxy_notify_add_fd(int fd, int type, void *priv);
 *   int  proxy_notify_delete_fd(int fd, int evict);
 *   int  proxy_main(sockmap_cb_t cb, int ktls_enabled);
 *
 * (proxy_notifier is file-local static — not exported)
 */

#endif /* __SOCKPROXY_NOTIFIER_H__ */
