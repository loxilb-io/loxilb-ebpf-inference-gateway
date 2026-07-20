/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * loxilb_kv_tcp.c -- TCP transport implementation for KV cache pipeline.
 *
 * Provides reliable chunk-level I/O over TCP with exact-read semantics
 * required for binary protocol framing.  This file is unconditional
 * (COMMON_OBJS) because TCP is POSIX and not DOCA-dependent.
 *
 * Key guarantees:
 *   - recv_exact() loops until exactly N bytes received or error/timeout
 *   - TCP_NODELAY set on all connections (no Nagle delay)
 *   - CRC32 validated on every received chunk via llb_kv_recv_chunk()
 */

#include "loxilb_kv.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* Internal connection state                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    int fd;
} kv_tcp_conn_t;

/* ------------------------------------------------------------------ */
/* Helper: monotonic clock in milliseconds                             */
/* ------------------------------------------------------------------ */

static int64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* ------------------------------------------------------------------ */
/* tcp_connect -- resolve host, connect with TCP_NODELAY               */
/* ------------------------------------------------------------------ */

static int tcp_connect(const char *host, uint16_t port, void **conn_out)
{
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[8];
    int fd = -1;
    int rc;

    if (!host || !conn_out)
        return LLB_KV_ERR_INTERNAL;

    snprintf(port_str, sizeof(port_str), "%u", port);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;     /* IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res)
        return LLB_KV_ERR_CONN;

    /* Try each resolved address */
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0)
            continue;

        /* Set TCP_NODELAY before connect -- locked decision */
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0)
            break;  /* success */

        close(fd);
        fd = -1;
    }

    freeaddrinfo(res);

    if (fd < 0)
        return LLB_KV_ERR_CONN;

    /* Allocate connection handle */
    kv_tcp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) {
        close(fd);
        return LLB_KV_ERR_NOMEM;
    }
    conn->fd = fd;
    *conn_out = conn;

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* tcp_recv_exact -- receive exactly len bytes or return error          */
/*                                                                     */
/* CRITICAL: This function MUST NOT return with partial data.          */
/* It either reads all len bytes or returns an error code.             */
/* ------------------------------------------------------------------ */

static int tcp_recv_exact(void *conn, void *buf, size_t len, int timeout_ms)
{
    kv_tcp_conn_t *tc = (kv_tcp_conn_t *)conn;
    if (!tc || !buf || len == 0)
        return LLB_KV_ERR_INTERNAL;

    unsigned char *dst = (unsigned char *)buf;
    size_t total_read = 0;
    int64_t deadline = (timeout_ms > 0) ? now_ms() + timeout_ms : 0;

    while (total_read < len) {
        int remaining_ms = -1;  /* infinite if no timeout */

        if (timeout_ms > 0) {
            int64_t now = now_ms();
            remaining_ms = (int)(deadline - now);
            if (remaining_ms <= 0)
                return LLB_KV_ERR_TIMEOUT;
        }

        struct pollfd pfd = {
            .fd     = tc->fd,
            .events = POLLIN,
        };

        int pr = poll(&pfd, 1, remaining_ms);
        if (pr == 0)
            return LLB_KV_ERR_TIMEOUT;
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return LLB_KV_ERR_CONN;
        }
        /* Check POLLIN first: read available data even if POLLHUP is also set.
         * On macOS/ARM, poll() may return POLLIN|POLLHUP simultaneously when
         * the peer closes but data is still buffered in the socket. */
        if (pfd.revents & POLLIN) {
            ssize_t n = recv(tc->fd, dst + total_read, len - total_read, 0);
            if (n <= 0)
                return LLB_KV_ERR_CONN;  /* connection closed or error */
            total_read += (size_t)n;
            continue;
        }
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            return LLB_KV_ERR_CONN;
    }

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* tcp_send_all -- send exactly len bytes or return error               */
/* ------------------------------------------------------------------ */

static int tcp_send_all(void *conn, const void *buf, size_t len)
{
    kv_tcp_conn_t *tc = (kv_tcp_conn_t *)conn;
    if (!tc || !buf)
        return LLB_KV_ERR_INTERNAL;
    if (len == 0)
        return LLB_KV_OK;

    const unsigned char *src = (const unsigned char *)buf;
    size_t total_sent = 0;

    while (total_sent < len) {
        ssize_t n = send(tc->fd, src + total_sent, len - total_sent,
                         MSG_NOSIGNAL);
        if (n <= 0)
            return LLB_KV_ERR_CONN;

        total_sent += (size_t)n;
    }

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* tcp_close -- close fd and free connection struct                     */
/* ------------------------------------------------------------------ */

static void tcp_close(void *conn)
{
    kv_tcp_conn_t *tc = (kv_tcp_conn_t *)conn;
    if (!tc)
        return;

    if (tc->fd >= 0)
        close(tc->fd);

    free(tc);
}

/* ------------------------------------------------------------------ */
/* Default TCP transport ops -- exported for pipeline consumption      */
/* ------------------------------------------------------------------ */

llb_kv_transport_ops llb_kv_tcp_ops = {
    .connect    = tcp_connect,
    .recv_exact = tcp_recv_exact,
    .send_all   = tcp_send_all,
    .close      = tcp_close,
};

/* ------------------------------------------------------------------ */
/* llb_kv_recv_chunk -- convenience: receive header + payload + CRC    */
/* ------------------------------------------------------------------ */

int llb_kv_recv_chunk(llb_kv_transport_ops *ops, void *conn,
                      llb_kv_chunk_hdr_t *hdr,
                      void *payload_buf, size_t payload_buf_len,
                      int timeout_ms)
{
    int rc;
    unsigned char hdr_buf[sizeof(llb_kv_chunk_hdr_t)];

    if (!ops || !conn || !hdr || !payload_buf)
        return LLB_KV_ERR_INTERNAL;

    /* Step 1: Receive raw header bytes */
    rc = ops->recv_exact(conn, hdr_buf, sizeof(hdr_buf), timeout_ms);
    if (rc != LLB_KV_OK)
        return rc;

    /* Step 2: Deserialize header (validates magic + version) */
    rc = llb_kv_chunk_hdr_deserialize(hdr_buf, sizeof(hdr_buf), hdr);
    if (rc != LLB_KV_OK)
        return rc;

    /* Step 3: Bounds check payload against caller's buffer */
    if (hdr->compressed_len > payload_buf_len)
        return LLB_KV_ERR_NOMEM;

    /* Step 4: Receive payload */
    rc = ops->recv_exact(conn, payload_buf, hdr->compressed_len, timeout_ms);
    if (rc != LLB_KV_OK)
        return rc;

    /* Step 5: Validate CRC32 */
    rc = llb_kv_chunk_validate_crc(hdr, payload_buf, hdr->compressed_len);
    if (rc != LLB_KV_OK)
        return rc;

    return LLB_KV_OK;
}
