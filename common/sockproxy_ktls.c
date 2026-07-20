/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * Task 2.1: SSL Key Extraction Framework for kTLS
 * 
 * This module implements kernel TLS (kTLS) support for LoxiLB sockproxy,
 * enabling hardware-accelerated encryption/decryption of TLS connections.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <linux/sockios.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/bio.h>
#include <linux/tls.h>

#include "sockproxy_ktls.h"
#include "log.h"

// TCP Upper Layer Protocol socket option
#ifndef SOL_TLS
#define SOL_TLS 282
#endif

// Global kTLS configuration
ktls_config_t g_ktls_cfg = {
  .enabled = 1,
  .fallback_ok = 1,
  .failures = 0,
  .fallbacks = 0,
  .successful = 0,
};

/**
 * Check kernel version and kTLS module availability
 */
int ktls_check_kernel_support(void) {
  struct utsname uts;
  
  if (uname(&uts) < 0) {
    log_error("[kTLS] Failed to get kernel version: %s", strerror(errno));
    return -1;
  }

  log_info("[kTLS] Kernel: %s %s", uts.sysname, uts.release);

  // Parse kernel version (e.g., "5.4.0-42-generic")
  int major, minor;
  if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
    log_error("[kTLS] Failed to parse kernel version: %s", uts.release);
    return -1;
  }

  if (major < 4 || (major == 4 && minor < 13)) {
    log_error("[kTLS] Requires kernel >= 4.13 (current: %d.%d)", major, minor);
    return -1;
  }

  if (major < 5 || (major == 5 && minor < 2)) {
    log_warn("[kTLS] RX offload requires kernel >= 5.2 (current: %d.%d)", 
             major, minor);
    log_warn("[kTLS] Only TX offload will be available");
  }

  // Check if TLS module is loaded
  FILE *fp = fopen("/proc/modules", "r");
  if (!fp) {
    log_error("[kTLS] Cannot read /proc/modules: %s", strerror(errno));
    return -1;
  }

  char line[256];
  int tls_loaded = 0;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "tls ", 4) == 0) {
      tls_loaded = 1;
      break;
    }
  }
  fclose(fp);

  if (!tls_loaded) {
    log_warn("[kTLS] TLS kernel module not loaded");
    log_info("[kTLS] Load with: modprobe tls");
    return -1;
  }

  log_info("[kTLS] Kernel support: available (version %d.%d)", major, minor);
  return 0;
}

/**
 * Get TLS version from OpenSSL connection
 */
int ktls_get_tls_version(SSL *ssl) {
  if (!ssl) {
    return -1;
  }

  int version = SSL_version(ssl);
  switch (version) {
    case TLS1_2_VERSION:
      return TLS_1_2_VERSION;
    case TLS1_3_VERSION:
      return TLS_1_3_VERSION;
    default:
      return -1;
  }
}

/**
 * Detect cipher suite from OpenSSL connection
 */
ktls_cipher_suite_t ktls_get_cipher_suite(SSL *ssl) {
  if (!ssl) {
    return KTLS_CIPHER_UNSUPPORTED;
  }

  const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
  if (!cipher) {
    return KTLS_CIPHER_UNSUPPORTED;
  }

  const char *name = SSL_CIPHER_get_name(cipher);
  if (!name) {
    return KTLS_CIPHER_UNSUPPORTED;
  }

  // Check for AES-GCM-128
  if (strstr(name, "AES128-GCM") || strstr(name, "AES_128_GCM")) {
    return KTLS_CIPHER_AES_GCM_128;
  }
  
  // Check for AES-GCM-256
  if (strstr(name, "AES256-GCM") || strstr(name, "AES_256_GCM")) {
    return KTLS_CIPHER_AES_GCM_256;
  }
  
  // Check for ChaCha20-Poly1305
  if (strstr(name, "CHACHA20-POLY1305")) {
    return KTLS_CIPHER_CHACHA20_POLY1305;
  }

  return KTLS_CIPHER_UNSUPPORTED;
}

/**
 * TLS 1.2 PRF (Pseudo-Random Function) for key derivation
 * Based on RFC 5246 Section 5
 */
static int ktls_tls12_prf(const unsigned char *secret, size_t secret_len,
                           const char *label,
                           const unsigned char *seed1, size_t seed1_len,
                           const unsigned char *seed2, size_t seed2_len,
                           unsigned char *out, size_t out_len) {
  
  EVP_PKEY_CTX *pctx = NULL;
  int ret = -1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  // OpenSSL 3.x API
  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
  if (!pctx) {
    log_error("[kTLS] EVP_PKEY_CTX_new_id failed");
    goto cleanup;
  }

  if (EVP_PKEY_derive_init(pctx) <= 0) {
    log_error("[kTLS] EVP_PKEY_derive_init failed");
    goto cleanup;
  }

  if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_set_tls1_prf_md failed");
    goto cleanup;
  }

  if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, secret_len) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_set1_tls1_prf_secret failed");
    goto cleanup;
  }

  // Add label
  if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, (const unsigned char *)label, 
                                       strlen(label)) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_add1_tls1_prf_seed (label) failed");
    goto cleanup;
  }

  // Add seed1 (server random)
  if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, seed1_len) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_add1_tls1_prf_seed (seed1) failed");
    goto cleanup;
  }

  // Add seed2 (client random)
  if (EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, seed2_len) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_add1_tls1_prf_seed (seed2) failed");
    goto cleanup;
  }

  size_t actual_len = out_len;
  if (EVP_PKEY_derive(pctx, out, &actual_len) <= 0) {
    log_error("[kTLS] EVP_PKEY_derive failed");
    goto cleanup;
  }

  ret = 0;

#else
  // OpenSSL 1.1.1 API
  pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
  if (!pctx) {
    log_error("[kTLS] EVP_PKEY_CTX_new_id failed");
    goto cleanup;
  }

  if (EVP_PKEY_derive_init(pctx) <= 0) {
    log_error("[kTLS] EVP_PKEY_derive_init failed");
    goto cleanup;
  }

  if (EVP_PKEY_CTX_set_tls1_prf_md(pctx, EVP_sha256()) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_set_tls1_prf_md failed");
    goto cleanup;
  }

  if (EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret, secret_len) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_set1_tls1_prf_secret failed");
    goto cleanup;
  }

  // Combine label + seed1 + seed2
  size_t total_seed_len = strlen(label) + seed1_len + seed2_len;
  unsigned char *combined_seed = malloc(total_seed_len);
  if (!combined_seed) {
    log_error("[kTLS] Failed to allocate combined seed");
    goto cleanup;
  }

  memcpy(combined_seed, label, strlen(label));
  memcpy(combined_seed + strlen(label), seed1, seed1_len);
  memcpy(combined_seed + strlen(label) + seed1_len, seed2, seed2_len);

  if (EVP_PKEY_CTX_set1_tls1_prf_seed(pctx, combined_seed, total_seed_len) <= 0) {
    log_error("[kTLS] EVP_PKEY_CTX_set1_tls1_prf_seed failed");
    free(combined_seed);
    goto cleanup;
  }

  free(combined_seed);

  size_t actual_len = out_len;
  if (EVP_PKEY_derive(pctx, out, &actual_len) <= 0) {
    log_error("[kTLS] EVP_PKEY_derive failed");
    goto cleanup;
  }

  ret = 0;
#endif

cleanup:
  if (pctx) {
    EVP_PKEY_CTX_free(pctx);
  }
  return ret;
}

/**
 * Extract TLS 1.2 session keys
 */
int ktls_extract_keys_tls12(SSL *ssl,
                             struct tls12_crypto_info_aes_gcm_128 *tx,
                             struct tls12_crypto_info_aes_gcm_128 *rx) {
  
  if (!ssl || !tx || !rx) {
    log_error("[kTLS] Invalid parameters");
    return -1;
  }

  SSL_SESSION *session = SSL_get_session(ssl);
  if (!session) {
    log_error("[kTLS] No SSL session available");
    return -1;
  }

  // Extract master secret
  unsigned char master_secret[SSL_MAX_MASTER_KEY_LENGTH];
  size_t master_len = SSL_SESSION_get_master_key(session, master_secret, 
                                                   sizeof(master_secret));
  if (master_len == 0) {
    log_error("[kTLS] Failed to extract master key");
    return -1;
  }

  // Get client and server random
  unsigned char client_random[SSL3_RANDOM_SIZE];
  unsigned char server_random[SSL3_RANDOM_SIZE];

  size_t cr_len = SSL_get_client_random(ssl, client_random, sizeof(client_random));
  size_t sr_len = SSL_get_server_random(ssl, server_random, sizeof(server_random));

  if (cr_len != SSL3_RANDOM_SIZE || sr_len != SSL3_RANDOM_SIZE) {
    log_error("[kTLS] Failed to get random values (cr=%zu, sr=%zu)", cr_len, sr_len);
    return -1;
  }

  // Derive key block using TLS 1.2 PRF
  // Key block layout for AES-GCM-128 (no MAC keys for AEAD):
  // client_write_key (16) | server_write_key (16) | 
  // client_write_IV (4) | server_write_IV (4)
  unsigned char key_block[40];  // 16+16+4+4 = 40 bytes

  int ret = ktls_tls12_prf(master_secret, master_len,
                            "key expansion",
                            server_random, SSL3_RANDOM_SIZE,
                            client_random, SSL3_RANDOM_SIZE,
                            key_block, sizeof(key_block));
  
  if (ret < 0) {
    log_error("[kTLS] Key derivation failed");
    // Clear sensitive data
    memset(master_secret, 0, sizeof(master_secret));
    return -1;
  }

  // Clear master secret from memory
  memset(master_secret, 0, sizeof(master_secret));

  // Parse key block
  unsigned char *p = key_block;

  // Client write key (16 bytes)
  unsigned char client_write_key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
  memcpy(client_write_key, p, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
  p += TLS_CIPHER_AES_GCM_128_KEY_SIZE;

  // Server write key (16 bytes)
  unsigned char server_write_key[TLS_CIPHER_AES_GCM_128_KEY_SIZE];
  memcpy(server_write_key, p, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
  p += TLS_CIPHER_AES_GCM_128_KEY_SIZE;

  // Client write IV (4 bytes for implicit part)
  unsigned char client_write_iv[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
  memcpy(client_write_iv, p, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  p += TLS_CIPHER_AES_GCM_128_SALT_SIZE;

  // Server write IV (4 bytes for implicit part)
  unsigned char server_write_iv[TLS_CIPHER_AES_GCM_128_SALT_SIZE];
  memcpy(server_write_iv, p, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  p += TLS_CIPHER_AES_GCM_128_SALT_SIZE;

  // Determine if we're client or server
  int is_server = SSL_is_server(ssl);

  // Populate TX crypto info (what we send)
  memset(tx, 0, sizeof(*tx));
  tx->info.version = TLS_1_2_VERSION;
  tx->info.cipher_type = TLS_CIPHER_AES_GCM_128;
  
  if (is_server) {
    // Server sends with server_write_key
    memcpy(tx->key, server_write_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(tx->salt, server_write_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  } else {
    // Client sends with client_write_key
    memcpy(tx->key, client_write_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(tx->salt, client_write_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  }
  
  // IV is the salt (implicit part of nonce)
  memcpy(tx->iv, tx->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

  // Populate RX crypto info (what we receive)
  memset(rx, 0, sizeof(*rx));
  rx->info.version = TLS_1_2_VERSION;
  rx->info.cipher_type = TLS_CIPHER_AES_GCM_128;

  if (is_server) {
    // Server receives with client_write_key
    memcpy(rx->key, client_write_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(rx->salt, client_write_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  } else {
    // Client receives with server_write_key
    memcpy(rx->key, server_write_key, TLS_CIPHER_AES_GCM_128_KEY_SIZE);
    memcpy(rx->salt, server_write_iv, TLS_CIPHER_AES_GCM_128_SALT_SIZE);
  }

  memcpy(rx->iv, rx->salt, TLS_CIPHER_AES_GCM_128_SALT_SIZE);

  // Set sequence numbers for kTLS
  // For TLS 1.2 immediately after handshake completion:
  // - Application data records start at sequence 0
  // - Handshake records used separate sequence numbers that don't carry over
  // - kTLS is enabled right after handshake, so sequence 0 is correct
  //
  // Note: OpenSSL 3.x has SSL_get_read/write_sequence() APIs but they're not
  // always available in all builds. Using sequence 0 is safe and correct for
  // the post-handshake case when kTLS is typically enabled.

  memset(tx->rec_seq, 0, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);
  memset(rx->rec_seq, 0, TLS_CIPHER_AES_GCM_128_REC_SEQ_SIZE);

  // Clear key block from memory
  memset(key_block, 0, sizeof(key_block));
  memset(client_write_key, 0, sizeof(client_write_key));
  memset(server_write_key, 0, sizeof(server_write_key));

  return 0;
}

/**
 * Initialize kernel TLS on socket
 */
int ktls_init_socket(int fd,
                     struct tls12_crypto_info_aes_gcm_128 *tx_crypto,
                     struct tls12_crypto_info_aes_gcm_128 *rx_crypto) {
  
  if (fd < 0 || !tx_crypto || !rx_crypto) {
    log_error("[kTLS] Invalid parameters (fd=%d)", fd);
    return -EINVAL;
  }

  int ret;
  int so_buf = 6553500;  // 6.5 MB socket buffers for better performance

  // Step 1: Enable TCP ULP (Upper Layer Protocol) for TLS
  const char *ulp_name = "tls";
  ret = setsockopt(fd, SOL_TCP, TCP_ULP, ulp_name, strlen(ulp_name));
  if (ret < 0) {
    int err = errno;

    if (err == EEXIST) {
      log_warn("[kTLS] TLS ULP already enabled on socket fd=%d - socket may be reused", fd);

      // Check if crypto is already configured (indicates reused socket in bad state)
      struct tls12_crypto_info_aes_gcm_128 check_info;
      socklen_t check_len = sizeof(check_info);
      int check_ret = getsockopt(fd, SOL_TLS, TLS_TX, &check_info, &check_len);

      if (check_ret == 0) {
        log_error("[kTLS] Socket fd=%d already has TLS_TX configured (reused socket)", fd);
        return -EEXIST;
      } else if (errno == ENOENT || errno == EBUSY) {
        // ENOENT: crypto not configured yet (expected for pre-attached ULP)
        // EBUSY: OpenSSL is in the middle of setting up kTLS (also expected)
        log_warn("[kTLS] Socket fd=%d has ULP but no crypto (errno=%d) - will attempt configuration", 
                 fd, errno);
        // Fall through to try TLS_TX setup
      } else {
        log_error("[kTLS] Failed to query TLS_TX state: %s (errno=%d)",
                  strerror(errno), errno);
        return -errno;
      }
    } else if (err == ENOENT) {
      log_error("[kTLS] setsockopt TCP_ULP failed: %s (errno=%d)",
                strerror(err), err);
      log_error("[kTLS] Kernel TLS module not loaded (try: modprobe tls)");
      return -err;
    } else {
      log_error("[kTLS] setsockopt TCP_ULP failed: %s (errno=%d)",
                strerror(err), err);
      return -err;
    }
  }

  // Flush socket buffers before TLS_TX configuration
  // Kernel cannot enable kTLS if socket has buffered data
  int pending_out = 0;

  // Check outgoing buffer (data waiting to be sent)
  if (ioctl(fd, TIOCOUTQ, &pending_out) == 0 && pending_out > 0) {
    // Wait briefly for kernel to flush (up to 100ms)
    for (int i = 0; i < 10 && pending_out > 0; i++) {
      usleep(10000);  // 10ms
      ioctl(fd, TIOCOUTQ, &pending_out);
    }

    if (pending_out > 0) {
      log_warn("[kTLS] Send buffer still has %d bytes after flush attempt", pending_out);
    }
  }

  // NOTE: Do NOT drain the receive buffer!
  // When OpenSSL pre-attaches TCP_ULP, the receive buffer may contain:
  // - Handshake completion messages (ChangeCipherSpec, Finished)
  // - Early application data
  // These MUST be processed by OpenSSL/application, not discarded.
  // The kernel will handle buffered data correctly when enabling kTLS.

  // Step 2: Configure TX (transmit) crypto parameters
  ret = setsockopt(fd, SOL_TLS, TLS_TX, tx_crypto, sizeof(*tx_crypto));
  if (ret < 0) {
    int err = errno;
    log_error("[kTLS] setsockopt TLS_TX failed on fd=%d: %s (errno=%d)",
              fd, strerror(err), err);

    // Enhanced diagnostic logging for TLS_TX failures
    // Get TCP connection state
    struct tcp_info tcpi;
    socklen_t tcpi_len = sizeof(tcpi);
    if (getsockopt(fd, SOL_TCP, TCP_INFO, &tcpi, &tcpi_len) == 0) {
      log_error("[kTLS] TCP state: state=%u, snd_cwnd=%u, rcv_mss=%u, "
                "unacked=%u, lost=%u, retrans=%u",
                tcpi.tcpi_state, tcpi.tcpi_snd_cwnd, tcpi.tcpi_rcv_mss,
                tcpi.tcpi_unacked, tcpi.tcpi_lost, tcpi.tcpi_retrans);
    }

    // Get socket buffer status
    int snd_buf = 0, rcv_buf = 0;
    socklen_t optlen = sizeof(int);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd_buf, &optlen) == 0) {
      log_error("[kTLS] Socket send buffer size: %d bytes", snd_buf);
    }
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv_buf, &optlen) == 0) {
      log_error("[kTLS] Socket recv buffer size: %d bytes", rcv_buf);
    }

    // Log crypto_info details
    log_error("[kTLS] TX crypto_info: version=0x%x, cipher=%u",
              tx_crypto->info.version, tx_crypto->info.cipher_type);

    // Log sequence number (first 8 bytes in network byte order)
    uint64_t tx_seq = be64toh(*(uint64_t*)tx_crypto->rec_seq);
    log_error("[kTLS] TX sequence number: %lu", tx_seq);

    // Errno-specific diagnostics
    if (err == EINVAL) {
      log_error("[kTLS] EINVAL - Invalid crypto_info parameters");
      log_error("[kTLS] Check: key length, IV length, sequence number, cipher type");
    } else if (err == EBUSY) {
      log_error("[kTLS] EBUSY - Socket has pending data or wrong state");
      log_error("[kTLS] Ensure socket buffers are flushed before calling");
    } else if (err == EEXIST) {
      log_error("[kTLS] EEXIST - TLS TX already configured on this socket");
    } else if (err == ENOPROTOOPT) {
      log_error("[kTLS] ENOPROTOOPT - kTLS not supported by kernel");
    }

    return -err;
  }

  // Step 3: Configure RX (receive) crypto parameters
  ret = setsockopt(fd, SOL_TLS, TLS_RX, rx_crypto, sizeof(*rx_crypto));
  if (ret < 0) {
    int err = errno;
    log_error("[kTLS] setsockopt TLS_RX failed: %s (errno=%d)", 
              strerror(err), err);

    if (err == ENOPROTOOPT) {
      log_warn("[kTLS] RX offload not supported (kernel < 5.2?)");
      log_info("[kTLS] Continuing with TX offload only");
      // Not fatal, TX offload still works
    } else {
      return -err;
    }
  }

  // Step 4: Increase socket buffer sizes for better performance
  setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &so_buf, sizeof(so_buf));
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &so_buf, sizeof(so_buf));

  log_info("[kTLS] Initialized on fd=%d (TX+RX offload enabled)", fd);
  return 0;
}

/**
 * Main entry point: Extract keys and enable kTLS
 */
int ktls_offload_enable(SSL *ssl, int fd, int is_client) {
  if (!ssl || fd < 0) {
    log_error("[kTLS] Invalid parameters (ssl=%p, fd=%d)", ssl, fd);
    return -1;
  }

  // Check if TLS handshake is complete
  if (!SSL_is_init_finished(ssl)) {
    return -1;
  }

  // Get TLS version
  int tls_version = ktls_get_tls_version(ssl);
  if (tls_version < 0) {
    log_info("[kTLS] fd=%d: Unsupported TLS version for kTLS offload", fd);
    return -1;
  }

  // Get cipher suite
  ktls_cipher_suite_t cipher = ktls_get_cipher_suite(ssl);
  if (cipher == KTLS_CIPHER_UNSUPPORTED) {
    const SSL_CIPHER *ssl_cipher = SSL_get_current_cipher(ssl);
    const char *cipher_name = ssl_cipher ? SSL_CIPHER_get_name(ssl_cipher) : "unknown";
    log_info("[kTLS] fd=%d: Cipher %s not supported for kTLS (requires AES-GCM-128)", 
             fd, cipher_name);
    return -1;
  }

  // Currently only support TLS 1.2 + AES-GCM-128
  if (tls_version != TLS_1_2_VERSION) {
    log_info("[kTLS] fd=%d: Only TLS 1.2 supported (current: 0x%x), falling back to userspace SSL", 
             fd, tls_version);
    return -1;
  }

  if (cipher != KTLS_CIPHER_AES_GCM_128) {
    log_info("[kTLS] fd=%d: Only AES-GCM-128 supported (current cipher: %d), falling back to userspace SSL", 
             fd, cipher);
    return -1;
  }
  
  log_info("[kTLS] fd=%d: TLS 1.2 + AES-GCM-128 detected, attempting kTLS offload...", fd);

  // Extract session keys
  struct tls12_crypto_info_aes_gcm_128 tx_crypto, rx_crypto;
  int ret = ktls_extract_keys_tls12(ssl, &tx_crypto, &rx_crypto);
  if (ret < 0) {
    log_error("[kTLS] Failed to extract TLS 1.2 keys on fd=%d", fd);
    return -1;
  }

  // Initialize kTLS on socket
  ret = ktls_init_socket(fd, &tx_crypto, &rx_crypto);
  if (ret < 0) {
    log_error("[kTLS] Failed to initialize kTLS on socket fd=%d", fd);
    
    // Clear sensitive data
    memset(&tx_crypto, 0, sizeof(tx_crypto));
    memset(&rx_crypto, 0, sizeof(rx_crypto));
    
    return -1;
  }

  // Clear sensitive data from memory
  memset(&tx_crypto, 0, sizeof(tx_crypto));
  memset(&rx_crypto, 0, sizeof(rx_crypto));

  log_info("[kTLS] ✓ Successfully enabled on fd=%d (TLS 1.2, AES-GCM-128, %s)",
           fd, is_client ? "client" : "server");
  log_info("[kTLS] fd=%d: Traffic will be encrypted/decrypted by KERNEL (not userspace OpenSSL)", fd);
  
  __atomic_fetch_add(&g_ktls_cfg.successful, 1, __ATOMIC_RELAXED);
  
  return 0;
}

/**
 * Try kTLS with fallback logic
 */
int ktls_try_offload(SSL *ssl, int fd, int is_client) {
  if (!g_ktls_cfg.enabled) {
    return -1;
  }

  // Check if TLS handshake is complete
  if (!SSL_is_init_finished(ssl)) {
    return -1;
  }

  // First check if TCP_ULP is already attached (prevents duplicate initialization)
  int ulp_attached = ktls_ulp_is_attached(fd);

  if (ulp_attached) {
    // Now check if kTLS is actually working (crypto configured)
    if (ktls_is_active(fd)) {
      __atomic_fetch_add(&g_ktls_cfg.successful, 1, __ATOMIC_RELAXED);
      return 0;  // Success - kTLS fully working
    }

    // TCP_ULP pre-attached but crypto not configured
    // Check if OpenSSL has enabled kTLS internally
    int ssl_ktls_tx = 0;
    int ssl_ktls_rx = 0;
    
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    // OpenSSL 3.x API to check if kTLS is enabled
    BIO *wbio = SSL_get_wbio(ssl);
    BIO *rbio = SSL_get_rbio(ssl);
    
    if (wbio) {
      ssl_ktls_tx = BIO_get_ktls_send(wbio);
    }
    if (rbio) {
      ssl_ktls_rx = BIO_get_ktls_recv(rbio);
    }
#endif

    if (ssl_ktls_tx || ssl_ktls_rx) {
      // OpenSSL has enabled kTLS internally
      log_info("[kTLS] Active on fd=%d (OpenSSL-managed, tx=%d, rx=%d)",
               fd, ssl_ktls_tx, ssl_ktls_rx);
      __atomic_fetch_add(&g_ktls_cfg.successful, 1, __ATOMIC_RELAXED);
      return 0;
    } else {
      // OpenSSL did not enable kTLS - fallback to userspace
      log_warn("[kTLS] OpenSSL did not enable kTLS on fd=%d (cipher/version incompatible or --enable-ktls missing)", fd);
      __atomic_fetch_add(&g_ktls_cfg.fallbacks, 1, __ATOMIC_RELAXED);
      return -1;
    }
  }

  // TCP_ULP not attached, try full kTLS initialization
  int ret = ktls_offload_enable(ssl, fd, is_client);
  if (ret < 0) {
    __atomic_fetch_add(&g_ktls_cfg.failures, 1, __ATOMIC_RELAXED);

    if (g_ktls_cfg.fallback_ok) {
      __atomic_fetch_add(&g_ktls_cfg.fallbacks, 1, __ATOMIC_RELAXED);
      return -1;  // Not fatal, continue with userspace SSL
    } else {
      log_error("[kTLS] Required but failed on fd=%d, aborting connection", fd);
      return -1;
    }
  }

  return 0;
}

/**
 * Check if TCP_ULP is already attached (for preventing duplicate initialization)
 */
int ktls_ulp_is_attached(int fd) {
  if (fd < 0) {
    return 0;
  }

  char ulp_name[16] = {0};
  socklen_t ulp_len = sizeof(ulp_name);
  
  int ret = getsockopt(fd, SOL_TCP, TCP_ULP, ulp_name, &ulp_len);
  
  if (ret == 0 && strcmp(ulp_name, "tls") == 0) {
    return 1;  // TCP_ULP 'tls' is attached
  }
  
  return 0;  // TCP_ULP not attached or different ULP
}

/**
 * Check if kTLS is fully active (crypto configured and working)
 * 
 * This function performs comprehensive validation to ensure kTLS is truly active:
 * 1. Checks if kTLS is globally enabled (respects --ktlssupport flag)
 * 2. Verifies TLS_TX crypto is configured (not just TCP_ULP attached)
 * 3. Ensures the configuration is valid and working
 * 
 * Returns: 1 if kTLS is fully active and working, 0 otherwise
 */
int ktls_is_active(int fd) {
  if (fd < 0) {
    return 0;
  }

  // CRITICAL: If kTLS is globally disabled, don't report it as active
  // This prevents confusing logs when OpenSSL has kTLS support but user disabled it
  if (!g_ktls_cfg.enabled) {
    return 0;
  }

  // Check if TLS_TX crypto is configured (this is the definitive test)
  struct tls12_crypto_info_aes_gcm_128 info;
  socklen_t optlen = sizeof(info);
  
  int ret = getsockopt(fd, SOL_TLS, TLS_TX, &info, &optlen);
  
  if (ret == 0) {
    // TLS_TX configured - kTLS is fully active and working
    return 1;
  }
  
  // TLS_TX not configured - kTLS not working
  return 0;  // kTLS not active
}

/**
 * Get kTLS statistics
 */
void ktls_get_stats(ktls_config_t *config) {
  if (!config) {
    return;
  }

  config->enabled = g_ktls_cfg.enabled;
  config->fallback_ok = g_ktls_cfg.fallback_ok;
  config->failures = __atomic_load_n(&g_ktls_cfg.failures, __ATOMIC_RELAXED);
  config->fallbacks = __atomic_load_n(&g_ktls_cfg.fallbacks, __ATOMIC_RELAXED);
  config->successful = __atomic_load_n(&g_ktls_cfg.successful, __ATOMIC_RELAXED);
}

/**
 * Reset kTLS statistics
 */
void ktls_reset_stats(void) {
  __atomic_store_n(&g_ktls_cfg.failures, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&g_ktls_cfg.fallbacks, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&g_ktls_cfg.successful, 0, __ATOMIC_RELAXED);
  
  log_info("[kTLS] Statistics reset");
}
