/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 */
#ifndef __SOCKPROXY_KTLS_H__
#define __SOCKPROXY_KTLS_H__

#include <stdint.h>
#include <openssl/ssl.h>
#include <linux/tls.h>

// Supported cipher suites for kTLS
typedef enum {
  KTLS_CIPHER_AES_GCM_128,
  KTLS_CIPHER_AES_GCM_256,
  KTLS_CIPHER_CHACHA20_POLY1305,
  KTLS_CIPHER_UNSUPPORTED
} ktls_cipher_suite_t;

// kTLS configuration and statistics
typedef struct ktls_config {
  uint8_t enabled;        // 0=disabled, 1=enabled
  uint8_t fallback_ok;    // Allow fallback to userspace SSL
  uint32_t failures;      // Counter for kTLS init failures
  uint32_t fallbacks;     // Counter for fallback occurrences
  uint32_t successful;    // Counter for successful kTLS offloads
} ktls_config_t;

// Global kTLS configuration
extern ktls_config_t g_ktls_cfg;

/**
 * Check if kernel supports kTLS
 * @return 0 on success, -1 on failure
 */
int ktls_check_kernel_support(void);

/**
 * Get TLS version from SSL connection
 * @param ssl OpenSSL connection handle
 * @return TLS version constant or -1 on error
 */
int ktls_get_tls_version(SSL *ssl);

/**
 * Get cipher suite from SSL connection
 * @param ssl OpenSSL connection handle
 * @return ktls_cipher_suite_t or KTLS_CIPHER_UNSUPPORTED
 */
ktls_cipher_suite_t ktls_get_cipher_suite(SSL *ssl);

/**
 * Extract TLS 1.2 session keys and populate crypto_info structures
 * @param ssl OpenSSL connection handle
 * @param tx Transmit crypto info (output)
 * @param rx Receive crypto info (output)
 * @return 0 on success, -1 on failure
 */
int ktls_extract_keys_tls12(SSL *ssl,
                             struct tls12_crypto_info_aes_gcm_128 *tx,
                             struct tls12_crypto_info_aes_gcm_128 *rx);

/**
 * Initialize kernel TLS on a socket
 * @param fd Socket file descriptor
 * @param tx_crypto Transmit crypto info
 * @param rx_crypto Receive crypto info
 * @return 0 on success, -errno on failure
 */
int ktls_init_socket(int fd,
                     struct tls12_crypto_info_aes_gcm_128 *tx_crypto,
                     struct tls12_crypto_info_aes_gcm_128 *rx_crypto);

/**
 * Extract TLS keys and initialize kTLS on socket
 * Main entry point for kTLS offload
 * @param ssl OpenSSL connection handle
 * @param fd Socket file descriptor
 * @param is_client 1 if client side, 0 if server side
 * @return 0 on success, -1 on failure
 */
int ktls_offload_enable(SSL *ssl, int fd, int is_client);

/**
 * Try kTLS with fallback logic
 * @param ssl OpenSSL connection handle
 * @param fd Socket file descriptor
 * @param is_client 1 if client side, 0 if server side
 * @return 0 on success, -1 if fallback to userspace
 */
int ktls_try_offload(SSL *ssl, int fd, int is_client);

/**
 * Check if TCP_ULP is already attached (prevents re-initialization)
 * @param fd Socket file descriptor
 * @return 1 if TCP_ULP 'tls' is attached
 *         0 if TCP_ULP is not attached
 */
int ktls_ulp_is_attached(int fd);

/**
 * Check if kTLS is fully active (crypto configured and working)
 * @param fd Socket file descriptor
 * @return 1 if kTLS is fully active (TX crypto configured)
 *         0 if kTLS is not active or only partially initialized
 */
int ktls_is_active(int fd);

/**
 * Get kTLS statistics
 * @param config Output buffer for statistics
 */
void ktls_get_stats(ktls_config_t *config);

/**
 * Reset kTLS statistics
 */
void ktls_reset_stats(void);

#endif /* __SOCKPROXY_KTLS_H__ */
