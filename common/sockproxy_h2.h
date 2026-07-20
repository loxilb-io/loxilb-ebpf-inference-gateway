/*
 * Copyright (c) 2025 LoxiLB Authors
 *
 * SPDX short identifier: BSD-3-Clause
 *
 * HTTP/2 Support for LoxiLB sockproxy
 * 
 * This module implements HTTP/2 protocol support using nghttp2 library,
 * enabling multiplexed streams, header compression, and better performance
 * for modern AI/LLM workloads.
 */

#ifndef __SOCKPROXY_H2_H__
#define __SOCKPROXY_H2_H__

#include <nghttp2/nghttp2.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include "uthash.h"

// Forward declarations
struct proxy_fd_ent;
typedef struct proxy_fd_ent proxy_fd_ent_t;

struct proxy_h2_session;
typedef struct proxy_h2_session proxy_h2_session_t;

struct backend_h2_session;
typedef struct backend_h2_session backend_h2_session_t;

struct stream_mapping;
typedef struct stream_mapping stream_mapping_t;

// ============================================================================
// HTTP/2 Stream Management
// ============================================================================

/**
 * HTTP/2 stream state
 * Maps to nghttp2 stream lifecycle
 */
typedef enum {
  H2_STREAM_IDLE,           // Stream created but no frames sent/received
  H2_STREAM_OPEN,           // Headers received, stream active
  H2_STREAM_HALF_CLOSED,    // One side closed
  H2_STREAM_CLOSED          // Stream fully closed
} h2_stream_state_t;

/**
 * HTTP/2 stream context
 * Represents a single HTTP request/response within a connection
 */
typedef struct proxy_h2_stream {
  int32_t stream_id;                 // nghttp2 stream ID (odd for client-initiated)
  h2_stream_state_t state;           // Current stream state
  
  // Request headers (from client)
  char method[16];                   // GET, POST, etc.
  char path[512];                    // Request path
  char authority[256];               // :authority pseudo-header (Host)
  char content_type[128];            // Content-Type header

  // Generic request header storage (for gRPC and protocol transparency)
  nghttp2_nv *request_headers;       // All request headers (malloc'd)
  size_t request_headers_count;      // Number of headers
  size_t request_headers_capacity;   // Allocated capacity

  // Request body accumulation
  uint8_t *data_buf;                 // Accumulated DATA frames
  size_t data_len;                   // Current data length
  size_t data_capacity;              // Allocated buffer size
  int headers_complete;              // 1 = all headers received
  int data_complete;                 // 1 = all data received (END_STREAM flag)
  
  // Response tracking
  int response_sent;                 // 1 = response headers/data sent
  
  // LLM-specific fields (for CHWBL/GPU routing)
  void *prefix_key;                  // llm_prefix_key_t* - extracted from request
  char conversation_id[128];         // X-Conversation-ID header
  int has_conv_id;                   // Flag: conversation ID present
  
  // Backend association
  int backend_ep_idx;                // Which backend endpoint handles this stream (-1 = not assigned)
  
  // Timing
  time_t created_ts;                 // Stream creation time
  time_t last_activity_ts;           // Last frame received/sent
  
  // Hash table linkage (stream_id → stream mapping)
  UT_hash_handle hh;
} proxy_h2_stream_t;

/**
 * Stream mapping entry for HTTP/2 transit mode
 * Maps client stream IDs to backend stream IDs for response routing
 */
typedef struct stream_mapping {
  int32_t client_stream_id;          // Stream ID on client-side connection
  int32_t backend_stream_id;         // Stream ID on backend connection
  int ep_idx;                        // Backend endpoint index
  time_t created_ts;                 // Mapping creation time

  // Response header collection (for backend → client forwarding)
  nghttp2_nv *response_headers;      // Collected response headers
  size_t response_headers_count;     // Number of headers
  size_t response_headers_capacity;  // Allocated capacity

  // Request data source (for cleanup when stream closes)
  void *data_source;                 // h2_data_source_t* (freed on stream close)

  UT_hash_handle hh;                 // Hash by client_stream_id
} stream_mapping_t;

/**
 * Backend send buffer context
 * Handles partial SSL_write() scenarios (WANT_WRITE/WANT_READ)
 * Mirrors HTTP/1.1 cache mechanism for retry support
 */
typedef struct backend_send_buffer {
  uint8_t *data;                     // Buffered send data (malloc'd)
  size_t total_len;                  // Original data length
  size_t sent_len;                   // Bytes already sent (for partial writes)
  int pending;                       // 1 = data waiting to send, 0 = buffer empty
  struct backend_send_buffer *next;  // Linked list for multiple buffers
} backend_send_buffer_t;

/**
 * Backend HTTP/2 session context
 * Manages HTTP/2 connection to backend server
 */
typedef struct backend_h2_session {
  int backend_fd;                    // Backend socket FD
  nghttp2_session *session;          // nghttp2 backend session (client mode)
  proxy_h2_session_t *client_session; // Link to client-side session

  // Stream mapping: client_stream_id → backend_stream_id
  stream_mapping_t *stream_map;      // Hash table for stream ID mapping

  // Connection state
  int connected;                     // 1 = connected and ready
  int goaway_sent;                   // 1 = GOAWAY sent to backend
  int goaway_received;               // 1 = GOAWAY received from backend

  // Backend endpoint info
  int ep_idx;                        // Which backend endpoint (index into tepval->eps)
  char backend_addr[64];             // Backend IP address (for logging)
  int backend_port;                  // Backend port

  // SSL context
  void *ssl;                         // SSL connection to backend (if HTTPS)

  // ============================================================================
  // BUG FIX: Backend send buffer for WANT_WRITE/WANT_READ retry
  // Mirrors HTTP/1.1 cache mechanism (sockproxy.c:286-354)
  // ============================================================================
  backend_send_buffer_t *send_buffer_head;  // Linked list of pending sends
  backend_send_buffer_t *send_buffer_tail;  // Tail for efficient append
  size_t send_buffer_total_size;            // Total bytes in send buffer
  int send_buffer_draining;                 // 1 = actively draining buffer

  // Statistics
  uint64_t frames_sent;              // Frames sent to backend
  uint64_t frames_recv;              // Frames received from backend

  // Thread safety
  pthread_mutex_t send_lock;         // Protect nghttp2_session_send()

  // Linkage (for managing multiple backend sessions)
  UT_hash_handle hh;                 // Hash by ep_idx
} backend_h2_session_t;

/**
 * HTTP/2 session context
 * Represents the entire HTTP/2 connection (can contain multiple streams)
 */
typedef struct proxy_h2_session {
  nghttp2_session *session;          // nghttp2 session handle
  void *pfe;                         // Back pointer to proxy_fd_ent_t (for statistics)

  int h2_enabled;                    // 1 = HTTP/2 active, 0 = HTTP/1.1 fallback
  int is_client;                     // 1 = client mode (to backend), 0 = server mode (from client)
  
  // Stream management
  proxy_h2_stream_t *streams;        // Hash table: stream_id → proxy_h2_stream_t
  int active_stream_count;           // Number of active streams
  int max_concurrent_streams;        // Limit (from SETTINGS frame)

  // Phase 75 (T-75-17): the stream id currently under L7 dispatch. Set at the H2
  // dispatch seam (proxy_h2_forward_to_backend) right before l7_route_dispatch so
  // proxy_h2_send_l7_synthetic() knows which stream to answer a REJECT/REDIRECT on
  // (l7_send_reject/redirect carry only `pfe`, not the stream). 0 = none active.
  int32_t l7_active_stream_id;

  // Backend session management (HTTP/2 transit mode)
  backend_h2_session_t *backend_sessions; // Hash table: ep_idx → backend_h2_session_t
  
  // Flow control
  int32_t send_window_size;          // Available send window
  int32_t recv_window_size;          // Available receive window
  
  // Statistics
  uint64_t frames_sent;              // Total frames sent
  uint64_t frames_recv;              // Total frames received
  uint64_t data_sent;                // Total DATA bytes sent
  uint64_t data_recv;                // Total DATA bytes received
  
  // Error tracking
  int last_error;                    // Last nghttp2 error code
  int goaway_sent;                   // 1 = GOAWAY frame sent
  int goaway_recv;                   // 1 = GOAWAY frame received
  
  // ============================================================================
  // HTTP/2 BACKPRESSURE CONTROL (same design as HTTP/1.1 cache mechanism)
  // Prevents memory exhaustion from slow clients or large backend responses
  // ============================================================================
  size_t total_response_buffer_size;  // Track all pending data_copy buffers (backend→client)
  int backpressure_active;            // 1 if backpressure applied (reading from backend paused)
  
  time_t created_ts;                 // Session creation time
} proxy_h2_session_t;

// ============================================================================
// Function Prototypes
// ============================================================================

/**
 * Initialize HTTP/2 session after ALPN negotiation
 * 
 * @param pfe Proxy file descriptor entry
 * @param is_client 1=client mode (to backend), 0=server mode (from client)
 * @return 0 on success, -1 on error
 */
int proxy_setup_h2_session(proxy_fd_ent_t *pfe, int is_client);

/**
 * Detect HTTP/2 from ALPN and initialize session
 * 
 * @param pfe Proxy file descriptor entry (must have SSL connection)
 * @return 0 on success (HTTP/2 detected and initialized), -1 if HTTP/1.1 or error
 */
int proxy_check_and_setup_h2(proxy_fd_ent_t *pfe);

/**
 * Handle incoming HTTP/2 data from client
 * Called from proxy_notifier() when data available on client socket
 * 
 * @param pfe Proxy file descriptor entry
 * @return 0 on success, -1 on error
 */
int proxy_h2_handle_client_data(proxy_fd_ent_t *pfe);

/**
 * Handle incoming HTTP/2 data from backend
 * Called from proxy_notifier() when data available on backend socket
 * 
 * @param pfe Proxy file descriptor entry
 * @return 0 on success, -1 on error
 */
int proxy_h2_handle_backend_data(proxy_fd_ent_t *pfe);

/**
 * Forward HTTP/2 stream to backend
 * Integrates with existing endpoint selection logic (CHWBL, GPU-aware, etc.)
 * 
 * @param pfe Proxy file descriptor entry
 * @param stream Stream to forward
 * @return 0 on success, -1 on error
 */
int proxy_h2_forward_to_backend(proxy_fd_ent_t *pfe, proxy_h2_stream_t *stream);

/**
 * Cleanup HTTP/2 session and all streams
 * Called when connection closes
 *
 * @param pfe Proxy file descriptor entry
 */
void proxy_h2_cleanup_session(proxy_fd_ent_t *pfe);

/**
 * proxy_h2_inject_resp_headers — Phase 76 (FR-08/FR-10): the ONE net-new C
 * primitive of this phase. A **NON-TERMINAL** HTTP/2 response-header injector.
 *
 * Unlike proxy_h2_send_l7_synthetic() (which is TERMINAL: it submits a
 * HEADERS-only frame with a NULL data provider => END_STREAM, answering a
 * REJECT/REDIRECT *instead of* proxying — no body can follow), this function
 * augments the response HEADERS frame the proxy is ALREADY relaying for a
 * body-bearing backend 200. It appends extra nghttp2_nv entries into the
 * per-stream collected header set (mapping->response_headers[]) that the
 * backend->client relay (proxy_h2_backend_on_frame_recv_callback) submits via
 * nghttp2_submit_headers(). It MUST NOT touch any frame flag: the relay derives
 * END_STREAM from the *backend's* HEADERS frame, so the backend DATA frames keep
 * flowing and the body is preserved (T-76-03-01/02). nghttp2 frames every byte
 * (no raw writes on the h2 socket — defect 097c8dba).
 *
 * The names/values are deep-copied onto the heap (malloc + memcpy), exactly like
 * proxy_h2_backend_on_header_callback, so the existing per-mapping cleanup paths
 * (sockproxy_h2.c free loops over response_headers[]) free them uniformly. The
 * per-stream request DATA source (mapping->data_source) is NEVER touched, so the
 * body data provider stays attached.
 *
 * Gating: the call site is guarded by node->has_l7_policy (D-01a) so the AI /
 * has_l7_policy==0 transit path is byte-for-byte unchanged.
 *
 * @param mapping  The per-stream response-header collection point (the relay hook).
 * @param extra    Array of headers to inject (name/value/lengths; flags ignored —
 *                 always forced to NGHTTP2_NV_FLAG_NONE on the injected copy).
 * @param nextra   Number of entries in @extra.
 * @return Number of headers successfully injected (>= 0), or -1 on a hard error
 *         (NULL mapping / allocation failure). A return < nextra signals a
 *         partial inject (capacity grow failed mid-way); the relay still emits a
 *         valid, non-terminal frame with whatever was appended.
 */
int proxy_h2_inject_resp_headers(stream_mapping_t *mapping,
                                 const nghttp2_nv *extra, size_t nextra);

/**
 * Create or get backend HTTP/2 session for endpoint
 * 
 * @param client_session Client-side HTTP/2 session
 * @param pfe Proxy file descriptor entry
 * @param ep_idx Backend endpoint index
 * @param backend_fd Backend socket FD (already connected)
 * @param ssl Backend SSL connection (NULL if plain HTTP/2)
 * @return backend_h2_session_t* on success, NULL on error
 */
backend_h2_session_t *proxy_h2_get_backend_session(proxy_h2_session_t *client_session,
                                                     proxy_fd_ent_t *pfe,
                                                     int ep_idx,
                                                     int backend_fd,
                                                     void *ssl);

/**
 * Destroy backend HTTP/2 session
 * 
 * @param backend_session Backend session to destroy
 */
void proxy_h2_backend_session_destroy(backend_h2_session_t *backend_session);

/**
 * Send pending frames to client
 * 
 * @param client_session Client session
 * @return 0 on success, -1 on error
 */
int proxy_h2_client_send(proxy_h2_session_t *client_session);

/**
 * Extract HTTP/2 header value from stream
 * Helper function for routing logic
 * 
 * @param stream Stream to search
 * @param header_name Header name (lowercase, no colon for pseudo-headers)
 * @param value_buf Output buffer for header value
 * @param value_size Size of output buffer
 * @return 0 on success (value written), -1 if header not found
 */
int proxy_h2_get_header(proxy_h2_stream_t *stream, const char *header_name,
                        char *value_buf, size_t value_size);

// ============================================================================
// Internal Callbacks (used by nghttp2)
// ============================================================================

/**
 * Called when a complete frame is received
 */
int proxy_h2_on_frame_recv_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data);

/**
 * Called when a header name-value pair is received
 */
int proxy_h2_on_header_callback(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 const uint8_t *name, size_t namelen,
                                 const uint8_t *value, size_t valuelen,
                                 uint8_t flags,
                                 void *user_data);

/**
 * Called when DATA chunk is received
 */
int proxy_h2_on_data_chunk_recv_callback(nghttp2_session *session,
                                          uint8_t flags,
                                          int32_t stream_id,
                                          const uint8_t *data,
                                          size_t len,
                                          void *user_data);

/**
 * Called when stream is closed
 */
int proxy_h2_on_stream_close_callback(nghttp2_session *session,
                                       int32_t stream_id,
                                       uint32_t error_code,
                                       void *user_data);

/**
 * Called when nghttp2 wants to send data
 */
ssize_t proxy_h2_send_callback(nghttp2_session *session,
                                const uint8_t *data, size_t length,
                                int flags,
                                void *user_data);

/**
 * Called when nghttp2 wants to receive data
 */
ssize_t proxy_h2_recv_callback(nghttp2_session *session,
                                uint8_t *buf, size_t length,
                                int flags,
                                void *user_data);

// ============================================================================
// Backend Send Buffer Management (Bug Fix for WANT_WRITE/WANT_READ retry)
// ============================================================================

/**
 * Add data to backend send buffer (for WANT_WRITE/WANT_READ retry)
 * Mirrors HTTP/1.1 proxy_add_xmitcache() pattern
 *
 * @param backend_session Backend session
 * @param data Data to buffer (will be copied)
 * @param len Length of data
 * @return 0 on success, -1 on error
 */
int proxy_h2_backend_add_send_buffer(backend_h2_session_t *backend_session,
                                      const uint8_t *data, size_t len);

/**
 * Drain backend send buffer (retry pending sends)
 * Mirrors HTTP/1.1 proxy_xmit_cache() pattern
 * Called on EPOLLOUT events
 *
 * @param backend_session Backend session
 * @return 0 on success (buffer drained or partial send), -1 on fatal error
 */
int proxy_h2_backend_drain_send_buffer(backend_h2_session_t *backend_session);

/**
 * Destroy all send buffers for backend session
 * Called during session cleanup
 *
 * @param backend_session Backend session
 */
void proxy_h2_backend_destroy_send_buffer(backend_h2_session_t *backend_session);

/**
 * Handle backend EPOLLOUT event (retry pending sends)
 * Called from event loop when backend fd is writable
 *
 * @param pfe Backend proxy file descriptor entry
 * @return 0 on success, -1 on error
 */
int proxy_h2_handle_backend_writable(proxy_fd_ent_t *pfe);

#endif /* __SOCKPROXY_H2_H__ */
