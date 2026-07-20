/*
 * Unit tests for vLLM Request-ID generation and injection (US-501)
 * Build: gcc -Wall -Wextra -o test_request_id test_request_id.c -I. -DTEST_REQUEST_ID
 * Run:   ./test_request_id
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

/* Minimal stubs for testing - xorshift64* PRNG */
static uint64_t test_rng_state = 0x123456789abcdef0ULL;

static uint64_t xorshift64star(uint64_t *state) {
  uint64_t x = *state;
  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;
  *state = x;
  return x * 0x2545F4914F6CDD1DULL;
}

static uint64_t lxb_gen_trace_id_part(void) {
  return xorshift64star(&test_rng_state);
}

/* Minimal proxy_fd_ent_t for testing */
typedef struct {
  char     vllm_request_id[256];
  uint8_t  has_vllm_request_id;
  uint8_t  request_id_injected;
} proxy_fd_ent_t;

/* ---- generate_vllm_request_id (copy for standalone testing) ---- */
static void
generate_vllm_request_id(proxy_fd_ent_t *pfe,
                         const char *prefill_ep,
                         const char *decode_ep)
{
  uint64_t hi, lo;

  hi = lxb_gen_trace_id_part();
  lo = lxb_gen_trace_id_part();

  /* Set UUID v4 version bits */
  hi = (hi & ~((uint64_t)0xF << 12)) | ((uint64_t)0x4 << 12);
  lo = (lo & ~((uint64_t)0x3 << 62)) | ((uint64_t)0x2 << 62);

  char uuid_buf[33];
  snprintf(uuid_buf, sizeof(uuid_buf), "%016llx%016llx",
           (unsigned long long)hi, (unsigned long long)lo);

  if (prefill_ep && decode_ep) {
    snprintf(pfe->vllm_request_id, sizeof(pfe->vllm_request_id),
             "___prefill_addr_%s___decode_addr_%s_%s",
             prefill_ep, decode_ep, uuid_buf);
  } else {
    strncpy(pfe->vllm_request_id, uuid_buf, sizeof(pfe->vllm_request_id) - 1);
    pfe->vllm_request_id[sizeof(pfe->vllm_request_id) - 1] = '\0';
  }

  pfe->has_vllm_request_id = 0;
  pfe->request_id_injected = 0;
}

/* ---- inject_request_id_header (copy for standalone testing) ---- */
static int
inject_request_id_header(void *msg, size_t *len, size_t bufsize,
                         const char *req_id)
{
  char inject_buf[512];
  size_t inject_len;
  uint8_t *headers_end;
  uint8_t *insert_point;
  size_t tail_len;
  uint8_t *existing;

  if (!req_id || req_id[0] == '\0')
    return -1;

  inject_len = (size_t)snprintf(inject_buf, sizeof(inject_buf),
                                "X-Request-Id: %s\r\n", req_id);
  if (inject_len >= sizeof(inject_buf))
    return -1;

  headers_end = memmem(msg, *len, "\r\n\r\n", 4);
  if (!headers_end)
    return -1;

  /* Strip existing X-Request-Id if present */
  existing = memmem(msg, (size_t)(headers_end - (uint8_t *)msg + 4),
                    "X-Request-Id:", 13);
  if (!existing) {
    existing = memmem(msg, (size_t)(headers_end - (uint8_t *)msg + 4),
                      "x-request-id:", 13);
  }
  if (existing) {
    uint8_t *line_end = memmem(existing,
                               *len - (size_t)(existing - (uint8_t *)msg),
                               "\r\n", 2);
    if (line_end) {
      line_end += 2;
      size_t remove_len = (size_t)(line_end - existing);
      memmove(existing, line_end,
              *len - (size_t)(line_end - (uint8_t *)msg));
      *len -= remove_len;
      headers_end = memmem(msg, *len, "\r\n\r\n", 4);
      if (!headers_end)
        return -1;
    }
  }

  if (*len + inject_len >= bufsize)
    return -1;

  insert_point = headers_end + 2;
  tail_len = *len - (size_t)(insert_point - (uint8_t *)msg);
  memmove(insert_point + inject_len, insert_point, tail_len);
  memcpy(insert_point, inject_buf, inject_len);
  *len += inject_len;
  return 0;
}

/* ============ TEST HARNESS ============ */

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
  tests_run++; \
  printf("  TEST %d: %s ... ", tests_run, name); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* ============ TEST CASES ============ */

static void test_uuid_format(void) {
  TEST("UUID v4 format (32 hex chars)");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, NULL, NULL);
  if (strlen(pfe.vllm_request_id) != 32) {
    char errbuf[128];
    snprintf(errbuf, sizeof(errbuf), "Expected 32 chars, got %zu: '%s'",
             strlen(pfe.vllm_request_id), pfe.vllm_request_id);
    FAIL(errbuf);
    return;
  }
  for (int i = 0; i < 32; i++) {
    char c = pfe.vllm_request_id[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
      FAIL("Non-hex character found");
      return;
    }
  }
  PASS();
}

static void test_uuid_v4_bits(void) {
  TEST("UUID v4 version and variant bits");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, NULL, NULL);

  /* Version nibble is char index 12 (bits 12-15 of hi = 4) */
  char version = pfe.vllm_request_id[3]; /* 4th hex digit of hi (0-indexed: bit positions 12-15) */
  /* Actually, snprintf produces "%016llx%016llx" so positions are:
   * hi occupies chars 0-15, lo occupies chars 16-31.
   * Bits 12-15 of hi correspond to hex digit at position:
   *   hi >> 12 & 0xF = digit at position (16 - 1 - 12/4) = position 12/4 from right
   *   In "%016llx": digit 0 is MSB. Bits 63-60 = digit 0.
   *   Bits 12-15 = digit (63-12)/4 = digit 12.75...
   *   Actually: digit_index = (60 - bit_position) / 4 ... no.
   *   Digit 0 = bits 63-60, digit 1 = bits 59-56, ...
   *   Digit k = bits (63 - 4k) to (60 - 4k)
   *   For bits 12-15: k = (63-15)/4 = 12, so digit 12 */
  version = pfe.vllm_request_id[12];
  if (version != '4') {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "Version nibble expected '4', got '%c'", version);
    FAIL(errbuf);
    return;
  }

  /* Variant bits: bits 62-63 of lo = 0b10 => hex digit 0 of lo (chars 16) should be 8,9,a,b */
  char variant = pfe.vllm_request_id[16];
  if (variant != '8' && variant != '9' && variant != 'a' && variant != 'b') {
    char errbuf[64];
    snprintf(errbuf, sizeof(errbuf), "Variant nibble expected [89ab], got '%c'", variant);
    FAIL(errbuf);
    return;
  }
  PASS();
}

static void test_uuid_uniqueness(void) {
  TEST("UUID uniqueness (100 IDs)");
  char ids[100][33];
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  for (int i = 0; i < 100; i++) {
    generate_vllm_request_id(&pfe, NULL, NULL);
    strncpy(ids[i], pfe.vllm_request_id, 32);
    ids[i][32] = '\0';
  }
  for (int i = 0; i < 100; i++) {
    for (int j = i + 1; j < 100; j++) {
      if (strcmp(ids[i], ids[j]) == 0) {
        FAIL("Duplicate ID found");
        return;
      }
    }
  }
  PASS();
}

static void test_flags_after_generate(void) {
  TEST("Flags cleared after auto-generation");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  pfe.has_vllm_request_id = 1;
  pfe.request_id_injected = 1;
  generate_vllm_request_id(&pfe, NULL, NULL);
  if (pfe.has_vllm_request_id != 0) { FAIL("has_vllm_request_id not cleared"); return; }
  if (pfe.request_id_injected != 0) { FAIL("request_id_injected not cleared"); return; }
  PASS();
}

static void test_pd_format(void) {
  TEST("P/D format with endpoint addresses");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, "10.0.1.1:8080", "10.0.1.2:8081");
  if (!strstr(pfe.vllm_request_id, "___prefill_addr_10.0.1.1:8080")) {
    FAIL("Missing prefill addr");
    return;
  }
  if (!strstr(pfe.vllm_request_id, "___decode_addr_10.0.1.2:8081")) {
    FAIL("Missing decode addr");
    return;
  }
  /* Should also contain UUID suffix */
  char *last_underscore = strrchr(pfe.vllm_request_id, '_');
  if (!last_underscore || strlen(last_underscore + 1) != 32) {
    FAIL("Missing or wrong-length UUID suffix");
    return;
  }
  PASS();
}

static void test_pd_format_zmq(void) {
  TEST("P/D format with ZMQ-style endpoints");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe,
                           "tcp://10.0.1.1:5556",
                           "tcp://10.0.1.2:5557");
  if (!strstr(pfe.vllm_request_id, "___prefill_addr_tcp://10.0.1.1:5556")) {
    FAIL("Missing ZMQ prefill addr");
    return;
  }
  if (!strstr(pfe.vllm_request_id, "___decode_addr_tcp://10.0.1.2:5557")) {
    FAIL("Missing ZMQ decode addr");
    return;
  }
  PASS();
}

static void test_inject_basic(void) {
  TEST("Header injection into valid HTTP request");
  char buf[4096];
  const char *req = "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "test-id-123");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  if (!strstr(buf, "X-Request-Id: test-id-123\r\n")) { FAIL("Header not found"); return; }
  if (!strstr(buf, "\r\n\r\n")) { FAIL("Header-body separator broken"); return; }
  /* Verify body preserved */
  if (!strstr(buf, "{\"model\":\"llama\"}")) { FAIL("Body corrupted"); return; }
  PASS();
}

static void test_inject_preserves_body(void) {
  TEST("Header injection preserves full body content");
  char buf[4096];
  const char *body = "{\"model\":\"llama-70b\",\"messages\":[{\"role\":\"user\",\"content\":\"Hello\"}]}";
  char req[2048];
  snprintf(req, sizeof(req),
           "POST /v1/chat/completions HTTP/1.1\r\n"
           "Host: api.example.com\r\n"
           "Content-Length: %zu\r\n"
           "\r\n%s", strlen(body), body);
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "uuid-abcdef");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  /* Verify body is intact after injection */
  char *body_start = strstr(buf, "\r\n\r\n");
  if (!body_start) { FAIL("No header-body separator"); return; }
  body_start += 4;
  if (strcmp(body_start, body) != 0) {
    FAIL("Body content changed after injection");
    return;
  }
  PASS();
}

static void test_inject_null_id(void) {
  TEST("Reject NULL request ID");
  char buf[256];
  const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  size_t len = strlen(req);
  memcpy(buf, req, len);
  int rc = inject_request_id_header(buf, &len, sizeof(buf), NULL);
  if (rc != -1) { FAIL("Should reject NULL req_id"); return; }
  PASS();
}

static void test_inject_empty_id(void) {
  TEST("Reject empty request ID");
  char buf[256];
  const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  size_t len = strlen(req);
  memcpy(buf, req, len);
  int rc = inject_request_id_header(buf, &len, sizeof(buf), "");
  if (rc != -1) { FAIL("Should reject empty req_id"); return; }
  PASS();
}

static void test_inject_no_headers(void) {
  TEST("Reject request without header-body separator");
  char buf[256];
  const char *req = "GET / HTTP/1.1\r\nHost: x";
  size_t len = strlen(req);
  memcpy(buf, req, len);
  int rc = inject_request_id_header(buf, &len, sizeof(buf), "test-id");
  if (rc != -1) { FAIL("Should reject incomplete headers"); return; }
  PASS();
}

static void test_inject_overflow(void) {
  TEST("Header injection overflow protection");
  char buf[64];
  const char *req = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf),
    "very-long-request-id-that-will-overflow-the-tiny-buffer-easily");
  if (rc != -1) { FAIL("Should have returned -1 for overflow"); return; }
  PASS();
}

static void test_inject_strip_existing(void) {
  TEST("Strip existing X-Request-Id before injection");
  char buf[4096];
  const char *req = "POST /v1/chat HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "X-Request-Id: old-id-999\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "new-id-123");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  if (strstr(buf, "old-id-999")) { FAIL("Old ID still present"); return; }
  if (!strstr(buf, "X-Request-Id: new-id-123\r\n")) { FAIL("New ID not found"); return; }
  /* Verify only one X-Request-Id header */
  char *first = strstr(buf, "X-Request-Id:");
  if (first) {
    char *second = strstr(first + 13, "X-Request-Id:");
    if (second) { FAIL("Multiple X-Request-Id headers"); return; }
  }
  PASS();
}

static void test_inject_strip_lowercase(void) {
  TEST("Strip existing lowercase x-request-id");
  char buf[4096];
  const char *req = "POST /v1/chat HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "x-request-id: old-lower-id\r\n"
                    "\r\n"
                    "body";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), "new-id-456");
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }
  if (strstr(buf, "old-lower-id")) { FAIL("Old lowercase ID still present"); return; }
  if (!strstr(buf, "X-Request-Id: new-id-456\r\n")) { FAIL("New ID not found"); return; }
  PASS();
}

static void test_inject_long_uuid(void) {
  TEST("Inject full-length P/D format request ID");
  char buf[4096];
  const char *req = "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  const char *pd_id = "___prefill_addr_tcp://10.0.1.1:5556"
                       "___decode_addr_tcp://10.0.1.2:5557"
                       "_0123456789abcdef0123456789abcdef";
  int rc = inject_request_id_header(buf, &len, sizeof(buf), pd_id);
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error for long P/D ID"); return; }
  if (!strstr(buf, pd_id)) { FAIL("P/D ID not found in output"); return; }
  PASS();
}

static void test_end_to_end(void) {
  TEST("End-to-end: generate then inject");
  proxy_fd_ent_t pfe;
  memset(&pfe, 0, sizeof(pfe));
  generate_vllm_request_id(&pfe, NULL, NULL);

  char buf[4096];
  const char *req = "POST /v1/chat/completions HTTP/1.1\r\n"
                    "Host: api.example.com\r\n"
                    "Content-Type: application/json\r\n"
                    "\r\n"
                    "{\"model\":\"llama\"}";
  size_t len = strlen(req);
  memcpy(buf, req, len);

  int rc = inject_request_id_header(buf, &len, sizeof(buf), pfe.vllm_request_id);
  buf[len] = '\0';
  if (rc != 0) { FAIL("inject returned error"); return; }

  /* Verify the generated UUID appears in the output */
  char expected_header[300];
  snprintf(expected_header, sizeof(expected_header),
           "X-Request-Id: %s\r\n", pfe.vllm_request_id);
  if (!strstr(buf, expected_header)) { FAIL("Generated UUID not found in headers"); return; }
  PASS();
}

/* ============ MAIN ============ */

int main(void) {
  printf("=== US-501: Request-ID Unit Tests ===\n\n");

  /* UUID generation tests */
  test_uuid_format();
  test_uuid_v4_bits();
  test_uuid_uniqueness();
  test_flags_after_generate();
  test_pd_format();
  test_pd_format_zmq();

  /* Header injection tests */
  test_inject_basic();
  test_inject_preserves_body();
  test_inject_null_id();
  test_inject_empty_id();
  test_inject_no_headers();
  test_inject_overflow();
  test_inject_strip_existing();
  test_inject_strip_lowercase();
  test_inject_long_uuid();

  /* End-to-end test */
  test_end_to_end();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
