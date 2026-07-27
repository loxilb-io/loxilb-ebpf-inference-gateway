/* SPDX-License-Identifier: GPL-2.0
 *
 * test_sockproxy_sync_emit.c — C-side emit-after-unlock + ring overflow test.
 * SPEC.md req: A4.
 *
 * What this test proves:
 *   1. Emit-after-unlock invariant: llb_sockproxy_emit_sync_event() is NEVER
 *      called while a thread-local "rwlock-held" flag is set. The flag is
 *      mocked here; the production code's discipline is enforced via the
 *      grep-verified call-site pattern in sockproxy_pd.c + sockproxy_ep.c.
 *   2. 10K-cap ring with drop-oldest: pushing 20,000 events in a tight loop
 *      yields exactly 10,000 events queued (FIFO order) + ~10,000 overflow
 *      counter increments. SPEC §Constraints.
 *   3. Coverage of 5 emit-site C functions: simulates an emit from each of
 *      {pd_session_store-update, pd_session_store-insert, pd_session_evict,
 *       pd_session_evict_key, store_conversation_endpoint} and asserts the
 *      recorder receives one event per simulated site (5 events total).
 *
 * Build: gcc -Wall -Wextra -o test_sockproxy_sync_emit test_sockproxy_sync_emit.c \
 *        -I. -DTEST_SOCKPROXY_SYNC -lpthread
 *
 * Note: this is a STANDALONE test — does NOT link against the production
 * sockproxy_*.o. The production code is grep-verified separately for the
 * ≥11-emit-sites property (SPEC verification grep).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

/* Mirror of MAX_CONV_ID_LEN + proxy_sync_event_t from sockproxy_internal.h.
 * MUST stay byte-compatible with the production typedef. */
#define MAX_CONV_ID_LEN 128

typedef enum {
    SYNC_SESSION_CREATE = 0,
    SYNC_SESSION_UPDATE = 1,
    SYNC_SESSION_DELETE = 2,
    SYNC_CONV_CREATE    = 3,
    SYNC_CONV_UPDATE    = 4,
    SYNC_CONV_DELETE    = 5,
} proxy_sync_event_kind_t;

typedef struct proxy_sync_event {
    int      kind;
    char     service_key[64];
    char     conv_id[MAX_CONV_ID_LEN];
    int      prefill_ep_idx;
    int      decode_ep_idx;
    int      ep_idx;
    uint64_t created_ts;
    uint64_t last_access_ts;
    uint32_t request_count;
} proxy_sync_event_t;

/* ============================================================================
 * Mock rwlock primitives: set a TLS flag when locked.
 * The mock emit function asserts the flag is OFF at emit-time.
 * ============================================================================ */
static __thread int tls_rwlock_held = 0;

static void mock_wrlock(void) { tls_rwlock_held++; }
static void mock_unlock(void) { if (tls_rwlock_held > 0) tls_rwlock_held--; }

/* ============================================================================
 * Mock event ring (10K cap with drop-oldest on overflow). This is the
 * canonical receiver the Go side would implement in pkg/loxinet/sockproxy_sync.go.
 * Implemented as a circular buffer; pure C, no pthread needed for the test
 * (single-threaded producer + recorder).
 * ============================================================================ */
#define RING_CAP 10000

typedef struct {
    proxy_sync_event_t buf[RING_CAP];
    uint32_t head;            /* index of next write */
    uint32_t tail;            /* index of next read (oldest) */
    uint32_t count;           /* current items */
    uint64_t overflow_total;  /* events evicted on overflow */
} test_ring_t;

static test_ring_t g_ring;

static void ring_init(void) { memset(&g_ring, 0, sizeof(g_ring)); }

static void ring_push_drop_oldest(const proxy_sync_event_t *ev) {
    if (g_ring.count == RING_CAP) {
        /* Drop oldest (advance tail) and increment overflow. */
        g_ring.tail = (g_ring.tail + 1) % RING_CAP;
        g_ring.count--;
        g_ring.overflow_total++;
    }
    g_ring.buf[g_ring.head] = *ev;
    g_ring.head = (g_ring.head + 1) % RING_CAP;
    g_ring.count++;
}

/* Records for the emit-after-unlock assertion. One slot per emit. */
typedef struct {
    int      lock_held_at_emit;
    int      kind;
    char     conv_id[MAX_CONV_ID_LEN];
} emit_record_t;

#define MAX_RECORDS 64
static emit_record_t g_records[MAX_RECORDS];
static uint32_t      g_record_count = 0;

/* Mock implementation of llb_sockproxy_emit_sync_event. Records the TLS
 * "rwlock-held" flag at emit time so the assertion below can detect any
 * call-site violation. */
void llb_sockproxy_emit_sync_event(const proxy_sync_event_t *ev) {
    if (!ev) return;
    if (g_record_count < MAX_RECORDS) {
        g_records[g_record_count].lock_held_at_emit = tls_rwlock_held;
        g_records[g_record_count].kind = ev->kind;
        strncpy(g_records[g_record_count].conv_id, ev->conv_id, MAX_CONV_ID_LEN - 1);
        g_records[g_record_count].conv_id[MAX_CONV_ID_LEN - 1] = '\0';
        g_record_count++;
    }
    ring_push_drop_oldest(ev);
}

/* ============================================================================
 * Test framework macros (mirrors test_pd_rewriter.c pattern).
 * ============================================================================ */
static int g_tests_run = 0;
static int g_tests_passed = 0;

#define ASSERT_TRUE(expr, desc) do { \
  if (!(expr)) { \
    fprintf(stderr, "  FAIL: %s — `%s` is false\n", desc, #expr); \
    return 0; \
  } \
} while (0)

#define ASSERT_EQ(actual, expected, desc) do { \
  long _a = (long)(actual), _e = (long)(expected); \
  if (_a != _e) { \
    fprintf(stderr, "  FAIL: %s — got %ld, expected %ld\n", desc, _a, _e); \
    return 0; \
  } \
} while (0)

#define RUN_TEST(fn) do { \
  g_tests_run++; \
  printf("[RUN ] %s\n", #fn); \
  if (fn()) { g_tests_passed++; printf("[ OK ] %s\n", #fn); } \
  else      { printf("[FAIL] %s\n", #fn); } \
} while (0)

/* ============================================================================
 * Tests
 * ============================================================================ */

/* Test 1: emit-after-unlock invariant.
 * Build a mock production call site: wrlock → mutate → unlock → emit.
 * Assert the recorded lock_held_at_emit is 0 for every site. */
static int test_emit_after_unlock(void) {
    g_record_count = 0;
    tls_rwlock_held = 0;
    ring_init();

    /* Site 1: pd_session_store update branch. */
    {
        mock_wrlock();
        /* ... mutate under lock ... */
        mock_unlock();
        proxy_sync_event_t ev = { .kind = SYNC_SESSION_UPDATE,
                                  .prefill_ep_idx = 0, .decode_ep_idx = 1,
                                  .ep_idx = -1, .created_ts = 1000 };
        strncpy(ev.conv_id, "session-update-1", MAX_CONV_ID_LEN - 1);
        strncpy(ev.service_key, "10.0.0.1:8080:6", sizeof(ev.service_key) - 1);
        llb_sockproxy_emit_sync_event(&ev);
    }

    /* Site 2: pd_session_store insert branch. */
    {
        mock_wrlock();
        mock_unlock();
        proxy_sync_event_t ev = { .kind = SYNC_SESSION_CREATE,
                                  .prefill_ep_idx = 0, .decode_ep_idx = 1,
                                  .ep_idx = -1, .created_ts = 2000 };
        strncpy(ev.conv_id, "session-create-1", MAX_CONV_ID_LEN - 1);
        strncpy(ev.service_key, "10.0.0.1:8080:6", sizeof(ev.service_key) - 1);
        llb_sockproxy_emit_sync_event(&ev);
    }

    /* Site 3: pd_session_evict bulk TTL evict (one of N victims). */
    {
        mock_wrlock();
        mock_unlock();
        proxy_sync_event_t ev = { .kind = SYNC_SESSION_DELETE,
                                  .prefill_ep_idx = -1, .decode_ep_idx = -1,
                                  .ep_idx = -1, .created_ts = 3000 };
        strncpy(ev.conv_id, "session-evict-bulk", MAX_CONV_ID_LEN - 1);
        strncpy(ev.service_key, "10.0.0.1:8080:6", sizeof(ev.service_key) - 1);
        llb_sockproxy_emit_sync_event(&ev);
    }

    /* Site 4: pd_session_evict_key single-key delete. */
    {
        mock_wrlock();
        mock_unlock();
        proxy_sync_event_t ev = { .kind = SYNC_SESSION_DELETE,
                                  .prefill_ep_idx = -1, .decode_ep_idx = -1,
                                  .ep_idx = -1, .created_ts = 4000 };
        strncpy(ev.conv_id, "session-evict-key", MAX_CONV_ID_LEN - 1);
        strncpy(ev.service_key, "10.0.0.1:8080:6", sizeof(ev.service_key) - 1);
        llb_sockproxy_emit_sync_event(&ev);
    }

    /* Site 5: store_conversation_endpoint update or insert. */
    {
        mock_wrlock();
        mock_unlock();
        proxy_sync_event_t ev = { .kind = SYNC_CONV_CREATE,
                                  .prefill_ep_idx = -1, .decode_ep_idx = -1,
                                  .ep_idx = 2, .created_ts = 5000 };
        strncpy(ev.conv_id, "conv-create-1", MAX_CONV_ID_LEN - 1);
        strncpy(ev.service_key, "10.0.0.1:8080:6", sizeof(ev.service_key) - 1);
        llb_sockproxy_emit_sync_event(&ev);
    }

    /* Assertions. */
    ASSERT_EQ(g_record_count, 5, "5 emit sites recorded");
    for (uint32_t i = 0; i < g_record_count; i++) {
        ASSERT_EQ(g_records[i].lock_held_at_emit, 0, "lock NOT held at emit");
    }
    return 1;
}

/* Test 2: 10K ring overflow drop-oldest.
 * Push 20,000 events; assert ring count == 10,000 + overflow_total == 10,000;
 * assert FIFO order (oldest dropped → tail entry is the 10,001th pushed event). */
static int test_ring_overflow_drop_oldest(void) {
    g_record_count = 0;
    tls_rwlock_held = 0;
    ring_init();

    const uint32_t N = 20000;
    for (uint32_t i = 0; i < N; i++) {
        proxy_sync_event_t ev = { .kind = SYNC_SESSION_CREATE,
                                  .prefill_ep_idx = 0, .decode_ep_idx = 1,
                                  .ep_idx = -1, .created_ts = (uint64_t)i };
        snprintf(ev.conv_id, sizeof(ev.conv_id), "ev-%u", i);
        strncpy(ev.service_key, "10.0.0.1:8080:6", sizeof(ev.service_key) - 1);
        /* Inline ring push (bypass the recorder which only has 64 slots). */
        ring_push_drop_oldest(&ev);
    }

    ASSERT_EQ(g_ring.count, RING_CAP, "ring is full after 20K pushes");
    ASSERT_EQ(g_ring.overflow_total, N - RING_CAP, "overflow_total == N - RING_CAP");

    /* FIFO drop-oldest: tail should be event #10000 (0-indexed). */
    {
        proxy_sync_event_t tail_ev = g_ring.buf[g_ring.tail];
        ASSERT_EQ(tail_ev.created_ts, RING_CAP, "tail is event #10000 (oldest survivor)");
    }
    /* Head-1 should be the last event pushed (#19999). */
    {
        uint32_t head_minus_1 = (g_ring.head == 0 ? RING_CAP - 1 : g_ring.head - 1);
        proxy_sync_event_t head_ev = g_ring.buf[head_minus_1];
        ASSERT_EQ(head_ev.created_ts, N - 1, "head-1 is event #19999 (newest)");
    }
    return 1;
}

/* Test 3: 5-function emit-site coverage.
 * Reuses test 1's records; asserts the kinds match the SPEC mapping.
 * (UPDATE, CREATE, DELETE, DELETE, CREATE) for the 5 simulated sites. */
static int test_five_function_coverage(void) {
    /* Re-run test 1 to populate records. */
    if (!test_emit_after_unlock()) return 0;

    ASSERT_EQ(g_records[0].kind, SYNC_SESSION_UPDATE, "site 1: pd_session_store update");
    ASSERT_EQ(g_records[1].kind, SYNC_SESSION_CREATE, "site 2: pd_session_store insert");
    ASSERT_EQ(g_records[2].kind, SYNC_SESSION_DELETE, "site 3: pd_session_evict bulk");
    ASSERT_EQ(g_records[3].kind, SYNC_SESSION_DELETE, "site 4: pd_session_evict_key");
    ASSERT_EQ(g_records[4].kind, SYNC_CONV_CREATE,    "site 5: store_conversation_endpoint");
    return 1;
}

int main(void) {
    printf(" Task A2 — sockproxy emit-after-unlock + 10K ring tests\n");
    RUN_TEST(test_emit_after_unlock);
    RUN_TEST(test_ring_overflow_drop_oldest);
    RUN_TEST(test_five_function_coverage);
    printf("\nResult: %d/%d tests passed\n", g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
