/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 LoxiLB Authors
 *
 * test_pdi_rmatch.c — the firewall rule table must find again every rule it
 * inserted, whatever its port match. Exercises pdi_rule_insert /
 * pdi_rule_delete through the same conversions the datapath uses, with
 * exact ports, port ranges and no ports, and proves a near-miss (another
 * port, another preference) is not matched.
 *
 * Before the PDI_RMATCH_ALL fix a rule with any port match was never found by
 * delete: the control plane dropped it while the kernel table kept enforcing
 * it (an allowedSources fence drop that outlived its rule).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/types.h>
#include "pdi.h"

static int fails;
#define CHECK(cond, ...) do { if (!(cond)) { fails++; printf("  FAIL: " __VA_ARGS__); printf("\n"); } else { printf("  ok:   " __VA_ARGS__); printf("\n"); } } while (0)

static struct pdi_rule *
mk(uint32_t pref, uint32_t dst, uint32_t dmask, uint16_t pmin, uint16_t pmax, uint8_t proto)
{
  struct pdi_rule *r = calloc(1, sizeof(*r));
  PDI_MATCH_INIT(&r->key.k4.dest, dst, dmask);
  PDI_MATCH_INIT(&r->key.k4.source, 0, 0);
  if (pmin == 0 && pmax == 0) {
    PDI_RMATCH_INIT(&r->key.k4.dport, 0, 0, 0);
  } else if (pmin == pmax) {
    PDI_RMATCH_INIT(&r->key.k4.dport, 0, pmin, 0xffff);   /* exact: val + mask */
  } else {
    PDI_RMATCH_INIT(&r->key.k4.dport, 1, pmin, pmax);     /* range */
  }
  PDI_RMATCH_INIT(&r->key.k4.sport, 0, 0, 0);
  PDI_MATCH_INIT(&r->key.k4.protocol, proto, proto ? 0xff : 0);
  r->data.pref = pref;
  return r;
}

static int
del_like(struct pdi_map *m, uint32_t pref, uint32_t dst, uint32_t dmask, uint16_t pmin, uint16_t pmax, uint8_t proto)
{
  struct pdi_rule *k = mk(pref, dst, dmask, pmin, pmax, proto);
  int nr = 0;
  int rc = pdi_rule_delete(m, &k->key, k->data.pref, &nr);
  free(k);
  return rc;
}

int
main(void)
{
  struct pdi_map *m = pdi_map_alloc("fw4-test", 0, NULL, NULL);
  int nr;
  const uint32_t vip = 0x0a0a0afe, any = 0;

  printf("pdi rule table: insert/delete with port matches\n");

  /* 1. exact port (the fence shape): insert, duplicate refused, delete found */
  CHECK(pdi_rule_insert(m, mk(64999, vip, 0xffffffff, 8080, 8080, 6), &nr) == 0, "exact-port rule inserted");
  struct pdi_rule *dup = mk(64999, vip, 0xffffffff, 8080, 8080, 6);
  CHECK(pdi_rule_insert(m, dup, &nr) == -EEXIST, "exact-port duplicate refused (EEXIST)");
  free(dup);
  CHECK(del_like(m, 64999, vip, 0xffffffff, 8081, 8081, 6) != 0, "another port is not a match");
  CHECK(del_like(m, 64998, vip, 0xffffffff, 8080, 8080, 6) != 0, "another preference is not a match");
  CHECK(del_like(m, 64999, vip, 0xffffffff, 8080, 8080, 6) == 0, "exact-port rule deleted");
  CHECK(m->nr == 0, "table empty after the delete (nr=%u)", m->nr);

  /* 2. port range */
  CHECK(pdi_rule_insert(m, mk(100, vip, 0xffffffff, 8000, 8100, 6), &nr) == 0, "range rule inserted");
  CHECK(del_like(m, 100, vip, 0xffffffff, 8000, 8101, 6) != 0, "another range bound is not a match");
  CHECK(del_like(m, 100, vip, 0xffffffff, 8080, 8080, 6) != 0, "an exact port inside the range is not the range");
  CHECK(del_like(m, 100, vip, 0xffffffff, 8000, 8100, 6) == 0, "range rule deleted");
  CHECK(m->nr == 0, "table empty after the delete (nr=%u)", m->nr);

  /* 3. no port, no proto (the generic allowedSources rule): unchanged behaviour */
  CHECK(pdi_rule_insert(m, mk(0, any, 0, 0, 0, 0), &nr) == 0, "portless rule inserted");
  CHECK(del_like(m, 0, any, 0, 0, 0, 0) == 0, "portless rule deleted");

  /* 4. the fence pair plus a portless rule, deleted in the fence's order */
  CHECK(pdi_rule_insert(m, mk(0, any, 0, 0, 0, 0), &nr) == 0, "generic allow inserted");
  CHECK(pdi_rule_insert(m, mk(65000, vip, 0xffffffff, 8080, 8080, 6), &nr) == 0, "fence allow inserted");
  CHECK(pdi_rule_insert(m, mk(64999, vip, 0xffffffff, 8080, 8080, 6), &nr) == 0, "fence drop inserted");
  CHECK(m->nr == 3, "three rules installed (nr=%u)", m->nr);
  CHECK(del_like(m, 0, any, 0, 0, 0, 0) == 0, "generic allow deleted");
  CHECK(del_like(m, 64999, vip, 0xffffffff, 8080, 8080, 6) == 0, "fence drop deleted");
  CHECK(del_like(m, 65000, vip, 0xffffffff, 8080, 8080, 6) == 0, "fence allow deleted");
  CHECK(m->nr == 0 && m->head == NULL, "table empty: nothing left to enforce (nr=%u)", m->nr);

  printf("%s (%d failures)\n", fails ? "FAILED" : "PASSED", fails);
  return fails ? 1 : 0;
}
