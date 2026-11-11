/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include "llb_nat_map_abi.h"

/* Run only in an isolated environment with permission to create BPF maps.
 * These maps are anonymous, never attached or pinned, and closed after use. */
int main(void)
{
  struct bpf_map_info info;
  unsigned char key[28] = {0};
  unsigned char value[4040], actual[4040];
  int fd = bpf_map_create(BPF_MAP_TYPE_HASH, "i45_nat_abi", 28, 4040, 1, NULL);

  if (fd < 0) {
    perror("create isolated hash map (BPF privileges required)");
    return 1;
  }
  memset(value, 0xa5, sizeof(value));
  assert(llb_nat_map_check_fd(fd, sizeof(key), sizeof(value), &info) == 0);
  assert(bpf_map_update_elem(fd, key, value, BPF_ANY) == 0);
  assert(bpf_map_lookup_elem(fd, key, actual) == 0);
  assert(memcmp(value, actual, sizeof(value)) == 0);
  /* Do not issue an unsafe lookup after the guard rejects this smaller
   * destination. This is the real kernel metadata, not a mocked map shape. */
  assert(llb_nat_map_check_fd(fd, 28, 3008, &info) == -EPROTO);
  assert(llb_nat_map_check_fd(fd, 24, 4040, &info) == -EPROTO);
  assert(bpf_map_lookup_elem(fd, key, actual) == 0);
  assert(memcmp(value, actual, sizeof(value)) == 0);
  assert(bpf_map_delete_elem(fd, key) == 0);
  close(fd);

  fd = bpf_map_create(BPF_MAP_TYPE_HASH, "i45_nat_small", 28, 3008, 1, NULL);
  assert(fd >= 0);
  assert(llb_nat_map_check_fd(fd, 28, 4040, &info) == -EPROTO);
  close(fd);

  fd = bpf_map_create(BPF_MAP_TYPE_HASH, "i45_nat_key", 24, 4040, 1, NULL);
  assert(fd >= 0);
  assert(llb_nat_map_check_fd(fd, 28, 4040, &info) == -EPROTO);
  close(fd);

  fd = bpf_map_create(BPF_MAP_TYPE_PERCPU_HASH, "i45_nat_pcpu", 28, 4040, 1, NULL);
  assert(fd >= 0);
  assert(llb_nat_map_check_fd(fd, 28, 4040, &info) == -EPROTO);
  close(fd);
  /* BPF_OBJ_GET_INFO_BY_FD returns EBADFD for an invalid descriptor. */
  assert(llb_nat_map_check_fd(fd, 28, 4040, &info) == -EBADFD);
  assert(info.id == 0);
  assert(llb_nat_map_check_fd(-1, 28, 4040, &info) == -EBADF);
  /* Generic D1 contracts: CT-style HASH and FW-style ARRAY geometry. */
  fd = bpf_map_create(BPF_MAP_TYPE_ARRAY, "i45_fw_abi", 4, 128, 1, NULL);
  assert(fd >= 0);
  assert(llb_map_check_fd(fd, BPF_MAP_TYPE_ARRAY, 4, 128, &info) == 0);
  assert(llb_map_check_fd(fd, BPF_MAP_TYPE_ARRAY, 4, 120, &info) == -EPROTO);
  assert(llb_map_check_fd(fd, BPF_MAP_TYPE_HASH, 4, 128, &info) == -EPROTO);
  close(fd);
  puts("PASS: real kernel map geometry, data integrity and negative controls");
  return 0;
}
