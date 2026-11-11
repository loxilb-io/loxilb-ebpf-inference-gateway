/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#include <assert.h>
#include <stdio.h>
#include "llb_nat_map_abi.h"

static struct bpf_map_info live;
static __u32 reply_len;
static int query_result;
static int queries;

/* Only the syscall boundary is replaced; the production guard is unchanged. */
int bpf_obj_get_info_by_fd(int fd, void *info, __u32 *len)
{
  assert(fd == 7);
  assert(*len == sizeof(live));
  queries++;
  if (query_result) return query_result;
  memcpy(info, &live, sizeof(live));
  *len = reply_len;
  return 0;
}

int main(void)
{
  struct bpf_map_info info;

  live.type = BPF_MAP_TYPE_HASH;
  live.key_size = 28;
  live.value_size = 4040;
  live.id = 42;
  reply_len = sizeof(live);
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == 0);
  assert(info.id == 42);
  /* Both directions matter: an oversized value overwrites the destination;
   * an undersized value is not the declared userspace layout either. */
  assert(llb_nat_map_check_fd(7, 28, 3008, &info) == -EPROTO);
  live.value_size = 3008;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EPROTO);
  live.value_size = 4040;
  live.key_size = 32;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EPROTO);
  live.key_size = 24;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EPROTO);
  live.key_size = 28;
  live.type = BPF_MAP_TYPE_PERCPU_HASH;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EPROTO);
  live.type = BPF_MAP_TYPE_ARRAY;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EPROTO);
  live.type = BPF_MAP_TYPE_HASH;
  reply_len = offsetof(struct bpf_map_info, value_size);
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EPROTO);
  reply_len = sizeof(live);
  query_result = -EPERM;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EPERM);
  query_result = -EBADF;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == -EBADF);
  queries = 0;
  assert(llb_nat_map_check_fd(-1, 28, 4040, &info) == -EBADF);
  assert(queries == 0);
  query_result = 0;
  assert(llb_nat_map_check_fd(7, 28, 4040, &info) == 0);
  live.type = BPF_MAP_TYPE_ARRAY;
  assert(llb_map_check_fd(7, BPF_MAP_TYPE_ARRAY, 28, 4040, &info) == 0);
  assert(llb_map_check_fd(7, BPF_MAP_TYPE_HASH, 28, 4040, &info) == -EPROTO);
  live.type = BPF_MAP_TYPE_PERCPU_ARRAY;
  assert(llb_map_check_fd(7, BPF_MAP_TYPE_PERCPU_ARRAY, 28, 4040, &info) == 0);
  assert(llb_map_check_fd(7, BPF_MAP_TYPE_ARRAY, 28, 4040, &info) == -EPROTO);
  puts("PASS: NAT map geometry and inspection-failure guards (12 NAT cases + generic array/per-CPU cases)");
  return 0;
}
