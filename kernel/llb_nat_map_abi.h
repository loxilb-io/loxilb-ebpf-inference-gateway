/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef LLB_NAT_MAP_ABI_H
#define LLB_NAT_MAP_ABI_H

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include "bpf.h"

/* A raw BPF lookup has no destination-length argument: the kernel copies the
 * live map's value_size bytes. Check the fd, not just the ELF or a build-time
 * assertion. Per-CPU map types also have a different userspace buffer contract.
 * This checks geometry only; equal sizes do not prove field-layout compatibility.
 */
static inline int
llb_map_check_fd(int fd, __u32 type, __u32 key_size, __u32 value_size,
                     struct bpf_map_info *info)
{
  __u32 len = sizeof(*info);
  int ret;

  memset(info, 0, sizeof(*info));
  if (fd < 0) {
    return -EBADF;
  }
  ret = bpf_obj_get_info_by_fd(fd, info, &len);
  if (ret != 0) {
    return ret;
  }
  if (len < offsetof(struct bpf_map_info, value_size) + sizeof(info->value_size) ||
      info->type != type || info->key_size != key_size ||
      info->value_size != value_size) {
    return -EPROTO;
  }
  return 0;
}

static inline int
llb_nat_map_check_fd(int fd, __u32 key_size, __u32 value_size,
                     struct bpf_map_info *info)
{
  return llb_map_check_fd(fd, BPF_MAP_TYPE_HASH, key_size, value_size, info);
}

#endif
