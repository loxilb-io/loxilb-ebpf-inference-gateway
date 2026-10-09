/* Common wrapper function for libbpf */
#ifndef __COMMON_LIBBPF_H
#define __COMMON_LIBBPF_H

#define PINPATH_MAX_LEN 4096

struct libbpf_cfg {
  int     ifindex;
  char    *ifname;
  char    ifname_buf[IF_NAMESIZE];
  bool    do_unload;
  bool    reuse_maps;
  char    pin_dir[512];
  char    filename[512];
  char    progsec[32];
  int     tc_bpf;
  int     tc_egr_bpf;
  __u32   bpf_flags;
  /* XDP only: flags to retry the attach with when bpf_flags is refused by
   * the driver (0 = no retry). On a successful retry bpf_flags is replaced
   * by the flags in force, so a later detach uses the mode that is live. */
  __u32   bpf_fallback_flags;
};

int xdp_link_attach(int ifindex, __u32 bpf_flags, int prog_fd);
int xdp_link_detach(int ifindex, __u32 bpf_flags, __u32 epgid);
struct bpf_object *libbpf_xdp_attach(struct libbpf_cfg *cfg);

int libbpf_tc_detach(struct libbpf_cfg *cfg, int egr);
void *libbpf_tc_attach(struct libbpf_cfg *cfg, int egr);

#endif /* __COMMON_LIBBPF_H */
