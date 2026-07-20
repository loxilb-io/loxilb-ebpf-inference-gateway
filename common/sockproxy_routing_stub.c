/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* sockproxy_routing_stub.c — No-op stubs compiled when HAVE_DP_GPU_ROUTING is
 * not set.  Satisfies the linker without pulling in the full routing logic.
 */

#include <stddef.h>
#include "uthash.h"
#include "sockproxy_routing.h"

void
build_ephash_key(char *key_buf, size_t buf_size,
                 const char *host, const char *path_prefix,
                 const char *model_name)
{
  (void)host; (void)path_prefix; (void)model_name;
  if (key_buf && buf_size > 0)
    key_buf[0] = '\0';
}

proxy_epval_t *
find_endpoint_lpm(proxy_map_ent_t *ent, const char *host,
                  const char *request_path, const char *model_name)
{
  (void)ent; (void)host; (void)request_path; (void)model_name;
  return NULL;
}
