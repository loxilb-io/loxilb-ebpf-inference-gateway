/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * loxilb_kv_cap_stub.c -- Stub capability probe for non-DOCA builds.
 *
 * Compiled when HAVE_DOCA is NOT set. All hardware capabilities are
 * reported as unavailable, health_status = "degraded".
 *
 * Pattern follows loxilb_doca_flow_stub.c style.
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* Stub capability probe -- all HW flags false                         */
/* ------------------------------------------------------------------ */

int llb_kv_capability_probe(llb_kv_capabilities_t *caps)
{
    if (!caps)
        return LLB_KV_ERR_INTERNAL;

    memset(caps, 0, sizeof(*caps));
    caps->hw_deflate          = false;
    caps->hw_dma              = false;
    caps->comch               = false;
    caps->pci_export_hw       = false;
    caps->comch_max_msg_bytes = 0;
    strncpy(caps->health_status, "degraded",
            sizeof(caps->health_status) - 1);

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Write capabilities JSON (same logic as real build)                   */
/* ------------------------------------------------------------------ */

int llb_kv_capability_write_json(const llb_kv_capabilities_t *caps,
                                 const char *path)
{
    if (!caps || !path)
        return LLB_KV_ERR_INTERNAL;

    /* Create parent directory */
    char dir[256];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';

    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            return LLB_KV_ERR_INTERNAL;
    }

    FILE *fp = fopen(path, "w");
    if (!fp)
        return LLB_KV_ERR_INTERNAL;

    fprintf(fp,
            "{\n"
            "  \"hw_deflate\": %s,\n"
            "  \"hw_dma\": %s,\n"
            "  \"comch\": %s,\n"
            "  \"pci_export_hw\": %s,\n"
            "  \"comch_max_msg_bytes\": %u,\n"
            "  \"health_status\": \"%s\"\n"
            "}\n",
            caps->hw_deflate   ? "true" : "false",
            caps->hw_dma       ? "true" : "false",
            caps->comch        ? "true" : "false",
            caps->pci_export_hw? "true" : "false",
            caps->comch_max_msg_bytes,
            caps->health_status);

    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    return LLB_KV_OK;
}
