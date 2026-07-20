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
 * loxilb_kv_affinity.c -- Core affinity module (real Linux implementation).
 *
 * Parses the --kv-core-affinity spec "net:deq:ctrl" into three cpu_set_t
 * groups, validates against online cores, and applies per-thread affinity
 * via pthread_setaffinity_np.
 *
 * Resource partitioning prevents interference between network recv,
 * dequantize compute, and HW accelerator polling per ShadowServe design.
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

/* ------------------------------------------------------------------ */
/* Internal: parse a comma-separated group into IDs + cpu_set          */
/* ------------------------------------------------------------------ */
static int parse_group(const char *group, int *ids, int *count,
                       cpu_set_t *cpuset)
{
    CPU_ZERO(cpuset);
    *count = 0;

    if (!group || group[0] == '\0')
        return LLB_KV_ERR_BOUNDS;

    char buf[256];
    size_t len = strlen(group);
    if (len >= sizeof(buf))
        return LLB_KV_ERR_BOUNDS;
    memcpy(buf, group, len + 1);

    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok) {
        for (const char *p = tok; *p; p++) {
            if (*p < '0' || *p > '9')
                return LLB_KV_ERR_BOUNDS;
        }

        char *endptr;
        long val = strtol(tok, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val >= LLB_KV_AFFINITY_MAX_CORES)
            return LLB_KV_ERR_BOUNDS;

        if (*count >= LLB_KV_AFFINITY_MAX_CORES)
            return LLB_KV_ERR_BOUNDS;

        int core_id = (int)val;
        ids[*count] = core_id;
        CPU_SET(core_id, cpuset);
        (*count)++;

        tok = strtok_r(NULL, ",", &saveptr);
    }

    if (*count == 0)
        return LLB_KV_ERR_BOUNDS;

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* llb_kv_affinity_parse                                               */
/* ------------------------------------------------------------------ */
int llb_kv_affinity_parse(const char *spec, llb_kv_affinity_t *aff)
{
    if (!spec || !aff)
        return LLB_KV_ERR_BOUNDS;

    memset(aff, 0, sizeof(*aff));

    char buf[1024];
    size_t len = strlen(spec);
    if (len >= sizeof(buf))
        return LLB_KV_ERR_BOUNDS;
    memcpy(buf, spec, len + 1);

    char *groups[3] = {NULL, NULL, NULL};
    int group_count = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(buf, ":", &saveptr);
    while (tok && group_count < 4) {
        if (group_count < 3)
            groups[group_count] = tok;
        group_count++;
        tok = strtok_r(NULL, ":", &saveptr);
    }

    if (group_count != 3)
        return LLB_KV_ERR_BOUNDS;

    int rc;
    rc = parse_group(groups[0], aff->net_ids, &aff->net_count, &aff->net_cores);
    if (rc != LLB_KV_OK) return rc;

    rc = parse_group(groups[1], aff->deq_ids, &aff->deq_count, &aff->deq_cores);
    if (rc != LLB_KV_OK) return rc;

    rc = parse_group(groups[2], aff->ctrl_ids, &aff->ctrl_count, &aff->ctrl_cores);
    if (rc != LLB_KV_OK) return rc;

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* llb_kv_affinity_auto_detect                                         */
/* ------------------------------------------------------------------ */
int llb_kv_affinity_auto_detect(llb_kv_affinity_t *aff)
{
    if (!aff)
        return LLB_KV_ERR_BOUNDS;

    memset(aff, 0, sizeof(*aff));

    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0)
        return LLB_KV_ERR_INTERNAL;

    CPU_ZERO(&aff->net_cores);
    CPU_ZERO(&aff->deq_cores);
    CPU_ZERO(&aff->ctrl_cores);

    if (ncpu >= 8) {
        aff->net_ids[0] = 0; aff->net_ids[1] = 1; aff->net_count = 2;
        CPU_SET(0, &aff->net_cores);
        CPU_SET(1, &aff->net_cores);

        aff->deq_count = 0;
        for (int i = 2; i <= ncpu - 3; i++) {
            aff->deq_ids[aff->deq_count] = i;
            CPU_SET(i, &aff->deq_cores);
            aff->deq_count++;
        }

        aff->ctrl_ids[0] = ncpu - 2; aff->ctrl_ids[1] = ncpu - 1; aff->ctrl_count = 2;
        CPU_SET(ncpu - 2, &aff->ctrl_cores);
        CPU_SET(ncpu - 1, &aff->ctrl_cores);
    } else if (ncpu >= 4) {
        aff->net_ids[0] = 0; aff->net_count = 1;
        CPU_SET(0, &aff->net_cores);

        aff->deq_count = 0;
        for (int i = 1; i <= ncpu - 2; i++) {
            aff->deq_ids[aff->deq_count] = i;
            CPU_SET(i, &aff->deq_cores);
            aff->deq_count++;
        }

        aff->ctrl_ids[0] = ncpu - 1; aff->ctrl_count = 1;
        CPU_SET(ncpu - 1, &aff->ctrl_cores);
    } else {
        aff->net_ids[0] = 0; aff->net_count = 1;
        CPU_SET(0, &aff->net_cores);

        if (ncpu >= 3) {
            aff->deq_ids[0] = 1; aff->deq_count = 1;
            CPU_SET(1, &aff->deq_cores);
            aff->ctrl_ids[0] = 2; aff->ctrl_count = 1;
            CPU_SET(2, &aff->ctrl_cores);
        } else if (ncpu == 2) {
            aff->deq_ids[0] = 1; aff->deq_count = 1;
            CPU_SET(1, &aff->deq_cores);
            aff->ctrl_ids[0] = 1; aff->ctrl_count = 1;
            CPU_SET(1, &aff->ctrl_cores);
        } else {
            aff->deq_ids[0] = 0; aff->deq_count = 1;
            CPU_SET(0, &aff->deq_cores);
            aff->ctrl_ids[0] = 0; aff->ctrl_count = 1;
            CPU_SET(0, &aff->ctrl_cores);
        }
    }

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* llb_kv_affinity_validate                                            */
/* ------------------------------------------------------------------ */
int llb_kv_affinity_validate(const llb_kv_affinity_t *aff)
{
    if (!aff)
        return LLB_KV_ERR_BOUNDS;

    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);

    if (aff->net_count < 1 || aff->deq_count < 1 || aff->ctrl_count < 1)
        return LLB_KV_ERR_BOUNDS;

    int seen[LLB_KV_AFFINITY_MAX_CORES];
    memset(seen, 0, sizeof(seen));

    for (int i = 0; i < aff->net_count; i++) {
        int id = aff->net_ids[i];
        if (id < 0 || id >= ncpu)
            return LLB_KV_ERR_BOUNDS;
        if (seen[id])
            return LLB_KV_ERR_BOUNDS;
        seen[id] = 1;
    }

    for (int i = 0; i < aff->deq_count; i++) {
        int id = aff->deq_ids[i];
        if (id < 0 || id >= ncpu)
            return LLB_KV_ERR_BOUNDS;
        if (seen[id])
            return LLB_KV_ERR_BOUNDS;
        seen[id] = 1;
    }

    for (int i = 0; i < aff->ctrl_count; i++) {
        int id = aff->ctrl_ids[i];
        if (id < 0 || id >= ncpu)
            return LLB_KV_ERR_BOUNDS;
        if (seen[id])
            return LLB_KV_ERR_BOUNDS;
        seen[id] = 1;
    }

    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* llb_kv_affinity_apply_thread -- REAL: pthread_setaffinity_np         */
/* ------------------------------------------------------------------ */
int llb_kv_affinity_apply_thread(const cpu_set_t *cpuset)
{
    if (!cpuset)
        return -1;

    int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), cpuset);
    if (rc != 0) {
        fprintf(stderr, "llb_kv_affinity: pthread_setaffinity_np failed: %s\n",
                strerror(rc));
        return -1;
    }

    return 0;
}
