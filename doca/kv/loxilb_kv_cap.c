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
 * loxilb_kv_cap.c -- DOCA hardware capability probe for the KV pipeline.
 *
 * Compiled only when HAVE_DOCA=1. Detects HW Deflate (Compress),
 * DMA, and Communication Channel availability on BlueField devices.
 * Writes results to /run/loxilb-kv/capabilities.json for runtime
 * consumption by the KV agent and CGO bridge.
 */

#include "loxilb_kv.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include <doca_dev.h>
#include <doca_compress.h>
#include <doca_dma.h>
#include <doca_comch.h>
#include <doca_mmap.h>
#include <doca_log.h>

DOCA_LOG_REGISTER(LLB_KV_CAP);

/* ------------------------------------------------------------------ */
/* Capability probe -- enumerate DOCA devices and test subsystems      */
/* ------------------------------------------------------------------ */

int llb_kv_capability_probe(llb_kv_capabilities_t *caps)
{
    struct doca_devinfo **dev_list = NULL;
    uint32_t nb_devs = 0;
    doca_error_t result;

    if (!caps)
        return LLB_KV_ERR_INTERNAL;

    /* Zero-initialize all capabilities */
    memset(caps, 0, sizeof(*caps));
    strncpy(caps->health_status, "down", sizeof(caps->health_status) - 1);

    /* Enumerate DOCA devices */
    result = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (result != DOCA_SUCCESS || nb_devs == 0) {
        DOCA_LOG_WARN("No DOCA devices found: %s",
                      doca_error_get_descr(result));
        return LLB_KV_OK;  /* Not an error -- just no HW */
    }

    /* Use first device for capability checks */
    struct doca_dev *dev = NULL;
    result = doca_dev_open(dev_list[0], &dev);
    if (result != DOCA_SUCCESS) {
        DOCA_LOG_ERR("Failed to open DOCA device: %s",
                     doca_error_get_descr(result));
        doca_devinfo_destroy_list(dev_list);
        return LLB_KV_ERR_HW;
    }

    /* --- Check HW Deflate (Compress) --- */
    {
        struct doca_compress *compress = NULL;
        result = doca_compress_create(dev, &compress);
        if (result == DOCA_SUCCESS) {
            caps->hw_deflate = true;
            doca_compress_destroy(compress);
        } else {
            DOCA_LOG_INFO("HW Deflate not available: %s",
                          doca_error_get_descr(result));
        }
    }

    /* --- Check DMA --- */
    {
        struct doca_dma *dma = NULL;
        result = doca_dma_create(dev, &dma);
        if (result == DOCA_SUCCESS) {
            caps->hw_dma = true;
            doca_dma_destroy(dma);
        } else {
            DOCA_LOG_INFO("HW DMA not available: %s",
                          doca_error_get_descr(result));
        }
    }

    /* --- Check PCI export support --- */
    {
        uint8_t supported = 0;
        result = doca_mmap_cap_is_export_pci_supported(dev_list[0],
                                                       &supported);
        if (result == DOCA_SUCCESS && supported) {
            caps->pci_export_hw = true;
        } else {
            DOCA_LOG_INFO("PCI export not supported: %s",
                          doca_error_get_descr(result));
        }
    }

    /* --- Check Communication Channel --- */
    {
        uint32_t max_msg = 0;
        result = doca_comch_cap_get_max_msg_size(dev_list[0], &max_msg);
        if (result == DOCA_SUCCESS && max_msg > 0) {
            caps->comch = true;
            caps->comch_max_msg_bytes = max_msg;

            /*
             * CRITICAL guard: ComCh max message must accommodate our
             * control messages. Check against a minimum reasonable size
             * (256 bytes covers all current KV control messages).
             */
            if (max_msg < 256) {
                DOCA_LOG_ERR("ComCh max msg size %u < minimum 256 bytes",
                             max_msg);
                doca_dev_close(dev);
                doca_devinfo_destroy_list(dev_list);
                return LLB_KV_ERR_HW;
            }
        } else {
            DOCA_LOG_INFO("ComCh not available: %s",
                          doca_error_get_descr(result));
        }
    }

    /* --- Determine health status --- */
    if (!caps->comch) {
        strncpy(caps->health_status, "down",
                sizeof(caps->health_status) - 1);
    } else if (caps->hw_deflate && caps->hw_dma && caps->comch &&
               caps->pci_export_hw) {
        strncpy(caps->health_status, "ok",
                sizeof(caps->health_status) - 1);
    } else {
        strncpy(caps->health_status, "degraded",
                sizeof(caps->health_status) - 1);
    }

    doca_dev_close(dev);
    doca_devinfo_destroy_list(dev_list);
    return LLB_KV_OK;
}

/* ------------------------------------------------------------------ */
/* Open a DOCA device (by PCI addr or first available)                  */
/* ------------------------------------------------------------------ */

doca_error_t llb_kv_cap_open_device(const char *pci_addr,
                                     struct doca_dev **dev_out)
{
    struct doca_devinfo **dev_list = NULL;
    uint32_t nb_devs = 0;
    doca_error_t ret;
    char buf[DOCA_DEVINFO_PCI_ADDR_SIZE];

    if (!dev_out)
        return DOCA_ERROR_INVALID_VALUE;

    ret = doca_devinfo_create_list(&dev_list, &nb_devs);
    if (ret != DOCA_SUCCESS || nb_devs == 0) {
        if (dev_list) doca_devinfo_destroy_list(dev_list);
        return ret != DOCA_SUCCESS ? ret : DOCA_ERROR_NOT_FOUND;
    }

    for (uint32_t i = 0; i < nb_devs; i++) {
        ret = doca_devinfo_get_pci_addr_str(dev_list[i], buf);
        if (ret != DOCA_SUCCESS) continue;

        if (pci_addr && strstr(buf, pci_addr) == NULL)
            continue;

        ret = doca_dev_open(dev_list[i], dev_out);
        doca_devinfo_destroy_list(dev_list);
        return ret;
    }

    doca_devinfo_destroy_list(dev_list);
    return DOCA_ERROR_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/* Write capabilities as JSON to filesystem                            */
/* ------------------------------------------------------------------ */

int llb_kv_capability_write_json(const llb_kv_capabilities_t *caps,
                                 const char *path)
{
    if (!caps || !path)
        return LLB_KV_ERR_INTERNAL;

    /* Create parent directory (equivalent to mkdir -p) */
    char dir[256];
    strncpy(dir, path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';

    /* Find last slash to extract directory */
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = '\0';
        /* Simple mkdir -p: try creating, ignore EEXIST */
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
            return LLB_KV_ERR_INTERNAL;
        }
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
