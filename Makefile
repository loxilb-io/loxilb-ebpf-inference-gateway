# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

kerninstalldir = $(shell pwd)/loxilb-kern
export kerninstalldir

DPU_CPUS ?= 8
export DPU_CPUS

KERN = $(wildcard kernel*)
KERN_CLEAN = $(addsuffix _clean,$(KERN))
KERN_INST = $(addsuffix _install,$(KERN))

# DOCA bridge library (only when HAVE_DOCA is set)
DOCA_DIR = doca

.PHONY: clean $(KERN) $(KERN_CLEAN) $(KERN_INST) doca-lib doca-stub doca-clean dpu dpu-bf3

ifdef HAVE_DOCA
all: $(KERN) doca-lib
else
all: $(KERN) doca-stub
endif

clean: $(KERN_CLEAN) doca-clean
install: $(KERN_INST)

$(KERN):
	$(MAKE) -C $@

$(KERN_CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean

$(KERN_INST):
	@sudo rm -fr $(kerninstalldir)
	@mkdir -p $(kerninstalldir)
	@echo dp-release path : $(kerninstalldir)
	$(MAKE) -C $(subst _install,,$@) install

doca-lib:
	$(MAKE) -C $(DOCA_DIR) HAVE_DOCA=1

doca-stub:
	$(MAKE) -C $(DOCA_DIR)

doca-clean:
	$(MAKE) -C $(DOCA_DIR) clean

# DPU build targets -- propagate flags to kernel sub-makes
dpu: $(KERN_CLEAN)
	$(MAKE) HAVE_DP_DPU_SLIM=1 DPU_CPUS=$(DPU_CPUS) $(KERN)

dpu-bf3: $(KERN_CLEAN)
	$(MAKE) HAVE_DP_DPU_BF3=1 DPU_CPUS=$(DPU_CPUS) $(KERN)
