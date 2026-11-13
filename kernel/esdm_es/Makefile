KERNEL_DIR?=/lib/modules/$(shell uname -r)/build

#
# The entropy sources to build: the scheduler ES needs the scheduler hooks of
# 0001-*.patch, the interrupt ES the interrupt hooks of 0002-*.patch. Each
# allocates its event rings, one per possible CPU, when the module is loaded.
#
BUILD_ES_SCHED?=0
BUILD_ES_IRQ?=1
BUILD_TESTING?=0

#
# config switch for OSR, 1 to 25 - the per-CPU event rings grow with it
#
ESDM_ES_OSR?=3

ccflags-y += -DESDM_ES_OSR=$(ESDM_ES_OSR)

#
# Code shared with the ESDM: the IOCTL interface and the health test cutoffs
# (kernel/shared), the seed sizes (esdm/drng) and, where the kernel provides
# SHAKE256, the XDRBG-256 (esdm/crypto, built by esdm_xdrbg_shared.c). The
# module's own directory comes first, so that its esdm_definitions.h is the one
# the shared code uses.
#
ccflags-y += -I$(src) -I$(src)/../shared -I$(src)/../../esdm/drng	\
	     -I$(src)/../../esdm/crypto -I$(src)/../../common

obj-m				+= esdm_es.o
esdm_es-y			= esdm_es_mgr.o esdm_es_timer_common.o 	\
				  esdm_es_ring.o esdm_es_drbg.o		\
				  esdm_drbg_kcapi.o esdm_xdrbg_shared.o	\
				  esdm_health.o

#
# Scheduler-based Entropy source
#
ifeq ($(BUILD_ES_SCHED), 1)
CFLAGS_esdm_es_mgr.o		+= -DESDM_ES_SCHED
CFLAGS_esdm_health.o		+= -DESDM_ES_SCHED
CFLAGS_esdm_es_mgr_sched.o	= -DESDM_ES_SCHED
CFLAGS_esdm_es_timer_common.o   += -DESDM_ES_SCHED
esdm_es-y			+= esdm_es_mgr_sched.o esdm_es_sched.o
endif

#
# Interrupt-based Entropy source
#
ifeq ($(BUILD_ES_IRQ), 1)
CFLAGS_esdm_es_mgr.o		+= -DESDM_ES_IRQ
CFLAGS_esdm_health.o		+= -DESDM_ES_IRQ
CFLAGS_esdm_es_mgr_irq.o	= -DESDM_ES_IRQ
CFLAGS_esdm_es_timer_common.o   += -DESDM_ES_IRQ
esdm_es-y			+= esdm_es_mgr_irq.o esdm_es_irq.o
endif

#
# Enable interfaces to obtain raw entropy
# If this interface is enabled, interface files in /sys/kernel/debug/esdm_es
# are created.
#
ifeq ($(BUILD_TESTING), 1)
CFLAGS_esdm_es_mgr.o		+= -DESDM_TESTING
CFLAGS_esdm_testing.o		= -DESDM_TESTING
esdm_es-y			+= esdm_testing.o
#
# Only the files of the entropy sources built: the others would never see
# data, and the scheduler ones have all readers busy-poll, see esdm_testing.c.
#
ifeq ($(BUILD_ES_IRQ), 1)
ccflags-y			+= -DCONFIG_ESDM_RAW_HIRES_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_IRQ_PERF
endif
ifeq ($(BUILD_ES_SCHED), 1)
ccflags-y			+= -DCONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_SCHED_PERF
endif
endif


all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

install:
	make -C $(KERNEL_DIR) M=$(PWD) modules_install

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
