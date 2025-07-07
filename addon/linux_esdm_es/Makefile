KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

BUILD_ES_SCHED?=1
BUILD_ES_IRQ?=1
BUILD_TESTING?=0

obj-m				+= esdm_es.o
esdm_es-y			= esdm_es_mgr.o esdm_es_timer_common.o 	\
				  esdm_drbg_kcapi.o esdm_health.o

#
# Scheduler-based Entropy source
#
ifeq ($(BUILD_ES_SCHED), 1)
CFLAGS_esdm_es_mgr.o		+= -DESDM_ES_SCHED
CFLAGS_esdm_health.o		+= -DESDM_ES_SCHED
CFLAGS_esdm_es_mgr_sched.o	= -DESDM_ES_SCHED
esdm_es-y			+= esdm_es_mgr_sched.o esdm_es_sched.o
endif

#
# Interrupt-based Entropy source
#
ifeq ($(BUILD_ES_IRQ), 1)
CFLAGS_esdm_es_mgr.o		+= -DESDM_ES_IRQ
CFLAGS_esdm_health.o		+= -DESDM_ES_IRQ
CFLAGS_esdm_es_mgr_irq.o	= -DESDM_ES_IRQ
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
ccflags-y			+= -DCONFIG_ESDM_RAW_HIRES_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_JIFFIES_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_IRQ_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_RETIP_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_REGS_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_ARRAY
ccflags-y			+= -DCONFIG_ESDM_IRQ_PERF
ccflags-y			+= -DCONFIG_ESDM_RAW_SCHED_HIRES_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_SCHED_PID_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_SCHED_START_TIME_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_RAW_SCHED_NVCSW_ENTROPY
ccflags-y			+= -DCONFIG_ESDM_SCHED_PERF
endif


all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

install:
	make -C $(KERNEL_DIR) M=$(PWD) modules_install

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
