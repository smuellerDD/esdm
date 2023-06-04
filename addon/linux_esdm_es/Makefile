KERNEL_DIR ?= /lib/modules/$(shell uname -r)/build

obj-m				+= esdm_es.o
esdm_es-y			= esdm_es_mgr.o esdm_es_timer_common.o 	\
				  esdm_hash_kcapi.o esdm_health.o

#
# Scheduler-based Entropy source
# Enable the following configuration if the entropy source shall be compiled
CFLAGS_esdm_es_mgr.o		+= -DESDM_ES_SCHED
CFLAGS_esdm_health.o		+= -DESDM_ES_SCHED
CFLAGS_esdm_es_mgr_sched.o	= -DESDM_ES_SCHED
esdm_es-y			+= esdm_es_mgr_sched.o esdm_es_sched.o

#
# Interrupt-based Entropy source
# Enable the following configuration if the entropy source shall be compiled
CFLAGS_esdm_es_mgr.o		+= -DESDM_ES_IRQ
CFLAGS_esdm_health.o		+= -DESDM_ES_IRQ
CFLAGS_esdm_es_mgr_irq.o	= -DESDM_ES_IRQ
esdm_es-y			+= esdm_es_mgr_irq.o esdm_es_irq.o

#
# Enable interfaces to obtain raw entropy
# If this interface is enabled, interface files in /sys/kernel/debug/esdm_es
# are created.
#
# When enabling this code base, select the proper interfaces in esdm_testing.h.
#
#CFLAGS_esdm_testing.o		= -DESDM_TESTING
#esdm_es-y			+= esdm_testing.o

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

install:
	make -C $(KERNEL_DIR) M=$(PWD) modules_install

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
