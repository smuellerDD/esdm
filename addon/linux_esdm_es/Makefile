obj-m		+= esdm_es.o
esdm_es-y	= esdm_es_mgr.o esdm_es_sched.o esdm_es_timer_common.o \
		  esdm_hash_kcapi.o esdm_health.o

#
# Enable interfaces to obtain raw entropy
# If this interface is enabled, interface files in /sys/kernel/debug/esdm_es
# are created.
#
# When enabling this code base, select the proper interfaces in esdm_testing.h.
#
#esdm_es-y	+= esdm_testing.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
