KERNEL_DIR?=/lib/modules/$(shell uname -r)/build

# The EGD protocol of the ESDM, which the module speaks
ccflags-y			+= -I$(src)/../../service-egd

obj-m				+= esdm_cdev.o
esdm_cdev-y			= esdm_cdev_main.o esdm_cdev_egd.o	\
				  esdm_cdev_proc.o

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

install:
	make -C $(KERNEL_DIR) M=$(PWD) modules_install

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean
