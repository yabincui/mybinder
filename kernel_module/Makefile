
ifneq ($(KERNELRELEASE),)
obj-m += mybinder.o
mybinder-objs := binder.o

else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

modules default:
	rm -rf *.o *.ko
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *.ko
endif
