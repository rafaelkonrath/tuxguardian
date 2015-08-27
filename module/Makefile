KERNELDIR := /lib/modules/$(shell uname -r)/build
KERNEL_SOURCES := $(KERNDIR)
KERNEL_HEADERS := -I$(KERNEL_SOURCES)/include

obj-m := tuxg.o
tuxg-objs := tg-defs.o tg.o
EXTRA_CFLAGS += -Os 

MODULE_NAME := tuxg


# checks if the user is running kernel 2.6.12 or above
MINOR=$(shell uname -r | cut -c3)
VERSION=$(shell uname -r | sed -n 's/[[:digit:]]\.[[:digit:]]\.\([[:digit:]]*\).*/\1/p')
CORRECT_VERSION=$(shell if [ $(VERSION) -ge 12 -a $(MINOR) -ge 6 ]; then echo yes; else echo no; fi)
ifeq ($(CORRECT_VERSION),yes)
all:
	make -C /lib/modules/$(shell uname -r)/build/ SUBDIRS=$(shell pwd) modules
else
all:
	@echo "You need kernel 2.6.12 or above!"
	@exit 1
endif




install:
	@install -m 0700 -o root -g root tuxg.ko /lib/modules/$(shell uname -r)
	@/sbin/depmod -ae
	@echo "Done."

uninstall:
	@rm -f /lib/modules/$(shell uname -r)/tuxg.ko
	@depmod -ae
	@echo "Done."

clean:
	@rm -rf *.o *.ko *.mod.? .t* *~
	@echo "Done."
