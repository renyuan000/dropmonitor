# This Makefile can Compile the kernel linux-3.12.6

MODNAME=dropmonitor

obj-m:=${MODNAME}.o
${MODNAME}-objs:=jprobe.o

KDIR:=/lib/modules/$(shell uname -r)/build
DEFE = -Wall -g
PWD:=$(shell pwd)
EXTRA_CFLAGS:= -Wall -Wmissing-prototypes -Wstrict-prototypes 
ADDR=$(shell grep -w  __kfree_skb /proc/kallsyms)

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
#	strip --strip-debug ${MODNAME}.ko
load:
	insmod $(MODNAME).ko; 
unload:
	rmmod  ${MODNAME}
reload:
	make unload
	make load
status:
	@lsmod |grep ${MODNAME} 
clean:
	make -C $(KDIR) M=$(PWD) clean
