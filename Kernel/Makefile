obj-m += mymodule.o
mymodule-objs := main.o StringUtils.o Events/ExecveEvent.o Rules/Rules.o Rules/RulesIoctl.o Alert.o Netlink/Netlink.o ThreadManagment/ThreadManagment.o Events/EventCommon.o Events/OpenEvent.o Exclusions/Exclusions.o Exclusions/ExclusionsIoctl.o

PWD := $(CURDIR)

KMOD:
	-rmmod mymodule
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "lsmod:"
	-lsmod | grep mymodule
	insmod mymodule.ko
	-echo "----------"
	-echo "lsmod:"
	-lsmod | grep mymodule

all: KMOD

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rmmod mymodule