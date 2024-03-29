obj-m += mymodule.o
mymodule-objs := main.o StringUtils.o Events/ExecveEvent.o Rules/Rules.o Rules/RulesIoctl.o Alert.o Netlink/Netlink.o ThreadManagment/ThreadManagment.o Events/EventCommon.o

PWD := $(CURDIR)
USER_SPACE_TARGET := user_app

# User space application build
USER_SPACE:
	g++ $(PWD)/UserSpace/UserSpace.cpp -o $(PWD)/UserSpace/$(USER_SPACE_TARGET)

# Kernel module build
KMOD:
	-rmmod mymodule
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "lsmod:"
	-lsmod | grep mymodule
	insmod mymodule.ko
	-echo "----------"
	-echo "lsmod:"
	-lsmod | grep mymodule

all: USER_SPACE KMOD


clean:
	-pkill -9 $(USER_SPACE_TARGET)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rmmod mymodule
	-rm -f $(PWD)/UserSpace/$(USER_SPACE_TARGET)