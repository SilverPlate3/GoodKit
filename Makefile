obj-m += mymodule.o
mymodule-objs := main.o StringUtils.o

PWD := $(CURDIR)

all:
	-rmmod mymodule
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "lsmod:"
	-lsmod | grep mymodule
	insmod mymodule.ko
	echo "----------"
	echo "lsmod:"
	lsmod | grep mymodule


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rmmod mymodule