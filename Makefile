obj-m += main.o

PWD := $(CURDIR)

all:
	-rmmod main
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	echo "lsmod:"
	-lsmod | grep main
	insmod main.ko
	echo "----------"
	echo "lsmod:"
	lsmod | grep main


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	-rmmod main