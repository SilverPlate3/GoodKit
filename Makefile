PWD := $(CURDIR)

all:
	$(MAKE) -C UserSpace $@
	$(MAKE) -C Kernel $@

clean: 
	$(MAKE) -C UserSpace $@
	$(MAKE) -C Kernel $@