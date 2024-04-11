PWD := $(CURDIR)
USER_SPACE_POC_TARGET := user_app_poc

USER_SPACE_POC:
	g++ $(PWD)/UserSpace_POC/UserSpace_POC.cpp -o $(PWD)/UserSpace_POC/$(USER_SPACE_POC_TARGET)

all: USER_SPACE_POC 
	$(MAKE) -C UserSpace__StillUnderDev $@
	$(MAKE) -C Kernel $@

clean: 
	$(MAKE) -C UserSpace__StillUnderDev $@
	-pkill -9 $(USER_SPACE_POC_TARGET)
	-rm -f $(PWD)/UserSpace_POC/$(USER_SPACE_POC_TARGET)
	$(MAKE) -C Kernel $@