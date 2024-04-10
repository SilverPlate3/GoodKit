PWD := $(CURDIR)
USER_SPACE_TARGET := user_app_poc

USER_SPACE:
#	g++ -o $(PWD)/UserSpace__StillUnderDev/$(USER_SPACE_TARGET) $(PWD)/UserSpace__StillUnderDev/UserSpace.cpp $(PWD)/UserSpace__StillUnderDev/Menu.cpp $(PWD)/UserSpace__StillUnderDev/Ioctl.cpp $(PWD)/UserSpace__StillUnderDev/Alerts.cpp $(PWD)/UserSpace__StillUnderDev/ConfigParser/ConfigParser.cpp  $(PWD)/UserSpace__StillUnderDev/UserSpaceRulesRepresentation.cpp
	g++ $(PWD)/UserSpace_POC/UserSpace_POC.cpp -o $(PWD)/UserSpace_POC/$(USER_SPACE_TARGET)

all: USER_SPACE 
	$(MAKE) -C Kernel $@

clean: 
	$(MAKE) -C Kernel $@
	-pkill -9 $(USER_SPACE_TARGET)
	-rm -f $(PWD)/UserSpace_POC/$(USER_SPACE_TARGET)
	-rm -f $(PWD)/UserSpace__StillUnderDev/$(USER_SPACE_TARGET)