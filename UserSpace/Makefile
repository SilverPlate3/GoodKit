PWD := $(CURDIR)
USER_SPACE_TARGET := user_app

USER_SPACE:
	g++ -o $(PWD)/$(USER_SPACE_TARGET) $(PWD)/UserSpace.cpp $(PWD)/Menu.cpp $(PWD)/Ioctl.cpp $(PWD)/Alerts.cpp $(PWD)/ConfigParser/ConfigParser.cpp  $(PWD)/UserSpaceRulesRepresentation.cpp

all: USER_SPACE 

clean: 
	-pkill -9 $(USER_SPACE_TARGET)
	-rm -f $(PWD)/$(USER_SPACE_TARGET)