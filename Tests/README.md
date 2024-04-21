Runs a test scenario that tests all the components in the LKM and in the UserSpace process. 

# How to run the scenario
```
git clone
sudo make all
python3 Tests/Scenario.py
```
Disclamer - The test is a bit hardcoded, so it must be run with a user with UID 1000 & GID 1000.
