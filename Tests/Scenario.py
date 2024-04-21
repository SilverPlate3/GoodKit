import subprocess
import os
import time

import Menu
import ProcessUtils
import dmesg
import TestSetup

def ensure_expected_alert(expected_output):
    output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
    error = ProcessUtils.read_nonblocking(user_app_proc.stderr.fileno()).strip()
    assert error == "", f"Error: stderr not empty. got: '{error}'"
    assert output == expected_output, f"Error: expected {expected_output}\ngot: {output}"

TestSetup.ensure_setup()

# Start the user_app process
command = ["sudo", TestSetup.get_user_space_binary_path()]
user_app_proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Check the menu
time.sleep(0.5)
Menu.EnsureStdOutIsMenu(user_app_proc)

# Check delete when 0 rules doesn't break anything
Menu.SendOptionToMenu(user_app_proc, 2)

# Check the request for a json path
Menu.SendOption1ToMenu(user_app_proc, "/home/ariel/Desktop/KernelDev/GoodKit/UserSpace/example_config1.json")

# Check the menu after inserting the json path
Menu.EnsureStdOutIsMenu(user_app_proc)

# Check that 4 rules and 4 exclusions were added as specifid in the json. Check via dmesg
dmesg.ensure_number_of_exclusions_and_rules("Finished hooking syscall table", 4)

# Check ping 8.8.8.8 no prevention no alert
ProcessUtils.sucessfull_command_doesnt_trigger_kmod("ping 8.8.8.8", user_app_proc)

# Check ping 9.9.9.9 prevention
ProcessUtils.ensure_command_prevented("/bin/ping 9.9.9.9")

# Check ping 9.9.9.9 alert
expected_ping_alert = """--------- RECEIVED ALERT ---------
Matched on execve rule:
binary_path: *ping
full_command: *ping 9.9.*
prevention: 1
Malicious event:
binary_path: /bin/ping
full_command: /bin/ping 9.9.9.9
uid: 1000
gid: 1000
argc: 2"""
ensure_expected_alert(expected_ping_alert)

# Check usermod no prevention
usermod_proc = subprocess.Popen("usermod -aG root user", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
error = ProcessUtils.read_nonblocking(usermod_proc.stderr.fileno()).strip()
assert "Operation not permitted" not in error, f"Error: not expected 'Operation not permitted' in error, got: '{error}'"

# Check usermod alert
which_proc = subprocess.Popen("which usermod", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
usermode_location = ProcessUtils.read_nonblocking(which_proc.stdout.fileno()).strip()
expected_usermod_alert = f"""--------- RECEIVED ALERT ---------
Matched on execve rule:
full_command: usermod -aG root*
uid: 1000
gid: 1000
prevention: 0
Malicious event:
binary_path: {usermode_location.strip()}
full_command: usermod -aG root user
uid: 1000
gid: 1000
argc: 4"""
ensure_expected_alert(expected_usermod_alert)

# Check /etc/samba/smb.conf prevention
ProcessUtils.ensure_command_prevented("echo malicious >> /etc/samba/smb.conf")

# Check /etc/samba/smb.conf alert
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
expected_output = """--------- RECEIVED ALERT ---------
Matched on open rule:
target_path: /etc/samba/smb.conf
flags: 1
prevention: 1
Malicious event:"""
assert expected_output in output, f"Error: expected {expected_output}\ngot: {output}"
expected_output = """echo malicious >> /etc/samba/smb.conf
target_path: /etc/samba/smb.conf
uid: 1000
gid: 1000
mode:"""
assert expected_output in output, f"Error: expected {expected_output}\ngot: {output}"

# Print rules and exclusions
Menu.SendOptionToMenu(user_app_proc, 4)
Menu.SendOptionToMenu(user_app_proc, 5)

# Check printed rules and exclusions
dmesg.ensure_rules_and_exclusions()

# delete all rules and exclusions
Menu.SendOptionToMenu(user_app_proc, 2)
Menu.SendOptionToMenu(user_app_proc, 3)

# Check ping 9.9.9.9 no prevention and no alert
ProcessUtils.sucessfull_command_doesnt_trigger_kmod("ping 9.9.9.9", user_app_proc)

# Check writing yo smb.conf no prevention and no alert
ProcessUtils.sucessfull_command_doesnt_trigger_kmod("echo malicious >> /etc/samba/smb.conf", user_app_proc)

# Check the request for a json path
Menu.SendOption1ToMenu(user_app_proc, "/home/ariel/Desktop/KernelDev/GoodKit/UserSpace/example_config1.json")
Menu.EnsureStdOutIsMenu(user_app_proc)

Menu.SendOption1ToMenu(user_app_proc, "/home/ariel/Desktop/KernelDev/GoodKit/UserSpace/example_config2.json")
Menu.EnsureStdOutIsMenu(user_app_proc)

# Check that 6 rules and 6 exclusions were added as specifid in the two jsons. Check via dmesg
dmesg.ensure_number_of_exclusions_and_rules("printing exclusions", 6)

# Check ping 9.9.9.9 prevention
ProcessUtils.ensure_command_prevented("/bin/ping 9.9.9.9")

# Check ping 9.9.9.9 alert
ensure_expected_alert(expected_ping_alert)

# Check wget *Malicious.com prevention
ProcessUtils.ensure_command_prevented("/bin/wget -q https://VeryMalicious.com")

# Check wget *Malicious.com alert
expected_wget_alert = """--------- RECEIVED ALERT ---------
Matched on execve rule:
binary_path: */wget
full_command: *Malicious.com
argc: 3
prevention: 1
Malicious event:
binary_path: /bin/wget
full_command: /bin/wget -q https://VeryMalicious.com
uid: 1000
gid: 1000
argc: 3"""
ensure_expected_alert(expected_wget_alert)

# Check usermod no prevention and no alert as usermod is excluded in example_config2.json
ProcessUtils.sucessfull_command_doesnt_trigger_kmod("usermod -aG root user", user_app_proc)

# Unload the kernel module
user_app_proc.kill()
time.sleep(0.5)
TestSetup.ensure_unload_kernel_module()

print("All tests passed!")