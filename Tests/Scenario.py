import subprocess
import os
import time
import Menu
import ProcessUtils

module_name = "mymodule"

def load_kernel_module():
    rmmod = subprocess.run(f"sudo rmmod {module_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    insmod = subprocess.run(f"sudo insmod {os.path.dirname(__file__)}/../Kernel/{module_name}.ko", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert insmod.returncode == 0, f"Error: insmod failed. stdout: '{insmod.stdout}', stderr: '{insmod.stderr}'"

def ensure_kernel_module_loaded():
    lsmod_output = subprocess.check_output(['lsmod'], text=True)
    assert module_name in lsmod_output, f"Error: The Goodkit kernel module '{module_name}' is not loaded. Please build the project with the Makefile. It should insmod the kmod automatically."

def get_user_space_binary_path():
    relative_path = '../UserSpace__StillUnderDev/user_app'
    script_dir = os.path.dirname(__file__)
    binary_path = os.path.join(script_dir, relative_path)
    return binary_path

def ensure_user_space_binary_exist():
    binary_path = get_user_space_binary_path()
    assert os.path.exists(binary_path), f"Error: The user space binary '{binary_path}' does not exist. Please build the project with the Makefile."

load_kernel_module()
ensure_kernel_module_loaded()
ensure_user_space_binary_exist()

menu_string = '''Select an option by typing its number:
1 - Add rules and exclusions via json
2 - Delete all rules
3 - Delete all exclusions
4 - Print all rules (dmesg)
5 - Print all exclusions (dmesg)
6 - Clear CLI
Enter your choice:'''.strip()

# Start the user_app process
command = ["sudo", get_user_space_binary_path()]
user_app_proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

# Check the menu
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
Menu.EnsureStringIsMenu(output)

# Check delete when 0 rules doesn't break anything
Menu.SendOptionToMenu(user_app_proc, 2)

# Check the request for a json path
Menu.SendOption1ToMenu(user_app_proc, "/home/ariel/Desktop/KernelDev/GoodKit/UserSpace__StillUnderDev/example_config1.json")

# Check the menu after inserting the json path
Menu.EnsureStdOutIsMenu(user_app_proc)

# Check that 4 rules and 4 exclusions were added as specifid in the json. Check via dmesg
dmseg_proc = subprocess.Popen("sudo dmesg -t | tail -200", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(dmseg_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(dmseg_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
parts = output.split("Finished hooking syscall table")
assert len(parts) >= 2, f"Error: expected >= 2 parts, got {len(parts)}"
last_part = parts[-1]
count_add_rule = last_part.count("good_kit_rules_ioctl_main_callback - ADD_RULE")
count_add_binary_exclusion = last_part.count("good_kit_exclusions_file_open - ADD_BINARY_EXCLUSION")
assert count_add_rule == 4, f"Error: expected 4 ADD_RULE, got {count_add_rule}"
assert count_add_binary_exclusion == 4, f"Error: expected 4 ADD_RULE, got {count_add_binary_exclusion}"

# Check ping 8.8.8.8 no prevention
allowed_ping_proc = subprocess.Popen("ping 8.8.8.8", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(1)
allowed_ping_proc.kill()
output = ProcessUtils.read_nonblocking(allowed_ping_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(allowed_ping_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
assert output != "", f"Error: expected output, got empty"

# Check ping 8.8.8.8 no alert
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
assert output == "", f"Error: expected empty output, got: '{output}'"


# Check ping 9.9.9.9 prevention
prevented_ping = subprocess.Popen("/bin/ping 9.9.9.9", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(prevented_ping.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(prevented_ping.stderr.fileno()).strip()
assert len(output) == 0, f"Error: expected empty output, got: '{output}'"
assert "Operation not permitted" in error, f"Error: expected 'Operation not permitted' in error, got: '{error}'"

# Check ping 9.9.9.9 alert
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(user_app_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
expected_output = """--------- RECEIVED ALERT ---------
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
assert output == expected_output, f"Error: expected {expected_output}\ngot: {output}"

# Check usermod no prevention
which_proc = subprocess.Popen("which usermod", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
usermode_location = ProcessUtils.read_nonblocking(which_proc.stdout.fileno()).strip()
assert usermode_location != "", f"Error: expected usermod location, got empty"
usermod_proc = subprocess.Popen("usermod -aG root user", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
error = ProcessUtils.read_nonblocking(usermod_proc.stderr.fileno()).strip()
assert "Operation not permitted" not in error, f"Error: expected 'Operation not permitted' in error, got: '{error}'"

# Check usermod alert
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
expected_output = f"""--------- RECEIVED ALERT ---------
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
assert output == expected_output, f"Error: expected {expected_output}\ngot: {output}"

# Check /etc/samba/smb.conf prevention
echo_proc = subprocess.Popen("echo malicious >> /etc/samba/smb.conf", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(echo_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(echo_proc.stderr.fileno()).strip()
assert len(output) == 0, f"Error: expected empty output, got: '{output}'"
assert "Operation not permitted" in error, f"Error: expected 'Operation not permitted' in error, got: {error}"

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

# Check printed rules
dmseg_proc = subprocess.Popen("sudo dmesg -t | tail -200", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(dmseg_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(dmseg_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
expected_output = """
-------- printing rules: --------

-------- execve_rule -----------
binary_path: 
full_command: usermod -aG root*
uid: 1000
gid: 1000
argc: -1
prevention: 0

-------- execve_rule -----------
binary_path: *ping
full_command: *ping 9.9.*
uid: -999
gid: -999
argc: -1
prevention: 1

-------- open_rule -----------
binary_path: /usr/bin/nano
full_command: *nano*
target_path: /tmp/newMaliciousFile.txt
uid: 1000
gid: 1000
flags: 64
mode: 128
prevention: 0

-------- open_rule -----------
binary_path: 
full_command: 
target_path: /etc/samba/smb.conf
uid: -999
gid: -999
flags: 1
mode: -1
prevention: 1"""
assert expected_output in output, f"Error: expected {expected_output}\ngot: {output}"


# Check printed exclusions
expected_output = """
-------- printing exclusions: --------
binary_path: *journald*
binary_path: /usr/bin/sudo
binary_path: *systemd-oomd
binary_path: *node"""
assert expected_output in output, f"Error: expected {expected_output}\ngot: {output}"

#delete all rules and exclusions
Menu.SendOptionToMenu(user_app_proc, 2)
Menu.SendOptionToMenu(user_app_proc, 3)

# Check ping 9.9.9.9 no prevention
allowed_ping_proc = subprocess.Popen("ping 9.9.9.9", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(1)
allowed_ping_proc.kill()
output = ProcessUtils.read_nonblocking(allowed_ping_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(allowed_ping_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
assert output != "", f"Error: expected output, got empty"

# Check ping 9.9.9.9 no alert
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
assert output == "", f"Error: expected empty output, got: '{output}'"

# Check the request for a json path
Menu.SendOption1ToMenu(user_app_proc, "/home/ariel/Desktop/KernelDev/GoodKit/UserSpace__StillUnderDev/example_config1.json")
Menu.EnsureStdOutIsMenu(user_app_proc)

Menu.SendOption1ToMenu(user_app_proc, "/home/ariel/Desktop/KernelDev/GoodKit/UserSpace__StillUnderDev/example_config2.json")
Menu.EnsureStdOutIsMenu(user_app_proc)

# Check that 6 rules and 6 exclusions were added as specifid in the json. Check via dmesg
dmseg_proc = subprocess.Popen("sudo dmesg -t | tail -200", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(dmseg_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(dmseg_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
parts = output.split("printing exclusions")
assert len(parts) >= 2, f"Error: expected >= 2 parts, got {len(parts)}"
last_part = parts[-1]
count_add_rule = last_part.count("good_kit_rules_ioctl_main_callback - ADD_RULE")
count_add_binary_exclusion = last_part.count("good_kit_exclusions_file_open - ADD_BINARY_EXCLUSION")
assert count_add_rule == 6, f"Error: expected 6 ADD_RULE, got {count_add_rule}"
assert count_add_binary_exclusion == 6, f"Error: expected 6 ADD_RULE, got {count_add_binary_exclusion}"

# Check ping 9.9.9.9 prevention
prevented_ping = subprocess.Popen("/bin/ping 9.9.9.9", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(prevented_ping.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(prevented_ping.stderr.fileno()).strip()
assert len(output) == 0, f"Error: expected empty output, got: '{output}'"
assert "Operation not permitted" in error, f"Error: expected 'Operation not permitted' in error, got: '{error}'"

# Check ping 9.9.9.9 alert
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(user_app_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
expected_output = """--------- RECEIVED ALERT ---------
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
assert output == expected_output, f"Error: expected {expected_output}\ngot: {output}"


# Check wget *Malicious.com prevention
prevented_ping = subprocess.Popen("/bin/wget -q https://VeryMalicious.com", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
output = ProcessUtils.read_nonblocking(prevented_ping.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(prevented_ping.stderr.fileno()).strip()
assert len(output) == 0, f"Error: expected empty output, got: '{output}'"
assert "Operation not permitted" in error, f"Error: expected 'Operation not permitted' in error, got: '{error}'"

# Check wget *Malicious.com alert
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
error = ProcessUtils.read_nonblocking(user_app_proc.stderr.fileno()).strip()
assert error == "", f"Error: stderr not empty. got: '{error}'"
expected_output = """--------- RECEIVED ALERT ---------
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
assert output == expected_output, f"Error: expected {expected_output}\ngot: {output}"

# Check usermod no prevention
which_proc = subprocess.Popen("which usermod", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
usermode_location = ProcessUtils.read_nonblocking(which_proc.stdout.fileno()).strip()
assert usermode_location != "", f"Error: expected usermod location, got empty"
usermod_proc = subprocess.Popen("usermod -aG root user", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
time.sleep(0.5)
error = ProcessUtils.read_nonblocking(usermod_proc.stderr.fileno()).strip()
assert "Operation not permitted" not in error, f"Error: expected 'Operation not permitted' in error, got: '{error}'"

# Check usermod no alert as usermod is excluded in example_config2.json
output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
assert output == "", f"Error: expected empty output, got: '{output}'"