import subprocess
import ProcessUtils
import time


def ensure_number_of_exclusions_and_rules(delemeter, number):
    output = get_output_from_successful_dmesg()
    parts = output.split(delemeter)
    assert len(parts) >= 2, f"Error: expected >= 2 parts, got {len(parts)}"
    last_part = parts[-1]
    count_add_rule = last_part.count("good_kit_rules_ioctl_main_callback - ADD_RULE")
    count_add_binary_exclusion = last_part.count("good_kit_exclusions_file_open - ADD_BINARY_EXCLUSION")
    assert count_add_rule == number, f"Error: expected {number} ADD_RULE, got {count_add_rule}"
    assert count_add_binary_exclusion == number, f"Error: expected {number} ADD_RULE, got {count_add_binary_exclusion}"
    

def ensure_rules_and_exclusions():
    output = get_output_from_successful_dmesg()
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

    expected_output = """
-------- printing exclusions: --------
binary_path: *journald*
binary_path: /usr/bin/sudo
binary_path: *systemd-oomd
binary_path: *node"""
    assert expected_output in output, f"Error: expected {expected_output}\ngot: {output}"


def get_output_from_successful_dmesg():
    dmesg_proc = subprocess.Popen("sudo dmesg -t | tail -200", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    output = ProcessUtils.read_nonblocking(dmesg_proc.stdout.fileno()).strip()
    error = ProcessUtils.read_nonblocking(dmesg_proc.stderr.fileno()).strip()
    assert error == "", f"Error: stderr not empty. got: '{error}'"
    return output