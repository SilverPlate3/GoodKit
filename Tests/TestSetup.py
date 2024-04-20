import subprocess
import os
module_name = "mymodule"

def ensure_setup():
    load_kernel_module()
    ensure_kernel_module_loaded()
    ensure_user_space_binary_exist()

def load_kernel_module():
    rmmod = subprocess.run(f"sudo rmmod {module_name}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    insmod = subprocess.run(f"sudo insmod {os.path.dirname(__file__)}/../Kernel/{module_name}.ko", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert insmod.returncode == 0, f"Error: insmod failed. stdout: '{insmod.stdout}', stderr: '{insmod.stderr}'"

def ensure_kernel_module_loaded():
    lsmod_output = subprocess.check_output(['lsmod'], text=True)
    assert module_name in lsmod_output, f"Error: The Goodkit kernel module '{module_name}' is not loaded. Please build the project with the Makefile. It should insmod the kmod automatically."

def ensure_user_space_binary_exist():
    binary_path = get_user_space_binary_path()
    assert os.path.exists(binary_path), f"Error: The user space binary '{binary_path}' does not exist. Please build the project with the Makefile."

def get_user_space_binary_path():
    relative_path = '../UserSpace__StillUnderDev/user_app'
    script_dir = os.path.dirname(__file__)
    binary_path = os.path.join(script_dir, relative_path)
    return binary_path