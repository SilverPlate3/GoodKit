import os
import select
import subprocess
import time

def read_nonblocking(fd):
    output = []
    while True:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if not ready:
            break

        data = os.read(fd, 1024)
        if not data:
            break
        output.append(data.decode('utf-8'))
    
    return ''.join(output)

def sucessfull_command_doesnt_trigger_kmod(command, user_app_proc):
    # Ensure no prevention
    proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(1)
    proc.kill()
    error = read_nonblocking(proc.stderr.fileno()).strip()
    assert "Operation not permitted" not in error, f"Error: not expected 'Operation not permitted' in error, got: '{error}'"

    # Ensure no alert
    output = read_nonblocking(user_app_proc.stdout.fileno()).strip()
    assert output == "", f"Error: expected empty output, got: '{output}'"


def ensure_command_prevented(command):
    proc = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(0.5)
    output = read_nonblocking(proc.stdout.fileno()).strip()
    error = read_nonblocking(proc.stderr.fileno()).strip()
    assert len(output) == 0, f"Error: expected empty output, got: '{output}'"
    assert "Operation not permitted" in error, f"Error: expected 'Operation not permitted' in error, got: '{error}'"