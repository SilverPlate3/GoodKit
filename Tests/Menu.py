import time
import ProcessUtils

menu_string = '''Select an option by typing its number:
1 - Add rules and exclusions via json
2 - Delete all rules
3 - Delete all exclusions
4 - Print all rules (dmesg)
5 - Print all exclusions (dmesg)
6 - Clear CLI
Enter your choice:'''.strip()

def SendOption1ToMenu(user_app_proc, json_path):
    user_app_proc.stdin.write('1\n')
    user_app_proc.stdin.flush()
    output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
    error = ProcessUtils.read_nonblocking(user_app_proc.stderr.fileno()).strip()
    assert output == "Input json path:", f"Error: expected: 'Input json path:', got: '{output}'"
    assert error == "", f"Error: stderr not empty. got: '{error}'"
    user_app_proc.stdin.write(f"{json_path}\n")
    user_app_proc.stdin.flush()

def SendOptionToMenu(user_app_proc, option):
    user_app_proc.stdin.write(f'{option}\n')
    user_app_proc.stdin.flush()
    time.sleep(0.5)
    output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
    error = ProcessUtils.read_nonblocking(user_app_proc.stderr.fileno()).strip()
    assert error == "", f"Error: stderr not empty. got: '{error}'"
    EnsureStringIsMenu(output)

def EnsureStdOutIsMenu(user_app_proc):
    output = ProcessUtils.read_nonblocking(user_app_proc.stdout.fileno()).strip()
    error = ProcessUtils.read_nonblocking(user_app_proc.stderr.fileno()).strip()
    assert error == "", f"Error: stderr not empty. got: '{error}'"
    EnsureStringIsMenu(output)

def EnsureStringIsMenu(output):
    assert output == menu_string, f"Error: expected: '{menu_string}', got: '{output}'"

    