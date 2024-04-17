import os
import select

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