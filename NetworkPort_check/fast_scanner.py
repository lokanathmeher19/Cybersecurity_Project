import socket
import threading
from queue import Queue
from datetime import datetime

print_lock = threading.Lock()
target = ""
queue = Queue()
open_ports = []

def port_scan(port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5) 
        result = s.connect_ex((target, port))
        if result == 0:
            with print_lock:
                print(f"Port {port}: OPEN")
                open_ports.append(port)
        s.close()
    except:
        pass

def threader():
    while True:
        worker = queue.get()
        port_scan(worker)
        queue.task_done()

if __name__ == "__main__":
    target = input("Enter Target IP: ")
    print(f"Scanning target: {target}")
    print(f"Time started: {datetime.now()}")

    for x in range(100):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()
    
    for worker in range(1, 1025):
        queue.put(worker)
    
    queue.join()

    print(f"Time finished: {datetime.now()}")
