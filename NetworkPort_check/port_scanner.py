import socket
import sys
from datetime import datetime

def scan_target(target):
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Hostname could not be resolved.")
        sys.exit()

    print(f"Scanning Target: {target_ip}")
    print(f"Time Started: {datetime.now()}")

    try:
        for port in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"Port {port}: OPEN")
            sock.close()

    except KeyboardInterrupt:
        print("Exiting Program.")
        sys.exit()
    except socket.error:
        print("Could not connect to server.")
        sys.exit()

if __name__ == "__main__":
    target = input("Enter Target IP: ")
    scan_target(target)
