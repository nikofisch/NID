from __future__ import annotations

import socket
import sys
import time

TARGET_HOST = "target"
TARGET_PORTS = [22, 23, 80, 443, 8080, 8443, 3306]


def normal_traffic() -> None:
    for i in range(10):
        with socket.create_connection((TARGET_HOST, 8000), timeout=1.0):
            time.sleep(0.2)
    print("normal traffic simulation complete")


def scan_like_traffic() -> None:
    for port in TARGET_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((TARGET_HOST, port))
            print(f"connected to port {port}")
        except OSError:
            pass
        finally:
            s.close()
    print("scan simulation complete")


def brute_force_traffic() -> None:
    for _ in range(8):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            s.connect((TARGET_HOST, 22))
            print("connection attempt to port 22")
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(0.1)
    print("brute-force simulation complete")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"
    if mode == "scan":
        scan_like_traffic()
    elif mode == "bruteforce":
        brute_force_traffic()
    else:
        normal_traffic()
