import hashlib
import socket
import uuid


def get_machine_fingerprint() -> str:
    hostname = socket.gethostname()
    mac = uuid.getnode()
    raw = f"{hostname}-{mac}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


if __name__ == "__main__":
    print(get_machine_fingerprint())
