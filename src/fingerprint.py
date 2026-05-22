import hashlib
import socket
import uuid


def get_machine_fingerprint() -> str:
    raw = f"{socket.gethostname()}-{uuid.getnode()}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
