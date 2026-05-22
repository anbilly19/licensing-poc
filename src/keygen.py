from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from pathlib import Path


def generate_keypair(private_path: Path, public_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


if __name__ == "__main__":
    generate_keypair(Path("private_key.pem"), Path("public_key.pem"))
    print("Keys written: private_key.pem, public_key.pem")
