from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization


def generate_keypair(
    private_key_path: Path,
    public_key_path: Path,
) -> None:
    """Generate an Ed25519 keypair and write both PEM files."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def main() -> None:
    priv = Path("private_key.pem")
    pub = Path("public_key.pem")
    generate_keypair(priv, pub)
    print(f"Keys written: {priv}, {pub}")
    print("Copy public_key.pem to each client machine.")


if __name__ == "__main__":
    main()
