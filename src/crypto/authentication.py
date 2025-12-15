import os
from quantcrypt.dss import MLDSA_87
from quantcrypt.kem import MLKEM_1024


def save_keys(private_key: bytes, public_key: bytes, key_owner: str):
    base_dir = os.path.join(os.path.dirname(__file__), "..", "keys", key_owner)
    os.makedirs(base_dir, exist_ok=True)
    priv_path = os.path.join(base_dir, "private.key")
    pub_path = os.path.join(base_dir, "public.key")
    with open(priv_path, "wb") as f:
        f.write(private_key)
    with open(pub_path, "wb") as f:
        f.write(public_key)
    return priv_path, pub_path


def load_keys(key_owner):
    base_dir = os.path.join(os.path.dirname(__file__), "..", "keys", key_owner)
    os.makedirs(base_dir, exist_ok=True)
    return load_private_key(key_owner), load_public_key(key_owner)


def load_private_key(key_owner):
    base_dir = os.path.join(os.path.dirname(__file__), "..", "keys", key_owner)
    path = os.path.join(base_dir, "private.key")
    with open(path, "rb") as f:
        return f.read()


def load_public_key(key_owner):
    base_dir = os.path.join(os.path.dirname(__file__), "..", "keys", key_owner)
    path = os.path.join(base_dir, "public.key")
    with open(path, "rb") as f:
        return f.read()


def gen_and_save_keys(key_owner):
    private_key, public_key = generate_keys()
    priv_path, pub_path = save_keys(private_key, public_key, key_owner)
    return priv_path, pub_path


def generate_keys() -> tuple:
    """
    Generate a public-private key pair using the MLKEM_1024 key encapsulation mechanism.

    :return: A tuple containing the public key and private key.
    """
    kem = MLKEM_1024()
    public_key, private_key = kem.keygen()
    return private_key, public_key


def sign(message: bytes, secret_key: bytes) -> bytes:
    """
    Sign a message using the MLDSA_87 digital signature algorithm.

    :param private_key: The private key used for signing.
    :param message: The message to be signed.
    :return: The digital signature.
    """
    dss = MLDSA_87()

    signature = dss.sign(secret_key, message)
    return signature


def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """
    Verify a digital signature using the MLDSA_87 digital signature algorithm.

    :param public_key: The public key used for verification.
    :param message: The original message that was signed.
    :param signature: The digital signature to be verified.
    :return: True if the signature is valid, False otherwise.
    """
    dss = MLDSA_87()

    is_valid = dss.verify(public_key, message, signature)
    return is_valid


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python authentication.py <user1> [<user2> ...]")
        sys.exit(1)
    for user in sys.argv[1:]:
        priv_path, pub_path = gen_and_save_keys(user)
        print(f"Keys generated for {user}:")
        print(f"  Private key: {os.path.normpath(priv_path)}")
        print(f"  Public key:  {os.path.normpath(pub_path)}")
