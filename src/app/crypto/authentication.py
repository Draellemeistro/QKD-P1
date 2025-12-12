from quantcrypt.dss import MLDSA_87
from quantcrypt.kem import MLKEM_1024


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
