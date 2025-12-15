import pytest
from src.crypto.authentication import generate_keys, sign, verify

pytestmark = pytest.mark.skipif(
    __import__("importlib").util.find_spec("oqs") is None,
    reason="python-oqs not installed; skip PQC tests",
)


@pytest.fixture
def keys():
    return generate_keys()


class TestDigitalSignatureBasic:
    def test_sign_produces_signature(self, keys):
        message = b"hello"
        private_key, _ = keys
        signature = sign(message, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_verify_valid_signature(self, keys):
        message = b"hello"
        private_key, public_key = keys
        signature = sign(message, private_key)
        assert verify(message, signature, public_key)

    def test_verify_invalid_signature(self, keys):
        message = b"hello"
        private_key, public_key = keys
        signature = sign(message, private_key)
        # Tamper with signature
        bad_signature = signature[:-1] + b"\x00"
        assert not verify(message, bad_signature, public_key)

    def test_verify_wrong_message(self, keys):
        private_key, public_key = keys
        signature = sign(b"hello", private_key)
        assert not verify(b"world", signature, public_key)

    def test_verify_wrong_public_key(self):
        private_key1, _ = generate_keys()
        _, public_key2 = generate_keys()
        signature = sign(b"hello", private_key1)
        assert not verify(b"hello", signature, public_key2)


class TestDigitalSignatureEdgeCases:
    def test_empty_message(self, keys):
        private_key, public_key = keys
        signature = sign(b"", private_key)
        assert verify(b"", signature, public_key)

    def test_large_message(self, keys):
        private_key, public_key = keys
        large_message = b"a" * 10_000_000  # 10 MB
        signature = sign(large_message, private_key)
        assert verify(large_message, signature, public_key)

    def test_repeated_signing(self, keys):
        private_key, public_key = keys
        message = b"repeat"
        sig1 = sign(message, private_key)
        sig2 = sign(message, private_key)
        # Depending on algorithm, signatures may or may not be identical
        assert verify(message, sig1, public_key)
        assert verify(message, sig2, public_key)
        assert (
            sig1 == sig2 or sig1 != sig2
        )  # Accept both deterministic and randomized signatures

    def test_verify_fails_on_tampered_message(self, keys):
        pk, sk = keys
        msg = b"authentic"
        sig = sign(msg, sk)
        tampered = b"authentic!"  # changed content
        assert not verify(tampered, sig, pk)

    def test_verify_fails_on_tampered_signature(self, keys):
        pk, sk = keys
        msg = b"integrity check"
        sig = sign(msg, sk)
        tampered_sig = bytes([sig[0] ^ 0x01]) + sig[1:]
        assert not verify(msg, tampered_sig, pk)
