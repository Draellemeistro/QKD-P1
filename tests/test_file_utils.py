import hashlib

import pytest
from src.app.file_utils import load_file_contents, save_file_contents, split_file_into_chunks, validate_file_hash, \
    hash_file, get_sorted_chunk_files, reassemble_file

def test_split_file_into_chunks(tmp_path):
    # 1. Create a dummy file (100 bytes)
    file_path = tmp_path / "test_split.bin"
    data = b"x" * 100
    file_path.write_bytes(data)

    # 2. Split into chunks of 30 bytes
    chunk_size = 30
    chunks = list(split_file_into_chunks(file_path, chunk_size))

    # 3. Assertions
    assert len(chunks) == 4  # 30 + 30 + 30 + 10 = 100 bytes
    assert chunks[0]["data"] == b"x" * 30
    assert chunks[3]["data"] == b"x" * 10  # Last chunk is smaller
    assert chunks[0]["id"] == 0
    assert chunks[3]["id"] == 3




def test_hash_file(tmp_path):
    # Create a temporary file with known content
    test_file = tmp_path / "test_hash.txt"
    test_content = b"Hash me!"
    test_file.write_bytes(test_content)
    hash_algorithm = "sha256"

    # Compute the expected hash using hashlib directly
    expected_hash = hashlib.sha256(test_content).hexdigest()

    # Specify hash_algorithm and use the function to hash the file
    computed_hash = hash_file(test_file, hash_algorithm)


    # Assert that the computed hash matches the expected hash
    assert computed_hash == expected_hash

def test_validate_file_hash(tmp_path):
    # Create a temporary file with known content
    test_file = tmp_path / "test_validate.txt"
    test_content = b"Validate me!"
    test_file.write_bytes(test_content)

    # Compute the expected hash using hashlib directly
    expected_hash = hashlib.sha256(test_content).hexdigest()

    # Use the function to validate the file hash
    is_valid = validate_file_hash(test_file, expected_hash, "sha256")

    # Assert that the hash validation returns True
    assert is_valid

    # Test with an incorrect expected hash
    incorrect_hash = "incorrecthashvalue"
    is_valid_incorrect = validate_file_hash(test_file, incorrect_hash, "sha256")

    # Assert that the hash validation returns False for incorrect hash
    assert not is_valid_incorrect

