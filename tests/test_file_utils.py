import pytest
import os
import hashlib
from src.app.file_utils import (
    split_file_into_chunks,
    FileStreamWriter,
    hash_file,
    validate_file_hash
)


# --- 1. CHUNKING TESTS ---

def test_split_file_into_chunks(tmp_path):
    """
    Verifies that a binary file is correctly split into smaller chunks,
    preserving order and handling the remainder (last chunk) correctly.
    """
    # 1. Setup: Create a dummy file (10 bytes)
    file_path = tmp_path / "test_split.bin"
    # Content: 0123456789
    file_content = b"0123456789"
    file_path.write_bytes(file_content)

    # 2. Execute: Split into 3-byte chunks
    chunk_size = 3
    generator = split_file_into_chunks(str(file_path), chunk_size)
    chunks = list(generator)

    # 3. Assertions
    # We expect 4 chunks: [012], [345], [678], [9]
    assert len(chunks) == 4

    # Check Chunk 0
    assert chunks[0]["id"] == 0
    assert chunks[0]["data"] == b"012"
    assert chunks[0]["size"] == 3

    # Check Chunk 1
    assert chunks[1]["id"] == 1
    assert chunks[1]["data"] == b"345"

    # Check Last Chunk (Remainder)
    assert chunks[3]["id"] == 3
    assert chunks[3]["data"] == b"9"
    assert chunks[3]["size"] == 1


def test_split_file_not_found():
    """Verifies that the function handles missing files gracefully."""
    generator = split_file_into_chunks("non_existent_file.txt", 1024)
    # Should yield nothing (empty list) or handle error
    chunks = list(generator)
    assert len(chunks) == 0


# --- 2. WRITER TESTS ---

def test_file_stream_writer(tmp_path):
    """
    Verifies that FileStreamWriter appends data sequentially
    and saves it to disk correctly.
    """
    output_path = tmp_path / "reconstructed.bin"

    # Use the context manager
    with FileStreamWriter(str(output_path)) as writer:
        writer.append(b"Hello ")
        writer.append(b"World")
        writer.append(b"!")

    # Verify content
    assert output_path.exists()
    assert output_path.read_bytes() == b"Hello World!"


def test_file_stream_writer_creates_dirs(tmp_path):
    """
    Verifies that the writer automatically creates missing subdirectories.
    """
    # Path in a sub-folder that doesn't exist yet
    output_path = tmp_path / "subdir" / "deep" / "output.txt"

    with FileStreamWriter(str(output_path)) as writer:
        writer.append(b"test")

    assert output_path.exists()
    assert output_path.read_bytes() == b"test"


# --- 3. HASHING TESTS ---

def test_hash_file_sha256(tmp_path):
    """
    Verifies that the mmap-based hashing produces the standard SHA-256 hash.
    """
    test_file = tmp_path / "data.txt"
    content = b"The quick brown fox jumps over the lazy dog"
    test_file.write_bytes(content)

    # Calculate expected hash using standard library
    expected_hash = hashlib.sha256(content).hexdigest()

    # Calculate using our utility
    computed_hash = hash_file(str(test_file), "sha256")

    assert computed_hash == expected_hash


def test_hash_empty_file(tmp_path):
    """
    Verifies edge case: Hashing an empty file (mmap can crash on size 0).
    Your implementation has a specific check for this.
    """
    empty_file = tmp_path / "empty.txt"
    empty_file.touch()

    # SHA256 of empty string
    expected_hash = hashlib.sha256(b"").hexdigest()

    computed_hash = hash_file(str(empty_file))

    assert computed_hash == expected_hash


def test_validate_file_hash(tmp_path):
    """Verifies the boolean validation helper."""
    test_file = tmp_path / "check.txt"
    test_file.write_bytes(b"verify me")

    valid_hash = hashlib.sha256(b"verify me").hexdigest()
    invalid_hash = "deadbeef" * 8

    assert validate_file_hash(str(test_file), valid_hash) is True
    assert validate_file_hash(str(test_file), invalid_hash) is False