import hashlib

import pytest
from src.app.file_utils import load_file_contents, save_file_contents, split_file_into_chunks, validate_file_hash, \
    hash_file, get_sorted_chunk_files, reassemble_file


def test_load_file_contents(tmp_path):
    # Create a temporary file with known content
    test_file = tmp_path / "test.txt"
    test_content = "Hello, world!"
    test_file.write_text(test_content)

    # Use the function to load the file contentsa
    loaded_content = load_file_contents(test_file)

    # Assert that the loaded content matches the expected content
    assert loaded_content == test_content


def test_load_file_contents_file_not_found():
    # Test loading a non-existent file
    non_existent_file = "non_existent_file.txt"

    with pytest.raises(FileNotFoundError):
        load_file_contents(non_existent_file)


def test_save_file_contents(tmp_path):
    # Define the file path and content to save
    test_file = tmp_path / "test_save.txt"
    test_content = "This is a test."

    # Use the function to save the file contents
    save_file_contents(test_file, test_content)

    # Read the file directly to verify its contents
    saved_content = test_file.read_text()

    # Assert that the saved content matches the expected content
    assert saved_content == test_content




def test_split_file_into_chunks(tmp_path):
    # Create a temporary binary file with known content
    test_file = tmp_path / "test.bin"
    test_data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # 26 bytes
    test_file.write_bytes(test_data)

    # Define chunk size
    chunk_size = 10

    # Use the function to split the file into chunks
    chunks = list(split_file_into_chunks(test_file, chunk_size))

    # Assert that the correct number of chunks were created
    assert len(chunks) == 3

    # Assert the contents of each chunk
    assert chunks[0]["data"] == b"ABCDEFGHIJ"
    assert chunks[1]["data"] == b"KLMNOPQRST"
    assert chunks[2]["data"] == b"UVWXYZ"

    # Assert the sizes of each chunk
    assert chunks[0]["size"] == 10
    assert chunks[1]["size"] == 10
    assert chunks[2]["size"] == 6


def test_get_sorted_chunk_files(tmp_path):
    # Create a temporary directory with chunk files
    chunk_dir = tmp_path / "chunks"
    chunk_dir.mkdir()

    # Create chunk files with different IDs
    (chunk_dir / "chunk_2.bin").write_text("Chunk 2")
    (chunk_dir / "chunk_10.bin").write_text("Chunk 10")
    (chunk_dir / "chunk_1.bin").write_text("Chunk 1")

    # Use the function to get sorted chunk files
    sorted_files = get_sorted_chunk_files(chunk_dir, chunk_prefix="chunk_")

    # Assert that the files are sorted correctly
    expected_order = [
        "chunk_1.bin",
        "chunk_2.bin",
        "chunk_10.bin",
    ]

    assert sorted_files == expected_order


def test_successful_reassembly(tmp_path):
    """Tests if the file is reassembled correctly with all chunks present."""

    # Create a temporary directory with chunk files
    chunk_dir = tmp_path / "chunks"
    chunk_dir.mkdir()

    # Create chunk files with known content
    (chunk_dir / "chunk_01.bin").write_bytes(b"This is the first part.")
    (chunk_dir / "chunk_02.bin").write_bytes(b"This is the middle part.")
    (chunk_dir / "chunk_03.bin").write_bytes(b"This is the end part.")

    sorted_chunks = ["chunk_01.bin", "chunk_02.bin", "chunk_03.bin"]

    # Define output file path
    output_file = tmp_path / "reassembled.dat"

    # Call the function to reassemble the file
    reassemble_file(sorted_chunks, str(output_file), str(chunk_dir))

    # Verify the output file exists
    assert output_file.exists(), "Output file was not created."

    # Verify the content of the output file
    expected_content = b"This is the first part.This is the middle part.This is the end part."
    reassembled_data = output_file.read_bytes()


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

