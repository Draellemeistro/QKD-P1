import pytest
from src.app.file_utils import load_file_contents, save_file_contents


def test_load_file_contents(tmp_path):
    # Create a temporary file with known content
    test_file = tmp_path / "test.txt"
    test_content = "Hello, world!"
    test_file.write_text(test_content)

    # Use the function to load the file contents
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
    from src.app.file_utils import split_file_into_chunks

    # Create a temporary binary file with known content
    test_file = tmp_path / "test.bin"
    test_content = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # 26 bytes
    test_file.write_bytes(test_content)

    # Define chunk size
    chunk_size = 10  # bytes

    # Use the function to split the file into chunks
    chunks = list(split_file_into_chunks(test_file, chunk_size))

    # Assert that the correct number of chunks were created
    assert len(chunks) == 3

    # Assert the contents of each chunk
    assert chunks[0]['data'] == b"ABCDEFGHIJ"
    assert chunks[1]['data'] == b"KLMNOPQRST"
    assert chunks[2]['data'] == b"UVWXYZ"


def test_reassemble_file(tmp_path):
    from src.app.file_utils import reassemble_file

    # Create a temporary directory for chunks
    chunk_dir = tmp_path / "chunks"
    chunk_dir.mkdir()

    # Create some chunk files
    chunk_contents = [b"ABCDEFGHIJ", b"KLMNOPQRST", b"UVWXYZ"]
    for i, content in enumerate(chunk_contents):
        chunk_file = chunk_dir / f"chunk_{i}.bin"
        chunk_file.write_bytes(content)

    # Define the output file path
    output_file = tmp_path / "reassembled.bin"

    # Use the function to reassemble the file
    reassemble_file(output_file, chunk_dir)

    # Read the reassembled file
    reassembled_content = output_file.read_bytes()

    # Assert that the reassembled content matches the original content
    expected_content = b"".join(chunk_contents)
    assert reassembled_content == expected_content

