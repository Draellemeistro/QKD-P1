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
