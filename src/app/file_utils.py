import os

def load_file_contents(file_path):
    """Load and return the contents of a file."""
    with open(file_path, 'r') as file:
        return file.read()

def save_file_contents(file_path, contents):
    """Save the given contents to a file."""
    with open(file_path, 'w') as file:
        file.write(contents)