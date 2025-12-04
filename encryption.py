from cryptography.fernet import Fernet
import os
from shutil import copyfile

# Generate a key (run this once to create the key file)
def generate_key():
    """
    Generates a secret encryption key and saves it to 'secret.key'.
    Run this only once to initialize the key file.
    """
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Load the encryption key
def load_key():
    """
    Loads the secret encryption key from 'secret.key'.
    Raises an error if the key file is missing.
    """
    if not os.path.exists("secret.key"):
        raise FileNotFoundError("Encryption key not found! Please generate it first.")
    with open("secret.key", "rb") as key_file:
        return key_file.read()

# Encrypt a file
def encrypt_file(input_path):
    """
    Encrypts the file located at 'input_path' using the secret key.
    The encrypted file is saved with a '.txt' extension.
    Returns the path to the encrypted file.
    """
    key = load_key()
    fernet = Fernet(key)

    with open(input_path, "rb") as file:
        original_data = file.read()

    # Encrypt the file content
    encrypted_data = fernet.encrypt(original_data)

    # Save encrypted file with ".txt" extension
    encrypted_path = input_path + "_encrypted.txt"
    with open(encrypted_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    return encrypted_path

# Decrypt a file
def decrypt_file(input_path):
    """
    Decrypts the file located at 'input_path' using the secret key.
    The decrypted file is saved with "_decrypted.txt".
    Returns the path to the decrypted file in the static folder for downloading.
    """
    key = load_key()
    fernet = Fernet(key)

    # Read the encrypted file
    with open(input_path, "rb") as encrypted_file:
        encrypted_data = encrypted_file.read()

    try:
        # Attempt to decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception as e:
        raise ValueError(f"Failed to decrypt the file: {e}")

    # Create a base name for the decrypted file
    # Input: test.pdf_encrypted.txt
    # Splitext: test.pdf_encrypted
    base_name = os.path.splitext(os.path.basename(input_path))[0]
    
    if base_name.endswith("_encrypted"):
        original_name = base_name.replace("_encrypted", "") # test.pdf
    else:
        original_name = base_name # Fallback

    # Save decrypted content with original extension
    decrypted_filename = f"decrypted_{original_name}"
    decrypted_path = os.path.join(os.path.dirname(input_path), decrypted_filename)
    
    with open(decrypted_path, "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)

    # Ensure static folder exists
    static_folder = os.path.join("static", "decrypted")
    os.makedirs(static_folder, exist_ok=True)
    
    # Copy the decrypted file to the static directory for downloading
    static_path = os.path.join(static_folder, decrypted_filename)
    copyfile(decrypted_path, static_path)

    # Return the path relative to the static folder for use in templates
    return os.path.join("decrypted", decrypted_filename)