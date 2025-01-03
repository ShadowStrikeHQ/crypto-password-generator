import os
import logging
import argparse
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
import secrets

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Set up command-line argument parsing.
    
    Returns:
        argparse.ArgumentParser: Configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="crypto-password-generator: Generate random, secure passwords using cryptographic operations."
    )
    parser.add_argument(
        "-l", "--length", type=int, default=16,
        help="Length of the generated password (default: 16)."
    )
    parser.add_argument(
        "-s", "--salt", type=str, default=None,
        help="Custom salt for the password generation (default: random salt)."
    )
    parser.add_argument(
        "-i", "--iterations", type=int, default=100000,
        help="Number of PBKDF2 iterations (default: 100000)."
    )
    parser.add_argument(
        "-v", "--version", action="version", version="crypto-password-generator 1.0",
        help="Show the version of the tool."
    )
    return parser

def generate_password(length, salt=None, iterations=100000):
    """
    Generate a secure password using PBKDF2 and cryptographic randomness.

    Args:
        length (int): Length of the password.
        salt (str): Custom salt or None for a random salt.
        iterations (int): Number of PBKDF2 iterations.

    Returns:
        str: The generated password.
    """
    if length <= 0:
        raise ValueError("Password length must be greater than 0.")
    
    # Generate a random salt if not provided
    if salt is None:
        salt = secrets.token_bytes(16)
    else:
        salt = salt.encode()
    
    # Derive a key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(secrets.token_bytes(16))
    
    # Encode the derived key to a URL-safe base64 string
    password = urlsafe_b64encode(key).decode('utf-8')[:length]
    return password

def main():
    """
    Main entry point of the application.
    """
    parser = setup_argparse()
    args = parser.parse_args()
    
    try:
        logging.info("Starting password generation...")
        password = generate_password(args.length, args.salt, args.iterations)
        logging.info("Password generation completed.")
        print(f"Generated Password: {password}")
    except ValueError as ve:
        logging.error(f"ValueError: {ve}")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()