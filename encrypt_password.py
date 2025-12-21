#!/usr/bin/env python3
"""
Password Encryption Utility for UniFi Route Loader

This utility encrypts passwords for use in the config file.
The encrypted password can be safely stored in a config file.
"""

import os
import sys
import getpass
from cryptography.fernet import Fernet


def get_encryption_key() -> bytes:
    """
    Get or create encryption key for password encryption

    Returns:
        Encryption key bytes
    """
    key_file = os.path.expanduser('~/.unifi_route_loader.key')

    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Generate new key
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        os.chmod(key_file, 0o600)  # Secure permissions
        print(f"✓ Created new encryption key: {key_file}")
        return key


def encrypt_password(password: str) -> str:
    """
    Encrypt a password for storage in config file

    Args:
        password: Plain text password

    Returns:
        Encrypted password string (base64 encoded)
    """
    key = get_encryption_key()
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted.decode()


def main():
    """Main function"""
    print("UniFi Route Loader - Password Encryption Utility")
    print("=" * 50)
    print()
    print("This utility will encrypt your password for use in the config file.")
    print("The encryption key will be stored securely in your home directory.")
    print()

    # Prompt for password
    password = getpass.getpass("Enter password to encrypt: ")
    if not password:
        print("✗ Error: Password cannot be empty")
        sys.exit(1)

    # Confirm password
    password_confirm = getpass.getpass("Confirm password: ")
    if password != password_confirm:
        print("✗ Error: Passwords do not match")
        sys.exit(1)

    # Encrypt password
    try:
        encrypted_password = encrypt_password(password)
        print()
        print("✓ Password encrypted successfully!")
        print()
        print("Add this line to your config.yaml file:")
        print("-" * 50)
        print(f"password_encrypted: {encrypted_password}")
        print("-" * 50)
        print()
        print("IMPORTANT:")
        print("  - Keep the encryption key file secure: ~/.unifi_route_loader.key")
        print("  - Do NOT share the key file or commit it to version control")
        print("  - The encrypted password only works with this key file")
        print("  - If you lose the key file, you'll need to re-encrypt your password")
        print()
    except Exception as e:
        print(f"✗ Error encrypting password: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
