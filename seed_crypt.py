#!/usr/bin/env python3

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import os
import json
import getpass

def generate_key_from_password(password: str, salt: bytes) -> bytes:
    """Generate a Fernet key from a password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_phrases(phrases: list, password: str) -> dict:
    """Encrypt a list of mnemonic phrases with a password."""
    salt = os.urandom(16)
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    encrypted_phrases = [cipher.encrypt(phrase.encode()) for phrase in phrases]
    return {
        "salt": base64.b64encode(salt).decode('utf-8'),
        "encrypted_phrases": [base64.b64encode(ep).decode('utf-8') for ep in encrypted_phrases]
    }

def decrypt_phrases(encrypted_data: dict, password: str) -> list:
    """Decrypt a list of mnemonic phrases using the password."""
    salt = base64.b64decode(encrypted_data["salt"])
    encrypted_phrases = [base64.b64decode(ep) for ep in encrypted_data["encrypted_phrases"]]
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)
    try:
        decrypted_phrases = [cipher.decrypt(ep).decode() for ep in encrypted_phrases]
        return decrypted_phrases
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted data.")

def save_encrypted_data(filename: str, encrypted_data: dict):
    """Save encrypted data to a file."""
    with open(filename, 'w') as f:
        json.dump(encrypted_data, f, indent=4)

def load_encrypted_data(filename: str) -> dict:
    """Load encrypted data from a file."""
    with open(filename, 'r') as f:
        return json.load(f)

def get_vaults() -> list:
    """Return a list of existing vault files in the current directory."""
    return [f for f in os.listdir() if f.endswith('.json') and 'vault' in f.lower()]

def create_new_vault():
    """Create a new vault by collecting and encrypting phrases."""
    print("\n=== Creating New Vault ===")
    vault_name = input("Enter a name for this vault (e.g., 'personal', 'backup'): ").strip()
    filename = f"vault_{vault_name}.json"
    
    if os.path.exists(filename):
        overwrite = input(f"Vault '{filename}' already exists. Overwrite? (y/n): ").lower()
        if overwrite != 'y':
            print("Vault creation cancelled.")
            return
    
    phrases = []
    print("Enter your existing mnemonic phrases (one per line). Press Enter twice to finish:")
    while True:
        phrase = input("Mnemonic phrase: ").strip()
        if not phrase:
            if phrases:
                break
            else:
                print("Please enter at least one phrase.")
        else:
            phrases.append(phrase)
    
    password = getpass.getpass("\nEnter a strong password to encrypt your phrases: ")
    encrypted_data = encrypt_phrases(phrases, password)
    print("\nEncrypted Phrases:")
    for i, ep in enumerate(encrypted_data["encrypted_phrases"], 1):
        print(f"Phrase {i}: {ep}")
    
    save_encrypted_data(filename, encrypted_data)
    print(f"\nEncrypted vault saved to {filename}")

def decrypt_existing_vault():
    """Decrypt a selected existing vault."""
    vaults = get_vaults()
    if not vaults:
        print("\nNo vaults found. Create one first.")
        return
    
    print("\n=== Decrypting Existing Vault ===")
    print("Available vaults:")
    for i, vault in enumerate(vaults, 1):
        print(f"{i}. {vault}")
    choice = input("Enter the number of the vault to decrypt: ").strip()
    
    try:
        vault_index = int(choice) - 1
        if 0 <= vault_index < len(vaults):
            filename = vaults[vault_index]
            loaded_data = load_encrypted_data(filename)
            password = getpass.getpass(f"Enter the password for {filename}: ")
            try:
                decrypted_phrases = decrypt_phrases(loaded_data, password)
                print("\nDecrypted Phrases:")
                for i, phrase in enumerate(decrypted_phrases, 1):
                    print(f"Phrase {i}: {phrase}")
            except ValueError as e:
                print(f"Error: {e}")
        else:
            print("Invalid vault number.")
    except ValueError:
        print("Please enter a valid number.")

def delete_vault():
    """Delete a selected vault after verifying the password."""
    vaults = get_vaults()
    if not vaults:
        print("\nNo vaults found to delete.")
        return
    
    print("\n=== Deleting a Vault ===")
    print("Available vaults:")
    for i, vault in enumerate(vaults, 1):
        print(f"{i}. {vault}")
    choice = input("Enter the number of the vault to delete: ").strip()
    
    try:
        vault_index = int(choice) - 1
        if 0 <= vault_index < len(vaults):
            filename = vaults[vault_index]
            loaded_data = load_encrypted_data(filename)
            password = getpass.getpass(f"Enter the password for {filename} to confirm deletion: ")
            try:
                # Verify password by attempting decryption
                decrypt_phrases(loaded_data, password)
                os.remove(filename)
                print(f"\nVault '{filename}' deleted successfully.")
            except ValueError as e:
                print(f"Error: {e}. Deletion cancelled.")
        else:
            print("Invalid vault number.")
    except ValueError:
        print("Please enter a valid number.")

def main():
    print("=== SeedSafe: Your Crypto Phrase Protector ===")
    
    while True:
        print("\nOptions:")
        print("1. Create a new vault")
        print("2. Decrypt an existing vault")
        print("3. Delete an existing vault")
        print("4. Exit")
        choice = input("Enter your choice (1-4): ").strip()
        
        if choice == "1":
            create_new_vault()
        elif choice == "2":
            decrypt_existing_vault()
        elif choice == "3":
            delete_vault()
        elif choice == "4":
            print("Exiting SeedSafe. Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")

if __name__ == "__main__":
    main()