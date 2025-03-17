# SeedCrypt v1.0.0

**Release Date:** [Insert Date, e.g., March 17, 2025]  
**Repository:** [https://github.com/andy-lawless/seedcrypt](https://github.com/andy-lawless/seedcrypt)  


## Overview
SeedCrypt is a Python-based cryptocurrency passphrase vault designed to securely encrypt, manage, and protect your existing mnemonic seed phrases. With a single password, you can create multiple vaults, decrypt specific vaults, and delete them securely—all with an intuitive command-line interface. This initial release, version 1.0.0, provides a robust foundation for safeguarding your crypto wallet keys.

## Key Features
- **Multiple Vaults**: Create named vaults (e.g., `vault_personal.json`, `vault_backup.json`) to store different sets of mnemonic phrases.
- **Flexible Decryption**: List and select from existing vaults to decrypt, revealing your phrases with the correct password.
- **Secure Deletion**: Delete a vault after verifying the password, ensuring only authorized users can remove sensitive data.
- **Password Masking**: Input passwords securely with `getpass`, keeping them hidden from the screen.
- **Strong Encryption**: Uses the `cryptography` library with Fernet (AES-based) and PBKDF2 key derivation for robust security.
- **User-Friendly Menu**: Choose to create, decrypt, delete, or exit via a simple numbered menu.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/seedsafe.git
   cd seedsafe
 
2. Install requirements:
   ```bash
   pip install -r requirements.txt

3. Run the script
   ```bash
   python seedcrypt.py
