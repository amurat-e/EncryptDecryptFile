# Encrypt/Decrypt File GUI Application

A secure file encryption and decryption application with a graphical user interface built in Java. This application uses **AES-256-CBC encryption** with **PBKDF2-SHA256** key derivation for strong password-based file protection.

## Project Purpose

This application provides an easy-to-use interface for securely encrypting and decrypting files. It allows users to:

- Encrypt any file using a password
- Decrypt encrypted files with password verification
- Store password hashes for encrypted files to verify authenticity
- Generate strong cryptographic keys from passwords using industry-standard algorithms

## Key Features

- **AES-256-CBC Encryption**: Military-grade encryption standard
- **PBKDF2-SHA256 Key Derivation**: 100,000 iterations for password-based key generation
- **GUI Interface**: User-friendly Swing-based graphical interface
- **Password Verification**: MD5-based password verification for decryption
- **File Management**: Automatic file organization with `.enc` extension for encrypted files
- **Error Handling**: Comprehensive error messages and validation
- **Cross-platform**: Runs on any system with Java 21+

## Project Structure

```text
EncryptDecryptGui/
├── README.md                      # This file
├── bin/                           # Compiled bytecode directory
├── src/
│   ├── EncryptDecryptGUI.java    # Main GUI application class
│   ├── FileCrypto.java           # File encryption/decryption operations
│   └── KeyDerivation.java        # PBKDF2 key derivation module
```

### Module Descriptions

- **EncryptDecryptGUI.java**: Main application entry point. Provides the GUI interface with password entry, file selection, and encryption/decryption controls. Manages password verification for encrypted files.

- **FileCrypto.java**: Handles all file encryption and decryption operations. Manages salt generation, IV generation, cipher operations, and file I/O.

- **KeyDerivation.java**: Implements PBKDF2-HMAC-SHA256 key derivation to generate 256-bit AES keys from passwords.

## Requirements

- **Java**: JDK 21 or later (uses `--enable-preview` flag)
- **Operating System**: macOS, Linux, or Windows
- **Memory**: Minimum 256 MB RAM
- **Disk Space**: Varies based on files being encrypted

## Build Instructions

### Prerequisites

Ensure Java 21+ is installed and configured:

```bash
java --version
```

### Compile the Project

Navigate to the project directory and compile all source files:

```bash
cd /path/to/EncryptDecryptGui
javac -d bin src/*.java
```

This compiles all Java source files in the `src/` directory and outputs the compiled bytecode to the `bin/` directory.

## Run Instructions

### Run the Application

Execute the compiled application:

```bash
java -cp bin EncryptDecryptGUI
```

For Java 21+, if using preview features:

```bash
java --enable-preview -cp bin EncryptDecryptGUI
```

The GUI window should open with the title "🔐 Encrypt 🔓 Decrypt File"

### Usage Steps

1. **To Encrypt a File:**
   - Enter a strong password in the password field
   - Click **"📂 Select File"** button to choose a file to encrypt
   - Click **"🔑 Encrypt Now"** to encrypt the file
   - The encrypted file will be saved with `.enc` extension
   - A success message will show the output file path

2. **To Decrypt a File:**
   - Enter the password used during encryption
   - Click **"🔐 Select Enc File"** button to choose a `.enc` file
   - Click **"🔓 Decrypt Now"** to decrypt the file
   - The decrypted file will be saved (original name restored)
   - The encrypted file will be automatically deleted after successful decryption

## Technical Details

### Encryption Algorithm

- **Cipher**: AES (Advanced Encryption Standard)
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS5
- **Key Size**: 256 bits

### Key Derivation

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000
- **Salt**: 16 bytes (randomly generated)
- **IV**: 16 bytes (randomly generated)

### Encrypted File Format

```text
[16 bytes Salt][16 bytes IV][Encrypted Data]
```

The encrypted file stores the salt and IV at the beginning for decryption purposes.

### Password Storage

Passwords are stored as MD5 hashes in `~/.encryptsrv_passwords_java` in the format:

```text
filename.enc:md5_hash
```

## Security Considerations

- Use strong passwords (minimum 12 characters recommended)
- Keep your passwords secure and do not share them
- Encrypted files can only be decrypted with the correct password
- The application uses industry-standard cryptographic algorithms
- Salt and IV are randomly generated for each encryption operation

## Troubleshooting

### "File not found" Error

- Ensure the file path is correct
- Check that you have read permissions for the file

### "Wrong Password" Error

- Verify you're using the correct password
- Password verification is case-sensitive

### "Invalid encrypted file" Error

- The `.enc` file may be corrupted
- Ensure you're selecting an encrypted file created by this application

### Compilation Errors

- Verify Java 21+ is installed: `java --version`
- Ensure all source files are in the `src/` directory
- Check for any typos in file names

## License

This project is provided as-is for educational and personal use.

## Author

Created as a Java GUI application for secure file encryption.
