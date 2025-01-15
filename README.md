# Secure Password Manager

A command-line password manager written in Rust that provides secure storage and management of credentials. The application supports both interactive and command-line modes, using strong encryption (AES-GCM) and password hashing (Argon2) for security.

## Features

- Secure credential storage using AES-GCM encryption
- Master password protection with Argon2 password hashing
- Interactive and CLI modes
- Secure password generation
- JSON-based encrypted storage
- Hidden password input
- Website URL storage for each credential

## Installation

1. Clone the repository:
```bash
git clone https://github.com/ScriptedButton/passman.git
cd passman
```

2. Build the project:
```bash
cargo build --release
```

The compiled binary will be available in `target/release/passman`

## Usage

### Interactive Mode

Launch the password manager in interactive mode by running without arguments:

```bash
passman
```

This will present a menu with the following options:
1. Add new credential
2. Get credential
3. Generate password
4. Save and exit

### CLI Mode

The password manager supports the following CLI commands:

1. Add a new credential:
```bash
passman add <service> <username> -w <website> [-p <password>]
```
If no password is provided with `-p`, a secure password will be generated automatically.

2. Get credentials for a service:
```bash
passman get <service>
```

3. Generate a new password:
```bash
passman gen [-l <length>]
```
The length parameter is optional and defaults to 16 characters.

### Examples

```bash
# Add a new credential with a specific password
passman add github johndoe -w github.com -p mypassword123

# Add a credential with auto-generated password
passman add github johndoe -w github.com

# Retrieve credentials
passman get github

# Generate a 20-character password
passman gen -l 20
```

## Security Features

- **Encryption**: Uses AES-GCM for credential encryption
- **Password Hashing**: Implements Argon2 for master password hashing
- **Secure Storage**: All credentials are encrypted before being stored in the JSON file
- **Hidden Input**: Master password input is hidden during typing
- **Secure Password Generation**: Generates strong random passwords using the `rand` crate
- **No Plain Text**: Passwords are never stored in plain text

## File Storage

The password manager stores encrypted credentials in a `passwords.json` file in the same directory as the executable. This file is automatically created when you first run the program and is updated after each operation.

## Development

To contribute to this project:

1. Fork the repository
2. Create a new branch for your feature
3. Make your changes
4. Submit a pull request

## Security Considerations

- The master password is never stored directly; only its hash is saved
- All passwords are encrypted before being stored
- The program uses cryptographically secure random number generation
- Sensitive input is hidden from view during typing

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This password manager is provided as-is, without any warranties. Always ensure you keep backups of your password database and master password.