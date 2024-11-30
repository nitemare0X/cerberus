# Cerberus Password Manager 

A secure command-line password manager written in Rust that focuses on:
- Strong encryption (AES-GCM)
- Secure password generation

# TODO:

- [x] Implement actually database usage via sqlx
- [ ] Add command to view services in entries


## Features

- Secure master password handling with invisible input
- Strong password generation with mixed characters
- AES-GCM encryption for stored passwords
- Argon2 key derivation
- OS-specific secure storage location
- Simple CLI interface

## Installation

``` bash
git clone https://github.com/nitemare0x/cerberus
cd cerberus
cargo install --path .
```

## Usage

1. Initialize the password manager:

```bash
cerberus init 
```

2. Generate new passwords:

```bash 
cerberus generate [service]

# With  custom length: 
cerberus generate [service] -l 32
```

3. Retrieve a password: 

```bash
cerberus get github
```

## Storage Location

Passwords are stored encrypted in:

- Linux: `~/.config/cerberus/passwords.db`
- macOS: `~/Library/Application Support/com.cerberus.password-manager/passwords.db`
- Windows: `%APPDATA%\cerberus\password-manager\config\passwords.db`


