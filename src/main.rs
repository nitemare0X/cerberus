use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key,
};
use argon2::{Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, Subcommand};
use rand::{distributions::Alphanumeric, Rng};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Generate { length: usize, service: String },
    Get { service: String },
}

#[derive(Serialize, Deserialize)]
struct PasswordEntry {
    service: String,
    encrypted_password: String,
    nonce: String,
}

#[derive(Serialize, Deserialize)]
struct Database {
    salt: String,
    key_hash: String,
    entries: Vec<PasswordEntry>,
}

fn read_master_password(confirm: bool) -> io::Result<String> {
    println!("Enter a master password: ");
    io::stdout().flush()?;
    let password = read_password()?;

    if confirm {
        println!("Confirm master password: ");
        io::stdout().flush()?;
        let confirmation = read_password()?;

        if password != confirmation {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "Passwords do not match.",
            ));
        }
    }

    Ok(password)
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let db_path = PathBuf::from("passwords.db");

    match cli.command {
        Commands::Init => {
            let master_password = read_master_password(true)?;

            let salt: [u8; 32] = rand::thread_rng().gen();
            let argon2 = Argon2::default();

            let key_hash = argon2
                .hash_password(master_password.as_bytes(), &salt)
                .unwrap()
                .to_string();

            let db = Database {
                salt: BASE64.encode(salt),
                key_hash,
                entries: Vec::new(),
            };

            fs::write(&db_path, serde_json::to_string(&db).unwrap())?;
            println!("Cerberus initialized successfully");
        }

        Commands::Generate { length, service } => {
            let master_password = read_master_password(false)?;

            let password: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(length)
                .chain(std::iter::once(b'@'))
                .chain(std::iter::once(b'#'))
                .chain(std::iter::once(b'$'))
                .map(char::from)
                .collect();

            println!("Generated password: {}", password);
            // Encrypt and Save the password here
        }

        Commands::Get { service } => {
            let master_password = read_master_password(false)?;
            // Decrypt and retrieve the password
            println!("Retrieved password for service: {}", service);
        }
    }

    Ok(())
}
