use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
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

fn get_db_path() -> io::Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "cerberus", "password-manager")
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get project directory"))?;

    let config_dir = proj_dirs.config_dir();
    fs::create_dir_all(config_dir)?;

    Ok(config_dir.join("passwords.db"))
}

fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    let argon2 = Argon2::default();
    let salt = SaltString::from_b64(&BASE64.encode(salt)).unwrap();

    argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string()
        .into_bytes()
}

fn encrypt_password(key: &[u8], password: &str) -> (String, String) {
    let cipher = Aes256Gcm::new_from_slice(&key[..32]).unwrap();
    let nonce: [u8; 12] = rand::thread_rng().gen();
    let nonce = Nonce::from_slice(&nonce);

    let ciphertext = cipher.encrypt(nonce, password.as_bytes()).unwrap();

    (BASE64.encode(ciphertext), BASE64.encode(nonce))
}

fn decrypt_password(key: &[u8], encrypted_password: &str, nonce: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(&key[..32]).unwrap();
    let nonce = BASE64.decode(nonce).unwrap();
    let nonce = Nonce::from_slice(&nonce);
    let ciphertext = BASE64.decode(encrypted_password).unwrap();

    String::from_utf8(cipher.decrypt(nonce, ciphertext.as_ref()).unwrap()).unwrap()
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
    let db_path = get_db_path()?;

    match cli.command {
        Commands::Init => {
            let master_password = read_master_password(true)?;

            let salt: [u8; 32] = rand::thread_rng().gen();
            let key = derive_key(&master_password, &salt);

            let db = Database {
                salt: BASE64.encode(salt),
                key_hash: BASE64.encode(&key),
                entries: Vec::new(),
            };

            fs::write(&db_path, serde_json::to_string(&db).unwrap())?;
            println!("Cerberus initialized successfully");
        }

        Commands::Generate { length, service } => {
            let master_password = read_master_password(false)?;

            let db_connect = fs::read_to_string(&db_path)?;
            let mut db: Database = serde_json::from_str(&db_connect)?;

            let salt = BASE64.decode(&db.salt).unwrap();
            let key = derive_key(&master_password, &salt);

            let password: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(length)
                .chain(std::iter::once(b'@'))
                .chain(std::iter::once(b'#'))
                .chain(std::iter::once(b'$'))
                .map(char::from)
                .collect();

            let (encrypted_password, nonce) = encrypt_password(&key, &password);

            db.entries.push(PasswordEntry {
                service,
                encrypted_password,
                nonce,
            });

            fs::write(&db_path, serde_json::to_string(&db).unwrap())?;
            println!("Generated password: {}", password);
            // Encrypt and Save the password here
        }

        Commands::Get { service } => {
            let master_password = read_master_password(false)?;

            let db_connect = fs::read_to_string(&db_path)?;
            let db: Database = serde_json::from_str(&db_connect)?;

            let salt = BASE64.decode(&db.salt).unwrap();
            let key = derive_key(&master_password, &salt);

            if let Some(entry) = db.entries.iter().find(|e| e.service == service) {
                let password = decrypt_password(&key, &entry.encrypted_password, &entry.nonce);
                println!("Password for {}: {}", service, password);
            } else {
                println!("No password found for service: {}", service);
            }

            // Decrypt and retrieve the password
            //println!("Retrieved password for service: {}", service);
        }
    }

    Ok(())
}
