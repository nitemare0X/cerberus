use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rand::{prelude::SliceRandom, Rng};
use rpassword::read_password;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

// Migration to create tables
const INIT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS master_key (
    id INTEGER PRIMARY KEY,
    salt TEXT NOT NULL,
    key_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY,
    service TEXT NOT NULL UNIQUE,
    encrypted_password TEXT NOT NULL,
    nonce TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
"#;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init,
    Generate {
        service: String,
        #[clap(short, long, default_value = "16")]
        length: usize,
    },
    Get {
        service: String,
    },
    List,
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

async fn init_db(pool: &SqlitePool) -> sqlx::Result<()> {
    sqlx::query(INIT_SQL).execute(pool).await?;
    Ok(())
}

async fn save_master_key(pool: &SqlitePool, salt: &str, key_hash: &str) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO master_key (salt, key_hash) VALUES (?, ?)")
        .bind(salt)
        .bind(key_hash)
        .execute(pool)
        .await?;
    Ok(())
}

async fn save_password(
    pool: &SqlitePool,
    service: &str,
    encrypted_password: &str,
    nonce: &str,
) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO passwords (service, encrypted_password, nonce) VALUES (?, ?, ?)")
        .bind(service)
        .bind(encrypted_password)
        .bind(nonce)
        .execute(pool)
        .await?;
    Ok(())
}

async fn get_password(pool: &SqlitePool, service: &str) -> sqlx::Result<Option<(String, String)>> {
    sqlx::query_as::<_, (String, String)>(
        "SELECT encrypted_password, nonce FROM passwords WHERE service = ?",
    )
    .bind(service)
    .fetch_optional(pool)
    .await
}

async fn list_services(pool: &SqlitePool) -> sqlx::Result<Vec<String>> {
    sqlx::query_as::<_, (String,)>("SELECT service FROM passwords ORDER BY service")
        .fetch_all(pool)
        .await
        .map(|rows| rows.into_iter().map(|(service,)| service).collect())
}

fn ensure_db_directory() -> io::Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "cerberus", "password-manager")
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Failed to get project directory"))?;

    let config_dir = proj_dirs.config_dir();
    fs::create_dir_all(config_dir)?;

    Ok(config_dir.to_path_buf())
}

fn derive_key(password: &str, salt: &[u8]) -> Vec<u8> {
    let argon2 = Argon2::default();
    let salt_string = SaltString::encode_b64(salt).unwrap();

    argon2
        .hash_password(password.as_bytes(), &salt_string)
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

#[tokio::main]
async fn main() -> io::Result<()> {
    let cli = Cli::parse();
    let db_dir = ensure_db_directory()?;
    let db_path = db_dir.join("passwords.db");

    let _database_url = format!("sqlite://{}", db_path.display());

    let connection_options = sqlx::sqlite::SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(connection_options)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    match cli.command {
        Commands::Init => {
            init_db(&pool)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            let master_password = read_master_password(true)?;
            let salt: [u8; 32] = rand::thread_rng().gen();
            let key = derive_key(&master_password, &salt);

            save_master_key(&pool, &BASE64.encode(salt), &BASE64.encode(&key))
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            println!("Cerberus initialized successfully");
        }

        Commands::Generate { length, service } => {
            let master_password = read_master_password(false)?;

            let salt = if let Some((salt,)) =
                sqlx::query_as::<_, (String,)>("SELECT salt FROM master_key LIMIT 1")
                    .fetch_optional(&pool)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            {
                salt
            } else {
                return Err(io::Error::new(io::ErrorKind::Other, "Master key not found"));
            };

            let salt = BASE64.decode(&salt).unwrap();
            let key = derive_key(&master_password, &salt);

            let password: String = generate_strong_password(Some(length));
            let (encrypted_password, nonce) = encrypt_password(&key, &password);

            save_password(&pool, &service, &encrypted_password, &nonce)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            println!("Generated password: {}", password);
        }

        Commands::Get { service } => {
            let master_password = read_master_password(false)?;

            let salt = if let Some((salt,)) =
                sqlx::query_as::<_, (String,)>("SELECT salt FROM master_key LIMIT 1")
                    .fetch_optional(&pool)
                    .await
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            {
                salt
            } else {
                return Err(io::Error::new(io::ErrorKind::Other, "Master key not found"));
            };

            let salt = BASE64.decode(&salt).unwrap();
            let key = derive_key(&master_password, &salt);

            if let Some((encrypted_password, nonce)) = get_password(&pool, &service)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            {
                let password = decrypt_password(&key, &encrypted_password, &nonce);
                println!("Password for {}: {}", service, password);
            } else {
                println!("No passwords found for service: {}", service);
            }
        }

        Commands::List => {
            let services = list_services(&pool)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

            if services.is_empty() {
                println!("No stored passwords found.");
            } else {
                println!("Stored passwords for:");
                for service in services {
                    println!(" - {}", service);
                }
            }
        }
    }

    Ok(())
}

fn generate_strong_password(length: Option<usize>) -> String {
    let length = length.unwrap_or(16);

    let uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let lowercase = "abcdefghijklmnopqrstuvwxyz";
    let numbers = "0123456789";
    let symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    let all_chars = format!("{}{}{}{}", uppercase, lowercase, numbers, symbols);
    let mut rng = rand::thread_rng();

    let mut password: String = vec![
        uppercase
            .chars()
            .nth(rng.gen_range(0..uppercase.len()))
            .unwrap(),
        lowercase
            .chars()
            .nth(rng.gen_range(0..lowercase.len()))
            .unwrap(),
        numbers
            .chars()
            .nth(rng.gen_range(0..numbers.len()))
            .unwrap(),
        symbols
            .chars()
            .nth(rng.gen_range(0..symbols.len()))
            .unwrap(),
    ]
    .into_iter()
    .collect();

    while password.len() < length {
        password.push(
            all_chars
                .chars()
                .nth(rng.gen_range(0..all_chars.len()))
                .unwrap(),
        );
    }

    let mut password_chars: Vec<char> = password.chars().collect();
    password_chars.shuffle(&mut rng);
    password_chars.into_iter().collect()
}
