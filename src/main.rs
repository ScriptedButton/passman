use aes_gcm::{
    aead::{rand_core::RngCore, Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use clap::{Parser, Subcommand};
use rand::Rng;
use rpassword;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    convert::TryFrom,
    fs::{self, File},
    io::{self, Write},
    path::Path,
};

#[derive(Serialize, Deserialize, Clone)]
struct Credential {
    username: String,
    encrypted_password: Vec<u8>,
    nonce: Vec<u8>,
    website: String,
}

#[derive(Serialize, Deserialize)]
struct PasswordManager {
    master_password_hash: String,
    master_key_salt: String,
    credentials: HashMap<String, Credential>,
}

impl PasswordManager {
    fn new(master_password: &str) -> io::Result<Self> {
        let password_salt = SaltString::generate(&mut OsRng);
        let key_salt = SaltString::generate(&mut OsRng);

        let argon2 = Argon2::default();
        let master_password_hash = argon2
            .hash_password(master_password.as_bytes(), &password_salt)
            .unwrap()
            .to_string();

        Ok(PasswordManager {
            master_password_hash,
            master_key_salt: key_salt.to_string(),
            credentials: HashMap::new(),
        })
    }

    fn verify_master_password(&self, master_password: &str) -> bool {
        let parsed_hash = PasswordHash::new(&self.master_password_hash).unwrap();
        Argon2::default()
            .verify_password(master_password.as_bytes(), &parsed_hash)
            .is_ok()
    }

    fn derive_encryption_key(&self, master_password: &str) -> [u8; 32] {
        let argon2 = Argon2::default();
        let mut key = [0u8; 32];

        let key_salt = SaltString::from_b64(&self.master_key_salt).unwrap();

        argon2
            .hash_password(master_password.as_bytes(), &key_salt)
            .unwrap()
            .to_string()
            .as_bytes()
            .iter()
            .take(32)
            .enumerate()
            .for_each(|(i, &byte)| key[i] = byte);

        key
    }

    fn add_credential(
        &mut self,
        service: String,
        username: String,
        password: String,
        master_password: &str,
        website: String,
    ) -> Result<(), String> {
        if !self.verify_master_password(master_password) {
            return Err("Invalid master password".to_string());
        }

        let key = self.derive_encryption_key(master_password);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Key error: {}", e))?;

        let mut nonce_bytes = [0u8; 12];
        let mut rng = OsRng;
        rng.fill_bytes(&mut nonce_bytes);

        let nonce =
            Nonce::try_from(&nonce_bytes[..]).map_err(|_| "Failed to create nonce".to_string())?;

        let encrypted_password = cipher
            .encrypt(&nonce, password.as_bytes().as_ref())
            .map_err(|e| format!("Encryption error: {}", e))?;

        self.credentials.insert(
            service,
            Credential {
                username,
                encrypted_password,
                nonce: nonce_bytes.to_vec(),
                website,
            },
        );

        Ok(())
    }

    fn get_credential(
        &self,
        service: &str,
        master_password: &str,
    ) -> Result<(String, String, String), String> {
        if !self.verify_master_password(master_password) {
            return Err("Invalid master password".to_string());
        }

        let credential = self
            .credentials
            .get(service)
            .ok_or_else(|| "Service not found".to_string())?;

        let key = self.derive_encryption_key(master_password);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| format!("Key error: {}", e))?;

        let nonce = Nonce::try_from(&credential.nonce[..])
            .map_err(|_| "Failed to create nonce from stored data".to_string())?;

        let password = cipher
            .decrypt(&nonce, credential.encrypted_password.as_slice())
            .map_err(|e| format!("Decryption error: {}", e))?;

        let password =
            String::from_utf8(password).map_err(|e| format!("UTF-8 conversion error: {}", e))?;

        Ok((
            credential.username.clone(),
            password,
            credential.website.clone(),
        ))
    }

    fn generate_password(length: usize) -> String {
        let mut rng = rand::rng();
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        (0..length)
            .map(|_| {
                let idx = rng.random_range(0..chars.len());
                chars.chars().nth(idx).unwrap()
            })
            .collect()
    }

    fn save_to_file(&self, filename: &str) -> io::Result<()> {
        let json = serde_json::to_string(&self)?;
        let mut file = File::create(filename)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }

    fn load_from_file(filename: &str) -> io::Result<Self> {
        let contents = fs::read_to_string(filename)?;
        let password_manager: PasswordManager = serde_json::from_str(&contents)?;
        Ok(password_manager)
    }

    // Helper method to list all services
    fn list_services(&self) -> Vec<String> {
        self.credentials.keys().cloned().collect()
    }
}

#[derive(Parser)]
#[command(name = "passman")]
#[command(about = "A secure password manager", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Add a new credential
    Add {
        /// Service name
        service: String,
        /// Username
        username: String,
        /// Password (optional - will be generated if not provided)
        #[arg(short, long)]
        password: Option<String>,
        /// Website URL
        #[arg(short, long)]
        website: String,
    },
    /// Retrieve credentials for a service
    Get {
        /// Service name
        service: String,
    },
    /// List all services
    List,
    /// Generate a new password
    Gen {
        /// Password length
        #[arg(short, long, default_value_t = 16)]
        length: usize,
    },
}

fn prompt_master_password(prompt: &str) -> io::Result<String> {
    rpassword::prompt_password(prompt)
}

fn run_interactive_mode(password_manager: &mut PasswordManager) -> io::Result<()> {
    loop {
        println!("\nPassword Manager Menu:");
        println!("1. Add new credential");
        println!("2. Get credential");
        println!("3. List services");
        println!("4. Generate password");
        println!("5. Save and exit");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;

        match choice.trim() {
            "1" => {
                print!("Enter service name: ");
                io::stdout().flush()?;
                let mut service = String::new();
                io::stdin().read_line(&mut service)?;

                print!("Enter username: ");
                io::stdout().flush()?;
                let mut username = String::new();
                io::stdin().read_line(&mut username)?;

                print!("Enter password (or press enter to generate one): ");
                io::stdout().flush()?;
                let mut password = String::new();
                io::stdin().read_line(&mut password)?;
                let password = if password.trim().is_empty() {
                    PasswordManager::generate_password(16)
                } else {
                    password.trim().to_string()
                };

                print!("Enter website URL: ");
                io::stdout().flush()?;
                let mut website = String::new();
                io::stdin().read_line(&mut website)?;

                let master_password = prompt_master_password("Enter master password: ")?;

                match password_manager.add_credential(
                    service.trim().to_string(),
                    username.trim().to_string(),
                    password,
                    &master_password,
                    website.trim().to_string(),
                ) {
                    Ok(_) => println!("Credential added successfully!"),
                    Err(e) => println!("Error: {}", e),
                }
            }
            "2" => {
                print!("Enter service name: ");
                io::stdout().flush()?;
                let mut service = String::new();
                io::stdin().read_line(&mut service)?;

                let master_password = prompt_master_password("Enter master password: ")?;

                match password_manager.get_credential(service.trim(), &master_password) {
                    Ok((username, password, website)) => {
                        println!("\nCredential found:");
                        println!("Username: {}", username);
                        println!("Password: {}", password);
                        println!("Website: {}", website);
                    }
                    Err(e) => println!("Error: {}", e),
                }
            }
            "3" => {
                let services = password_manager.list_services();
                println!("Available services:");
                for service in services {
                    println!("{}", service);
                }
            }
            "4" => {
                print!("Enter desired password length: ");
                io::stdout().flush()?;
                let mut length = String::new();
                io::stdin().read_line(&mut length)?;
                let length: usize = length.trim().parse().unwrap_or(16);
                println!(
                    "Generated password: {}",
                    PasswordManager::generate_password(length)
                );
            }
            "5" => {
                password_manager.save_to_file("passwords.json")?;
                println!("Passwords saved. Goodbye!");
                break;
            }
            _ => println!("Invalid choice!"),
        }
    }
    Ok(())
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let mut password_manager = match Path::new("passwords.json").exists() {
        true => PasswordManager::load_from_file("passwords.json")?,
        false => {
            let master_password = prompt_master_password(
                "Enter a master password to create a new password manager: ",
            )?;
            PasswordManager::new(&master_password)?
        }
    };

    match cli.command {
        None => {
            // Run interactive mode when no command-line arguments are provided
            run_interactive_mode(&mut password_manager)?;
            return Ok(());
        }
        Some(command) => match command {
            Commands::Add {
                service,
                username,
                password,
                website,
            } => {
                let master_password = prompt_master_password("Enter master password: ")?;

                let password = password.unwrap_or_else(|| {
                    println!("Generating a secure password...");
                    PasswordManager::generate_password(16)
                });

                match password_manager.add_credential(
                    service.clone(),
                    username,
                    password.clone(),
                    &master_password,
                    website,
                ) {
                    Ok(_) => {
                        println!("Credential added successfully!");
                        println!("Service: {}", service);
                        println!("Password: {}", password);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }

            Commands::Get { service } => {
                let master_password = prompt_master_password("Enter master password: ")?;

                match password_manager.get_credential(&service, &master_password) {
                    Ok((username, password, website)) => {
                        println!("\nCredential found:");
                        println!("Service: {}", service);
                        println!("Username: {}", username);
                        println!("Password: {}", password);
                        println!("Website: {}", website);
                    }
                    Err(e) => eprintln!("Error: {}", e),
                }
            }

            Commands::List => {
                let services = password_manager.list_services();
                println!("Available services:");
                for service in services {
                    println!("{}", service);
                }
            }

            Commands::Gen { length } => {
                let password = PasswordManager::generate_password(length);
                println!("Generated password: {}", password);
            }
        },
    }

    // Save changes to file
    password_manager.save_to_file("passwords.json")?;

    Ok(())
}
