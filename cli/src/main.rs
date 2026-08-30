use clap::{Parser, Subcommand};
use std::process::Command;
use std::path::Path;
use vault_fs::crypto;

#[derive(Parser)]
#[command(name = "qv")]
#[command(about = "QuantumVault Command Line Interface", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount the virtual post-quantum filesystem
    Mount {
        /// Backend cipher store directory path
        #[arg(short, long)]
        backend: String,

        /// Virtual mount directory path
        #[arg(short, long)]
        mountpoint: String,
    },

    /// Unmount the virtual post-quantum filesystem cleanly
    Unmount {
        /// Virtual mount directory path
        #[arg(short, long)]
        mountpoint: String,
    },
    
    /// Generate CRYSTALS-Kyber and CRYSTALS-Dilithium post-quantum keys
    Keygen {
        /// Directory path to save generated keys
        #[arg(short, long, default_value = ".")]
        out_dir: String,
    },
    
    /// Start the key management background daemon
    RunDaemon,
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match &cli.command {
        Commands::Mount { backend, mountpoint } => {
            println!("Mounting QuantumVault FUSE filesystem in background...");
            println!("Backend Store: {}", backend);
            println!("Mount Point: {}", mountpoint);

            // Spawn vault-fs as a background process
            match Command::new("vault-fs")
                .arg(backend)
                .arg(mountpoint)
                .spawn() 
            {
                Ok(child) => {
                    println!("Successfully spawned filesystem daemon in background (PID: {}).", child.id());
                }
                Err(err) => {
                    eprintln!("Failed to spawn vault-fs background process: {:?}", err);
                    eprintln!("Please ensure that the 'vault-fs' binary is built and in your system PATH.");
                }
            }
        }
        Commands::Unmount { mountpoint } => {
            println!("Attempting to unmount QuantumVault FUSE filesystem cleanly at: {}...", mountpoint);

            // Execute fusermount -u or target platform equivalent
            #[cfg(target_os = "linux")]
            let mut cmd = Command::new("fusermount");
            #[cfg(target_os = "linux")]
            cmd.arg("-u").arg(mountpoint);

            #[cfg(not(target_os = "linux"))]
            let mut cmd = Command::new("umount");
            #[cfg(not(target_os = "linux"))]
            cmd.arg(mountpoint);

            match cmd.status() {
                Ok(status) if status.success() => {
                    println!("Clean unmount of FUSE mountpoint completed successfully.");
                }
                Ok(status) => {
                    eprintln!("Unmount command returned non-zero exit status: {:?}", status.code());
                }
                Err(err) => {
                    eprintln!("Failed to execute unmount command: {:?}", err);
                }
            }
        }
        Commands::Keygen { out_dir } => {
            println!("Generating post-quantum credentials inside: {}...", out_dir);
            let out_path = Path::new(out_dir);
            if !out_path.exists() {
                if let Err(err) = std::fs::create_dir_all(out_path) {
                    eprintln!("Failed to create output directory: {:?}", err);
                    return;
                }
            }

            // Generate CRYSTALS-Kyber-768 session keys
            println!("Generating Kyber-768 credential keypair...");
            match crypto::generate_keypair() {
                Ok(keys) => {
                    let pub_file = out_path.join("kyber_public.key");
                    let sec_file = out_path.join("kyber_secret.key");
                    if let Err(err) = std::fs::write(&pub_file, &keys.public_key) {
                        eprintln!("Failed to write Kyber public key: {:?}", err);
                        return;
                    }
                    if let Err(err) = std::fs::write(&sec_file, &keys.secret_key) {
                        eprintln!("Failed to write Kyber secret key: {:?}", err);
                        return;
                    }
                    println!("Saved Kyber-768 credentials to Disk.");
                }
                Err(err) => {
                    eprintln!("Kyber credential keypair generation failed: {:?}", err);
                    return;
                }
            }

            // Generate CRYSTALS-Dilithium-3 signature keys
            println!("Generating Dilithium-3 signature keypair...");
            match crypto::generate_dilithium_keypair() {
                Ok(keys) => {
                    let pub_file = out_path.join("dilithium_public.key");
                    let sec_file = out_path.join("dilithium_secret.key");
                    if let Err(err) = std::fs::write(&pub_file, &keys.public_key) {
                        eprintln!("Failed to write Dilithium public key: {:?}", err);
                        return;
                    }
                    if let Err(err) = std::fs::write(&sec_file, &keys.secret_key) {
                        eprintln!("Failed to write Dilithium secret key: {:?}", err);
                        return;
                    }
                    println!("Saved Dilithium-3 credentials to Disk.");
                }
                Err(err) => {
                    eprintln!("Dilithium credential keypair generation failed: {:?}", err);
                    return;
                }
            }
            println!("Key generation complete. All credentials initialized successfully.");
        }
        Commands::RunDaemon => {
            println!("Starting QuantumVault Key Management Daemon in background...");
            match Command::new("keymgmt").spawn() {
                Ok(child) => {
                    println!("Successfully spawned key management daemon (PID: {}).", child.id());
                }
                Err(err) => {
                    eprintln!("Failed to spawn keymgmt daemon process: {:?}", err);
                }
            }
        }
    }
}
