use clap::{Parser, Subcommand};

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
            println!("Mounting QuantumVault FUSE filesystem...");
            println!("Backend Store: {}", backend);
            println!("Mount Point: {}", mountpoint);
        }
        Commands::Keygen { out_dir } => {
            println!("Generating post-quantum credentials inside: {}...", out_dir);
        }
        Commands::RunDaemon => {
            println!("Starting QuantumVault Key Management Daemon in background...");
        }
    }
}
