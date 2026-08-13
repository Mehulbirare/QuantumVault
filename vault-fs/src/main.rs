use std::env;
use std::process;

fn main() {
    // Initialize env logger for debugging
    env_logger::init();

    println!("=========================================");
    #[cfg(target_os = "linux")]
    println!("QuantumVault FUSE Filesystem (Linux)");
    #[cfg(not(target_os = "linux"))]
    println!("QuantumVault FUSE Filesystem (Non-Linux Mock)");
    println!("=========================================");

    // Parse arguments (expect mount point)
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <MOUNT_POINT>", args[0]);
        process::exit(1);
    }

    let mountpoint = &args[1];
    println!("Target mount point configured: {}", mountpoint);
}
