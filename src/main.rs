use clap::{Parser, Subcommand};

mod caddy;
mod client;
mod console;
mod daemon;
mod firecracker;
mod network;
mod session;
mod vm;

#[derive(Parser)]
#[command(name = "fcm")]
#[command(about = "Simple Firecracker VM manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new VM
    Create,
    /// List all VMs
    Ls,
    /// Open persistent console session
    Console {
        /// VM name or ID
        vm: String,
    },
    /// List active sessions for a VM
    Sessions {
        /// VM name or ID
        vm: String,
    },
    /// Reattach to an existing session
    Attach {
        /// VM name or ID
        vm: String,
        /// Session ID
        session_id: String,
    },
    /// Stop a running VM
    Stop {
        /// VM name or ID
        vm: String,
    },
    /// Start a stopped VM
    Start {
        /// VM name or ID
        vm: String,
    },
    /// Destroy a VM
    Destroy {
        /// VM name or ID
        vm: String,
    },
    /// Run the daemon (requires root)
    Daemon,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Create => {
            if let Err(e) = client::create_vm() {
                eprintln!("Error creating VM: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Ls => {
            if let Err(e) = client::list_vms() {
                eprintln!("Error listing VMs: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Console { vm } => {
            if let Err(e) = client::console_vm(&vm) {
                eprintln!("Error opening console: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Sessions { vm } => {
            if let Err(e) = client::list_sessions(&vm) {
                eprintln!("Error listing sessions: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Attach { vm, session_id } => {
            if let Err(e) = client::attach_session(&vm, &session_id) {
                eprintln!("Error attaching to session: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Stop { vm } => {
            if let Err(e) = client::stop_vm(&vm) {
                eprintln!("Error stopping VM: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Start { vm } => {
            if let Err(e) = client::start_vm(&vm) {
                eprintln!("Error starting VM: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Destroy { vm } => {
            if let Err(e) = client::destroy_vm(&vm) {
                eprintln!("Error destroying VM: {}", e);
                std::process::exit(1);
            }
        }
        Commands::Daemon => {
            if let Err(e) = daemon::run() {
                eprintln!("Error running daemon: {}", e);
                std::process::exit(1);
            }
        }
    }
}
