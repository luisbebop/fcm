use clap::{CommandFactory, Parser, Subcommand};

mod caddy;
mod client;
mod console;
mod daemon;
mod firecracker;
mod git;
mod network;
mod vm;

const LOGO: &str = r#"
   ██████╗ ██████╗███╗   ███╗
   ██╔═══╝██╔════╝████╗ ████║
   █████╗ ██║     ██╔████╔██║
   ██╔══╝ ██║     ██║╚██╔╝██║
   ██║    ╚██████╗██║ ╚═╝ ██║
   ╚═╝     ╚═════╝╚═╝     ╚═╝
      ▄▄▄▄  ░▒▓█ FIRE █▓▒░  ▄▄▄▄
"#;

#[derive(Parser)]
#[command(name = "fcm")]
#[command(about = "Firecracker VM manager")]
#[command(before_help = LOGO)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a new VM
    Create,
    /// List all VMs
    Ls,
    /// Open persistent console session
    Console {
        /// VM name or ID (defaults to .fcm config)
        vm: Option<String>,
        /// Session ID to reconnect to (use 'fcm console ls' to list sessions)
        #[arg(short, long)]
        session: Option<String>,
        /// List active sessions instead of connecting
        #[arg(long)]
        ls: bool,
    },
    /// Stop a running VM
    Stop {
        /// VM name or ID (defaults to .fcm config)
        vm: Option<String>,
    },
    /// Start a stopped VM
    Start {
        /// VM name or ID (defaults to .fcm config)
        vm: Option<String>,
    },
    /// Destroy a VM
    Destroy {
        /// VM name or ID (defaults to .fcm config)
        vm: Option<String>,
    },
    /// Authenticate with Google
    Login,
    /// Remove authentication token
    Logout,
    /// Show current user info
    Whoami,
    /// Run the daemon (requires root)
    Daemon,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        None => {
            // No command given - check for .fcm file in current directory
            if client::show_local_vm().is_err() {
                // No local config - show help
                let _ = Cli::command().print_help();
                println!();
            }
        }
        Some(Commands::Create) => {
            if let Err(e) = client::create_vm() {
                eprintln!("Error creating VM: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Ls) => {
            if let Err(e) = client::list_vms() {
                eprintln!("Error listing VMs: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Console { vm, session, ls }) => {
            if ls {
                // List sessions
                let vm_filter = vm.as_ref().and_then(|v| {
                    // Try to resolve VM name, but don't error if it fails (might be VM name/ID filter)
                    client::resolve_vm_name(Some(v.clone())).ok()
                }).or(vm);
                if let Err(e) = client::list_sessions(vm_filter.as_deref()) {
                    eprintln!("Error listing sessions: {}", e);
                    std::process::exit(1);
                }
            } else {
                let vm_name = match client::resolve_vm_name(vm) {
                    Ok(name) => name,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        std::process::exit(1);
                    }
                };
                if let Err(e) = client::console_vm(&vm_name, session.as_deref()) {
                    eprintln!("Error opening console: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Some(Commands::Stop { vm }) => {
            let vm_name = match client::resolve_vm_name(vm) {
                Ok(name) => name,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = client::stop_vm(&vm_name) {
                eprintln!("Error stopping VM: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Start { vm }) => {
            let vm_name = match client::resolve_vm_name(vm) {
                Ok(name) => name,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = client::start_vm(&vm_name) {
                eprintln!("Error starting VM: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Destroy { vm }) => {
            let vm_name = match client::resolve_vm_name(vm) {
                Ok(name) => name,
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            };
            if let Err(e) = client::destroy_vm(&vm_name) {
                eprintln!("Error destroying VM: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Login) => {
            if let Err(e) = client::login() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Logout) => {
            if let Err(e) = client::logout() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Whoami) => {
            if let Err(e) = client::whoami() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Some(Commands::Daemon) => {
            if let Err(e) = daemon::run() {
                eprintln!("Error running daemon: {}", e);
                std::process::exit(1);
            }
        }
    }
}
