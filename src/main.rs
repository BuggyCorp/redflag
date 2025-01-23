use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan directory for secrets
    Scan {
        #[arg(default_value = ".")]
        path: String,
        
        #[arg(short, long)]
        config: Option<String>,
    },
    /// Install git pre-commit hook
    InstallHook,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, config } => run_scan(path, config),
        Commands::InstallHook => install_hook(),
    }
}