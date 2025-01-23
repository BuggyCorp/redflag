use clap::{Parser, Subcommand};
use redflag::{error::RedflagError, scanner::Scanner};
use std::path::PathBuf;

mod config;
mod error;
mod scanner;

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
        config: Option<PathBuf>,
        
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
    /// Install git pre-commit hook
    InstallHook,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

fn main() -> Result<(), RedflagError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, config, format } => run_scan(path, config, format),
        Commands::InstallHook => install_hook(),
    }
}

fn run_scan(path: String, config: Option<PathBuf>, format: OutputFormat) -> Result<(), RedflagError> {
    let config = config::Config::load(config)?;
    let scanner = scanner::Scanner::with_config(config);
    let findings = scanner.scan_directory(&path);

    if !findings.is_empty() {
        let output = output::format_findings(&findings, format);
        println!("{}", output);
        std::process::exit(1);
    }
    
    println!("No secrets found!");
    Ok(())
}

fn install_hook() -> Result<(), RedflagError> {
    // Implementation from previous step
    // ...
    Ok(())
}