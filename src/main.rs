mod config;
mod error;
mod output;
mod scanner;

use clap::{Parser, Subcommand};
use crate::{
    config::Config,
    error::RedflagError,
    scanner::Scanner
};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
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
        format: output::OutputFormat,
    },
    /// Install git pre-commit hook
    InstallHook,
}

fn main() -> Result<(), RedflagError> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, config, format } => run_scan(path, config, format),
        Commands::InstallHook => install_hook(),
    }
}

fn run_scan(
    path: String,
    config_path: Option<PathBuf>,
    format: output::OutputFormat,
) -> Result<(), RedflagError> {
    let config = Config::load(config_path)?;
    let scanner = Scanner::with_config(config);
    let findings = scanner.scan_directory(&path);

    if !findings.is_empty() {
        println!("{}", output::format_findings(&findings, format));
        std::process::exit(1);
    }
    
    println!("No secrets found!");
    Ok(())
}

fn install_hook() -> Result<(), RedflagError> {
    const HOOK_CONTENT: &str = r#"#!/bin/sh
# Redflag pre-commit hook
staged_files=$(git diff --cached --name-only --diff-filter=d)
echo "Scanning for secrets..."
redflag scan $staged_files
exit $?
"#;

    let hook_path = PathBuf::from(".git/hooks/pre-commit");
    std::fs::write(hook_path, HOOK_CONTENT)?;
    println!("Pre-commit hook installed successfully");
    Ok(())
}