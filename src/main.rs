mod config;
mod error;
mod output;
mod scanner;
mod git_scanner;

use clap::{Parser, Subcommand};
use crate::{
    config::Config,
    error::RedflagError,
    scanner::Scanner
};
use std::path::PathBuf;
use std::path::Path;
use env_logger;

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

        #[arg(long)]
        git_history: bool,

        #[arg(long)]
        git_max_depth: Option<usize>,

        #[arg(long)]
        git_since: Option<String>,

        #[arg(long)]
        git_until: Option<String>,

        #[arg(long, value_delimiter = ',')]
        git_branches: Option<Vec<String>>,
    },
    /// Install git pre-commit hook
    InstallHook,
}

fn main() -> Result<(), RedflagError> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Scan { path, config, format, git_history, git_max_depth, git_since, git_until, git_branches } => run_scan(path, config, format, git_history, GitScanOptions { max_depth: git_max_depth, branches: git_branches, since_date: git_since, until_date: git_until }),
        Commands::InstallHook => install_hook(),
    }
}

fn run_scan(
    path: String,
    config_path: Option<PathBuf>,
    format: output::OutputFormat,
    git_history: bool,
    git_options: GitScanOptions,
) -> Result<(), RedflagError> {
    let mut config = Config::load(config_path)?;
    
    // Override git config with CLI options if provided
    if git_history {
        if let Some(depth) = git_options.max_depth {
            config.git.max_depth = depth;
        }
        if let Some(branches) = git_options.branches {
            config.git.branches = branches;
        }
        if let Some(since) = git_options.since_date {
            config.git.since_date = Some(since);
        }
        if let Some(until) = git_options.until_date {
            config.git.until_date = Some(until);
        }
    }

    let scanner = Scanner::with_config(config.clone());
    let mut handler = OutputHandler::new(format);
    
    // Stream findings instead of collecting them
    scanner.scan_with_handler(&path, &mut handler)?;
    
    if git_history {
        git_scanner::scan_git_history_with_handler(Path::new(&path), &config, &mut handler)?;
    }
    
    handler.finish()?;
    Ok(())
}

struct GitScanOptions {
    max_depth: Option<usize>,
    branches: Option<Vec<String>>,
    since_date: Option<String>,
    until_date: Option<String>,
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