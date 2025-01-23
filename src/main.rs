use std::{
    fs,
    path::PathBuf,
    process::exit,
};

fn install_hook() {
    let hook_content = r#"#!/bin/sh
# Redflag pre-commit hook
staged_files=$(git diff --cached --name-only --diff-filter=d)

echo "Scanning for secrets..."
redflag scan $staged_files

if [ $? -ne 0 ]; then
    echo "Secrets detected! Commit blocked."
    exit 1
fi
"#;

    let git_dir = PathBuf::from(".git");
    if !git_dir.exists() {
        eprintln!("Not a git repository");
        exit(1);
    }

    let hook_path = git_dir.join("hooks").join("pre-commit");
    if let Err(e) = fs::write(&hook_path, hook_content) {
        eprintln!("Failed to write hook: {}", e);
        exit(1);
    }

    println!("Pre-commit hook installed at {}", hook_path.display());
}

fn run_scan(path: String, _config: Option<String>) {
    let scanner = Scanner::new();
    let findings = scanner.scan_directory(&path);

    if findings.is_empty() {
        println!("No secrets found!");
        return;
    }

    println!("{} potential secrets found:", findings.len());
    for finding in findings {
        println!(
            "{}:{} - {} - {}",
            finding.file.display(),
            finding.line,
            finding.pattern_name,
            finding.snippet
        );
    }

    exit(1);
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Json,
    Sarif,
}

#[derive(Subcommand)]
enum Commands {
    Scan {
        // ...
        #[arg(short, long, value_enum, default_value = "text")]
        format: OutputFormat,
    },
}