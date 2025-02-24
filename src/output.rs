use crate::scanner::Finding;
use std::io::{self, Write};

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json
}

pub fn format_findings(findings: &[Finding], format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => text_format(findings),
        OutputFormat::Json => serde_json::to_string_pretty(&findings).unwrap(),
    }
}

fn text_format(findings: &[Finding]) -> String {
    let mut output = String::new();
    for finding in findings {
        output.push_str(&format!(
            "{}:{} - {} - {}\nSnippet: {}{}\n\n",
            finding.file.display(),
            finding.line,
            finding.pattern_name,
            finding.description,
            finding.snippet,
            commit_info(finding)
        ));
    }
    output
}

fn commit_info(finding: &Finding) -> String {
    if let (Some(hash), Some(author), Some(date)) = (
        &finding.commit_hash,
        &finding.commit_author,
        &finding.commit_date,
    ) {
        format!("\nCommit: {} ({}, {})", hash, author, date)
    } else {
        String::new()
    }
}

pub struct OutputHandler {
    format: OutputFormat,
    findings_count: usize,
    first_finding: bool,
}

impl OutputHandler {
    pub fn new(format: OutputFormat) -> Self {
        match format {
            OutputFormat::Json => println!("["),
            _ => {}
        }
        
        Self {
            format,
            findings_count: 0,
            first_finding: true,
        }
    }

    pub fn finish(&mut self) -> io::Result<()> {
        match self.format {
            OutputFormat::Json => {
                println!("\n]");
            }
            OutputFormat::Text => {
                if self.findings_count == 0 {
                    println!("No secrets found!");
                } else {
                    println!("\nTotal findings: {}", self.findings_count);
                }
            }
        }
        
        if self.findings_count > 0 {
            std::process::exit(1);
        }
        Ok(())
    }
}

impl FindingHandler for OutputHandler {
    fn handle(&mut self, finding: Finding) {
        self.findings_count += 1;
        
        match self.format {
            OutputFormat::Text => {
                println!(
                    "{}:{} - {} - {}\nSnippet: {}{}\n",
                    finding.file.display(),
                    finding.line,
                    finding.pattern_name,
                    finding.description,
                    finding.snippet,
                    commit_info(&finding)
                );
            }
            OutputFormat::Json => {
                if !self.first_finding {
                    print!(",");
                }
                self.first_finding = false;
                print!("\n{}", serde_json::to_string_pretty(&finding).unwrap());
            }
        }
        io::stdout().flush().unwrap();
    }
}