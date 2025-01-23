use crate::{
    config::{Config, EntropyConfig, SecretPattern},
    error::RedflagError,
};
use encoding_rs::Encoding;
use ignore::WalkBuilder;
use regex::Regex;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug)]
pub struct Finding {
    pub file: PathBuf,
    pub line: usize,
    pub pattern_name: String,
    pub description: String,
    pub snippet: String,
}

pub struct Scanner {
    patterns: Vec<(Regex, String, String)>,
    ignore_patterns: Vec<String>,
    entropy_config: EntropyConfig,
    extensions: Vec<String>,
}

impl Scanner {
    pub fn new() -> Result<Self, RedflagError> {
        let config = Config::load(None)?;
        Ok(Self::with_config(config))
    }

    pub fn with_config(config: Config) -> Self {
        let mut patterns = Vec::new();
        let mut seen = HashSet::new();

        // Process built-in patterns
        for p in default_secret_patterns() {
            if seen.contains(&p.name) {
                continue;
            }
            match Regex::new(&p.pattern) {
                Ok(re) => {
                    seen.insert(p.name.clone());
                    patterns.push((re, p.name, p.description));
                }
                Err(e) => eprintln!("Invalid built-in pattern {}: {}", p.name, e),
            }
        }

        // Process custom patterns
        for p in config.patterns {
            if seen.contains(&p.name) {
                continue;
            }
            match Regex::new(&p.pattern) {
                Ok(re) => {
                    seen.insert(p.name.clone());
                    patterns.push((re, p.name, p.description));
                }
                Err(e) => eprintln!("Invalid custom pattern {}: {}", p.name, e),
            }
        }

        Scanner {
            patterns,
            ignore_patterns: config.ignore,
            entropy_config: config.entropy,
            extensions: config.extensions,
        }
    }

    pub fn scan_directory(&self, path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let walker = WalkBuilder::new(path)
            .overrides(self.ignore_patterns.iter().map(|s| s.as_str()))
            .build();

        for entry in walker.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && self.should_scan_file(path) {
                if let Some(mut file_findings) = self.scan_file(path) {
                    findings.append(&mut file_findings);
                }
            }
        }

        findings
    }

    fn should_scan_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| self.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)))
            .unwrap_or(false)
    }

    fn scan_file(&self, path: &Path) -> Option<Vec<Finding>> {
        let content = match fs::read(path) {
            Ok(c) => c,
            Err(_) => return None,
        };

        let (text, _, _) = Encoding::detect(&content).decode(&content);
        let mut findings = Vec::new();

        for (line_num, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Check regex patterns
            for (pattern, name, description) in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(Finding {
                        file: path.to_path_buf(),
                        line: line_num + 1,
                        pattern_name: name.clone(),
                        description: description.clone(),
                        snippet: line.chars().take(50).collect(),
                    });
                }
            }

            // Check entropy
            if self.check_entropy(line) {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    pattern_name: "high-entropy".to_string(),
                    description: "High entropy string detected".to_string(),
                    snippet: line.chars().take(50).collect(),
                });
            }
        }

        if findings.is_empty() {
            None
        } else {
            Some(findings)
        }
    }

    fn check_entropy(&self, text: &str) -> bool {
        if !self.entropy_config.enabled {
            return false;
        }
        
        let clean_text = text.replace(|c: char| !c.is_ascii_alphanumeric(), "");
        if clean_text.len() < self.entropy_config.min_length {
            return false;
        }

        let entropy = calculate_shannon_entropy(&clean_text);
        entropy >= self.entropy_config.threshold
    }
}

fn calculate_shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let length = s.len() as f64;
    
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }

    counts.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / length;
            -p * p.log2()
        })
        .sum()
}

fn default_secret_patterns() -> Vec<SecretPattern> {
    Config::default().patterns
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_entropy_calculation() {
        let random = "KJHSDfkjh324kjhKJH234KJ2H34";
        let low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        
        assert!(calculate_shannon_entropy(random) > 4.0);
        assert!(calculate_shannon_entropy(low_entropy) < 2.5);
    }

    #[test]
    fn test_file_scanning() -> Result<(), RedflagError> {
        let dir = tempdir()?;
        let file_path = dir.path().join("test.rs");
        fs::write(&file_path, r#"let api_key = "ABCDEFGHIJK1234567890";"#)?;

        let scanner = Scanner::new()?;
        let findings = scanner.scan_directory(dir.path().to_str().unwrap());

        assert!(!findings.is_empty());
        Ok(())
    }
}