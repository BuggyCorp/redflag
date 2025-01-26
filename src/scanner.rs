use crate::{
    config::{Config, EntropyConfig, SecretPattern},
    error::RedflagError,
};
use ignore::WalkBuilder;
use regex::Regex;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use ignore::overrides::{OverrideBuilder};

#[derive(Debug, serde::Serialize)]
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
        let config: Config = Config::load(None).map_err(|e| RedflagError::Config(e.to_string()))?;
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
        let mut override_builder = OverrideBuilder::new(path);
        for pattern in &self.ignore_patterns {
            if let Err(e) = override_builder.add(pattern) {
                eprintln!("Invalid ignore pattern '{}': {}", pattern, e);
            }
        }
        
        let overrides = match override_builder.build() {
            Ok(o) => o,
            Err(e) => {
                eprintln!("Error building ignore patterns: {}", e);
                return Vec::new();
            }
        };
    
        let walker = WalkBuilder::new(path)
            .overrides(overrides)
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
        println!("Scanning file: {}", path.display());
    
        let content = match fs::read_to_string(path) {
            Ok(c) => {
                println!("File content:\n{}", c);
                c
            }
            Err(e) => {
                eprintln!("Failed to read file {}: {}", path.display(), e);
                return None;
            }
        };
    
        let mut findings = Vec::new();
    
        for (line_num, line) in content.lines().enumerate() {
            println!("Line {}: {}", line_num + 1, line);
    
            for (pattern, name, description) in &self.patterns {
                if pattern.is_match(line) {
                    println!("Match found: {} - {}", name, line);
                    findings.push(Finding {
                        file: path.to_path_buf(),
                        line: line_num + 1,
                        pattern_name: name.clone(),
                        description: description.clone(),
                        snippet: line.chars().take(50).collect(),
                    });
                }
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
    if s.is_empty() {
        return 0.0;
    }
    
    let mut counts = [0u32; 256];
    let length = s.len() as f64;

    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }

    counts
        .iter()
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

    #[test]
    fn test_regex_pattern() {
        let pattern = r#"api_key\s*=\s*"test_key_\d{10}""#;
        let re = Regex::new(pattern).unwrap();
    
        let test_input = r#"let api_key = "test_key_1234567890";"#;
        assert!(re.is_match(test_input), "Regex pattern did not match test input");
    }

    #[test]
    fn test_entropy_calculation() {
        // Test known values
        let random = "mR7hJ8q$Lz@w!bE5"; // 16 random chars
        let low_entropy = "aaaaaaaaaaaaaaaa"; // 16 identical chars
        
        let random_entropy = calculate_shannon_entropy(random);
        let low_entropy_val = calculate_shannon_entropy(low_entropy);
        
        // Check relative values without fixed thresholds
        assert!(random_entropy > 3.0, "Random entropy was {}", random_entropy);
        assert!(low_entropy_val < 1.5, "Low entropy was {}", low_entropy_val);
        assert!(random_entropy > low_entropy_val);
    }

    #[test]
    fn test_file_scanning() -> Result<(), RedflagError> {
        let dir = tempfile::tempdir()?;
        let file_path = dir.path().join("test_file.rs");
    
        // Write a test file with a known secret pattern
        fs::write(&file_path, r#"let api_key = "test_key_1234567890";"#)?;
    
        // Create a scanner with a specific pattern for testing
        let config = Config {
            patterns: vec![SecretPattern {
                name: "test-key".to_string(),
                pattern: r#"api_key\s*=\s*"test_key_\d{10}""#.to_string(),
                description: "Test key pattern".to_string(),
            }],
            extensions: vec!["rs".to_string()], // Ensure the file extension is included
            ..Config::default()
        };
    
        let scanner = Scanner::with_config(config);
    
        let findings = scanner.scan_directory(dir.path().to_str().unwrap());
    
        assert!(!findings.is_empty(), "No findings detected");
        Ok(())
    }
}