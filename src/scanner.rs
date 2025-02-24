use crate::{
    config::{Config, EntropyConfig, ExclusionPolicy, Severity, SecretPattern},
    error::RedflagError,
};
use glob::Pattern;
use ignore::overrides::OverrideBuilder;
use ignore::WalkBuilder;
use regex::Regex;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use once_cell::sync::Lazy;

const IGNORE_COMMENT_PATTERN: &str = r"(?i)//\s*redflag-ignore(?:-next)?(?:\s+.*)?$";
static IGNORE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(IGNORE_COMMENT_PATTERN).unwrap());

#[derive(Debug, serde::Serialize, Clone)]
pub struct Finding {
    pub file: PathBuf,
    pub line: usize,
    pub pattern_name: String,
    pub description: String,
    pub snippet: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_date: Option<String>,
}

pub struct Scanner {
    patterns: Vec<(Regex, String, String, Severity)>,
    entropy_config: EntropyConfig,
    extensions: Vec<String>,
    exclusions: Vec<ExclusionRule>,
}

#[derive(Debug, Clone)]
struct ExclusionRule {
    pattern: Pattern,
    policy: ExclusionPolicy,
}

pub trait FindingHandler {
    fn handle(&mut self, finding: Finding);
}

impl Scanner {
    pub fn with_config(config: Config) -> Self {
        let mut patterns = Vec::new();
        let mut seen = HashSet::new();

        // Process all patterns
        for p in config.patterns {
            if seen.contains(&p.name) {
                continue;
            }
            match Regex::new(&p.pattern) {
                Ok(re) => {
                    seen.insert(p.name.clone());
                    patterns.push((re, p.name, p.description, p.severity));
                }
                Err(e) => eprintln!("Invalid pattern {}: {}", p.name, e),
            }
        }

        // Compile exclusion patterns
        let exclusions = config.exclusions
            .into_iter()
            .filter_map(|r| match Pattern::new(&r.pattern) {
                Ok(pattern) => Some(ExclusionRule {
                    pattern,
                    policy: r.policy,
                }),
                Err(e) => {
                    eprintln!("Invalid exclusion pattern '{}': {}", r.pattern, e);
                    None
                }
            })
            .collect();

        Scanner {
            patterns,
            entropy_config: config.entropy,
            extensions: config.extensions,
            exclusions,
        }
    }

    pub fn scan_directory(&self, path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut override_builder = OverrideBuilder::new(path);

        // Add ignore patterns to walker
        for rule in &self.exclusions {
            if rule.policy == ExclusionPolicy::Ignore {
                if let Err(e) = override_builder.add(&rule.pattern.to_string()) {
                    eprintln!("Invalid ignore pattern: {}", e);
                }
            }
        }

        let walker = WalkBuilder::new(path)
            .overrides(override_builder.build().unwrap())
            .build();

        for entry in walker.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_file() && self.should_scan_file(path) {
                match self.get_file_policy(path) {
                    ExclusionPolicy::Ignore => continue,
                    policy => {
                        if let Some(mut file_findings) = self.scan_file(path, policy) {
                            findings.append(&mut file_findings);
                        }
                    }
                }
            }
        }

        findings
    }

    fn get_file_policy(&self, path: &Path) -> ExclusionPolicy {
        let path_str = path.to_string_lossy();
        self.exclusions
            .iter()
            .rev()
            .find(|r| r.pattern.matches(&path_str))
            .map(|r| r.policy.clone())
            .unwrap_or(ExclusionPolicy::ScanButAllow) // Changed from Ignore to ScanButAllow
    }

    fn should_scan_file(&self, path: &Path) -> bool {
        path.extension()
            .and_then(|ext| ext.to_str())
            .map(|ext| self.extensions.iter().any(|e| e.eq_ignore_ascii_case(ext)))
            .unwrap_or(false)
    }

    fn scan_file(&self, path: &Path, policy: ExclusionPolicy) -> Option<Vec<Finding>> {
        let content = match fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to read file {}: {}", path.display(), e);
                return None;
            }
        };

        let mut findings = Vec::new();
        let mut ignore_next_line = false;

        for (line_num, line) in content.lines().enumerate() {
            // Check for ignore comments
            if IGNORE_REGEX.is_match(line) {
                if line.to_lowercase().contains("ignore-next") {
                    ignore_next_line = true;
                }
                continue;
            }

            if ignore_next_line {
                ignore_next_line = false;
                continue;
            }

            // Skip if line appears to be in a test file or test function
            if self.is_test_context(path, line) {
                continue;
            }

            // Check regex patterns
            for (pattern, name, description, severity) in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(self.create_finding(path, line_num + 1, line, name, description, *severity));
                }
            }

            // Check entropy
            if self.entropy_config.enabled {
                let clean_line = line.replace(|c: char| !c.is_ascii_alphanumeric(), "");
                if clean_line.len() >= self.entropy_config.min_length &&
                    calculate_shannon_entropy(&clean_line) >= self.entropy_config.threshold {
                    findings.push(self.create_finding(
                        path,
                        line_num + 1,
                        line,
                        "high-entropy",
                        "High entropy string detected",
                        Severity::Medium,
                    ));
                }
            }
        }

        match policy {
            ExclusionPolicy::ScanButWarn => {
                for finding in &findings {
                    println!("WARNING: Potential secret found but allowed: {:?}", finding);
                }
                None
            }
            ExclusionPolicy::ScanButAllow => {
                if findings.is_empty() {
                    None
                } else {
                    Some(findings)
                }
            }
            _ => if findings.is_empty() { None } else { Some(findings) },
        }
    }

    fn is_test_context(&self, path: &Path, line: &str) -> bool {
        // Check if file is a test file
        let file_name = path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        
        if file_name.contains("test") || file_name.contains("spec") {
            return true;
        }

        // Check for common test patterns in the line
        let test_patterns = [
            r"#\[test\]",
            r"describe\s*\(",
            r"it\s*\(",
            r"test\s*\(",
            r"assert",
            r"expect\s*\(",
            r"mock\s*\(",
            r"fixture",
        ];

        test_patterns.iter().any(|pattern| {
            Regex::new(pattern).map(|re| re.is_match(line)).unwrap_or(false)
        })
    }

    fn create_finding(&self, path: &Path, line: usize, text: &str, name: &str, desc: &str, severity: Severity) -> Finding {
        Finding {
            file: path.to_path_buf(),
            line,
            pattern_name: name.to_string(),
            description: desc.to_string(),
            snippet: text.chars().take(50).collect(),
            severity,
            commit_hash: None,
            commit_author: None,
            commit_date: None,
        }
    }

    pub fn scan_with_handler<H: FindingHandler>(&self, path: &str, handler: &mut H) -> Result<(), RedflagError> {
        let findings = self.scan_directory(path);
        for finding in findings {
            handler.handle(finding);
        }
        Ok(())
    }
}

pub(crate) fn calculate_shannon_entropy(s: &str) -> f64 {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_regex_pattern() {
        let pattern = r#"api_key\s*=\s*"test_key_\d{10}""#;
        let re = Regex::new(pattern).unwrap();

        let test_input = r#"let api_key = "test_key_1234567890";"#;
        assert!(
            re.is_match(test_input),
            "Regex pattern did not match test input"
        );
    }

    #[test]
    fn test_entropy_calculation() {
        // Test known values
        let random = "mR7hJ8q$Lz@w!bE5"; // 16 random chars
        let low_entropy = "aaaaaaaaaaaaaaaa"; // 16 identical chars

        let random_entropy = calculate_shannon_entropy(random);
        let low_entropy_val = calculate_shannon_entropy(low_entropy);

        // Check relative values without fixed thresholds
        assert!(
            random_entropy > 3.0,
            "Random entropy was {}",
            random_entropy
        );
        assert!(low_entropy_val < 1.5, "Low entropy was {}", low_entropy_val);
        assert!(random_entropy > low_entropy_val);
    }

    #[test]
    fn test_file_scanning() -> Result<(), RedflagError> {
        let dir = tempfile::tempdir()?;
        let file_path = dir.path().join("secrets.rs");
    
        fs::write(&file_path, r#"let api_key = "test_key_1234567890";"#)?;
    
        let config = Config {
            patterns: vec![SecretPattern {
                name: "test-key".to_string(),
                pattern: r#"api_key\s*=\s*"[^"]*""#.to_string(),
                description: "Test key pattern".to_string(),
                severity: Severity::High,
            }],
            extensions: vec!["rs".to_string()],
            exclusions: vec![], // Clear default exclusions
            entropy: EntropyConfig {
                enabled: false,
                ..Default::default()
            },
            ..Config::default()
        };
    
        let scanner = Scanner::with_config(config);
        let findings = scanner.scan_directory(dir.path().to_str().unwrap());
    
        assert!(!findings.is_empty(), "No findings detected");
        Ok(())
    }
}
