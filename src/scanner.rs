use encoding_rs::Encoding;
use ignore::Walk;
use regex::Regex;
use std::{
    fs,
    path::{Path, PathBuf},
    io::{self, BufRead},
};

lazy_static::lazy_static! {
    static ref DEFAULT_IGNORE: Vec<&'static str> = vec![
        "**/.git/**",
        "**/node_modules/**",
        "**/target/**",
        "**/*.lock",
        "**/*.bin",
        "**/*.pdf",
        "**/*.zip",
    ];
}

#[derive(Debug)]
pub struct Finding {
    pub file: PathBuf,
    pub line: usize,
    pub pattern_name: String,
    pub snippet: String,
}

pub struct Scanner {
    patterns: Vec<(Regex, String)>,
    ignore_patterns: Vec<String>,
}

impl Scanner {
    pub fn new() -> Self {
        let mut ignore_patterns = DEFAULT_IGNORE.iter().map(|s| s.to_string()).collect();
        
        Scanner {
            patterns: SECRET_PATTERNS.iter()
                .map(|(p, d)| (Regex::new(p).unwrap(), d.to_string()))
                .collect(),
            ignore_patterns,
        }
    }

    pub fn scan_directory(&self, path: &str) -> Vec<Finding> {
        let mut findings = Vec::new();

        for result in Walk::new(path)
            .overrides(self.ignore_patterns.clone())
            .filter_map(|e| e.ok()) 
        {
            let path = result.path();
            if path.is_file() {
                if let Some(file_findings) = self.scan_file(path) {
                    findings.extend(file_findings);
                }
            }
        }

        findings
    }

    fn scan_file(&self, path: &Path) -> Option<Vec<Finding>> {
        let content = match fs::read(path) {
            Ok(c) => c,
            Err(_) => return None,
        };

        // Detect encoding
        let (text, _, _) = Encoding::detect(&content).decode(&content);
        
        let mut findings = Vec::new();
        
        for (line_num, line) in text.lines().enumerate() {
            for (pattern, pattern_name) in &self.patterns {
                if pattern.is_match(line) {
                    findings.push(Finding {
                        file: path.to_path_buf(),
                        line: line_num + 1,
                        pattern_name: pattern_name.clone(),
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
}