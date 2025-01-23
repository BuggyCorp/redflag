use crate::config::{Config, EntropyConfig};
use base64::Engine;
use std::collections::HashSet;

pub struct Scanner {
    patterns: Vec<(Regex, String, String)>,
    ignore_patterns: Vec<String>,
    entropy_config: EntropyConfig,
}

impl Scanner {
    pub fn new() -> Result<Self, RedflagError> {
        let config = Config::load(None)?;
        Ok(Self::with_config(config))
    }

    fn should_scan_file(&self, path: &Path) -> bool {
        let ext = path.extension()
            .and_then(|s| s.to_str())
            .unwrap_or("")
            .to_lowercase();

        self.config.extensions.iter()
            .any(|e| e.to_lowercase() == ext)
    }

    pub fn scan_directory(&self, path: &str) -> Vec<Finding> {
        // ...
        if path.is_file() && self.should_scan_file(path) {
            // scan
        }
    }

    pub fn with_config(config: Config) -> Self {
        let mut patterns = Vec::new();
        let mut seen = HashSet::new();

        // Add built-in patterns
        for p in default_secret_patterns() {
            seen.insert(p.name.clone());
            patterns.push((
                Regex::new(&p.pattern).unwrap(),
                p.name,
                p.description,
            ));
        }

        // Add custom patterns
        for p in config.patterns {
            if !seen.contains(&p.name) {
                patterns.push((
                    Regex::new(&p.pattern).unwrap(),
                    p.name,
                    p.description,
                ));
            }
        }

        Scanner {
            patterns,
            ignore_patterns: config.ignore,
            entropy_config: config.entropy,
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

    fn scan_line(&self, line: &str) -> Vec<(String, String)> {
        let mut matches = Vec::new();
        
        // Regex matches
        for (pattern, name, description) in &self.patterns {
            if pattern.is_match(line) {
                matches.push((name.clone(), description.clone()));
            }
        }

        // Entropy check
        if self.check_entropy(line) {
            matches.push((
                "high-entropy-string".into(),
                "High entropy string detected".into(),
            ));
        }

        matches
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

// Add base64 detection
fn is_base64(s: &str) -> bool {
    let engine = base64::engine::general_purpose::STANDARD;
    engine.decode(s.trim()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let random = "KJHSDfkjh324kjhKJH234KJ2H34";
        let low_entropy = "aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        
        assert!(calculate_shannon_entropy(random) > 4.0);
        assert!(calculate_shannon_entropy(low_entropy) < 2.5);
    }

    #[test]
    fn test_config_loading() {
        let config = Config::load(Some("redflag.example.toml".into())).unwrap();
        assert!(!config.patterns.is_empty());
        assert!(config.entropy.enabled);
    }
}