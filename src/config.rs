use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default = "default_ignore_patterns")]
    pub ignore: Vec<String>,
    
    #[serde(default = "default_secret_patterns")]
    pub patterns: Vec<SecretPattern>,
    
    #[serde(default)]
    pub entropy: EntropyConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
}

fn default_ignore_patterns() -> Vec<String> {
    vec![
        "**/.git/**".into(),
        "**/node_modules/**".into(),
        "**/target/**".into(),
        "**/*.lock".into(),
        "**/*.bin".into(),
    ]
}

fn default_secret_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws-access-key".into(),
            pattern: r"(?i)aws_access_key_id\s*=\s*['\"]?[A-Z0-9/+=]{20}['\"]?".into(),
            description: "AWS Access Key ID".into(),
        },
        SecretPattern {
            name: "generic-api-key".into(),
            pattern: r"(?i)(api|access)[_-]?key\s*=\s*['\"]?[A-Za-z0-9]{32,45}['\"]?".into(),
            description: "Generic API Key".into(),
        },
    ]
}

fn default_true() -> bool { true }
fn default_threshold() -> f64 { 3.5 }
fn default_min_length() -> usize { 20 }

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self, anyhow::Error> {
        let default_path = PathBuf::from("redflag.toml");
        let config_path = path.or_else(|| Some(default_path)).unwrap();
        
        if config_path.exists() {
            let content = std::fs::read_to_string(config_path)?;
            Ok(toml::from_str(&content)?)
        } else {
            Ok(Config::default())
        }
    }
}