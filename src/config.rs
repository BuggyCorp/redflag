use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::RedflagError;

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default = "default_ignore_patterns")]
    pub ignore: Vec<String>,
    
    #[serde(default = "default_secret_patterns")]
    pub patterns: Vec<SecretPattern>,
    
    #[serde(default)]
    pub entropy: EntropyConfig,

    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EntropyConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_threshold")]
    pub threshold: f64,
    #[serde(default = "default_min_length")]
    pub min_length: usize,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        EntropyConfig {
            enabled: default_true(),
            threshold: default_threshold(),
            min_length: default_min_length(),
        }
    }
}

fn default_extensions() -> Vec<String> {
    vec![
        "rs", "py", "js", "ts", "java", "go", 
        "php", "rb", "sh", "yaml", "yml", "toml",
        "env", "tf"
    ].iter().map(|s| s.to_string()).collect()
}

fn default_ignore_patterns() -> Vec<String> {
    vec![
        "**/.git/**".to_string(),
        "**/node_modules/**".to_string(),
        "**/target/**".to_string(),
        "**/*.lock".to_string(),
        "**/*.bin".to_string(),
    ]
}

fn default_secret_patterns() -> Vec<SecretPattern> {
    vec![
        SecretPattern {
            name: "aws-access-key".to_string(),
            pattern: r#"(?i)aws_access_key_id\s*=\s*['"]?[A-Z0-9/+=]{20}['"]?"#.to_string(),
            description: "AWS Access Key ID".to_string(),
        },
        SecretPattern {
            name: "generic-api-key".to_string(),
            pattern: r#"(?i)(api|access)[_-]?key\s*=\s*['"]?[A-Za-z0-9]{32,45}['"]?"#.to_string(),
            description: "Generic API Key".to_string(),
        },
    ]
}

fn default_true() -> bool { true }
fn default_threshold() -> f64 { 3.5 }
fn default_min_length() -> usize { 20 }

impl Config {
    pub fn load(path: Option<PathBuf>) -> Result<Self, RedflagError> {
        let config_path: PathBuf = path.unwrap_or_else(|| PathBuf::from("redflag.toml"));
        
        let content = std::fs::read_to_string(config_path)
            .map_err(|e| RedflagError::Config(e.to_string()))?;
            
        toml::from_str(&content)
            .map_err(|e| RedflagError::Config(e.to_string()))
    }
}