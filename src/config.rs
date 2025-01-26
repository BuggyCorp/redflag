use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::RedflagError;
use log::warn;


#[derive(Debug, Serialize, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default = "default_ignore_patterns")]
    pub ignore: Vec<String>,
    
    #[serde(default = "default_secret_patterns")]
    pub patterns: Vec<SecretPattern>,
    
    #[serde(default)]
    pub entropy: EntropyConfig,

    #[serde(default = "default_extensions")]
    pub extensions: Vec<String>
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SecretPattern {
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub fn load(user_path: Option<PathBuf>) -> Result<Self, RedflagError> {
        // Try user-specified config first
        if let Some(path) = user_path {
            if path.exists() {
                let content = std::fs::read_to_string(&path)
                    .map_err(|e| RedflagError::Config(format!("Failed to read config file {}: {}", path.display(), e)))?;
                return toml::from_str(&content)
                    .map_err(|e| RedflagError::Config(format!("Invalid config file {}: {}", path.display(), e)));
            }
            return Err(RedflagError::Config(format!("Config file not found: {}", path.display())));
        }

        // Try default locations
        let default_paths = [
            PathBuf::from("redflag.toml"),
            PathBuf::from(".redflag.toml"),
            PathBuf::from("config/redflag.toml"),
        ];

        for path in default_paths.iter() {
            if path.exists() {
                let content = std::fs::read_to_string(path)
                    .map_err(|e| RedflagError::Config(format!("Failed to read config file {}: {}", path.display(), e)))?;
                return toml::from_str(&content)
                    .map_err(|e| RedflagError::Config(format!("Invalid config file {}: {}", path.display(), e)));
            }
        }

        // Fallback to defaults with warning
        warn!("No configuration file found. Using default settings.");
        Ok(Config::default())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            ignore: default_ignore_patterns(),
            patterns: default_secret_patterns(),
            entropy: EntropyConfig::default(),
            extensions: default_extensions(),
            whitelist: vec![
                WhitelistRule {
                    path: PathBuf::from("docs/examples.conf"),
                    reason: Some("Example configuration".to_string()),
                }
            ],
        }
    }
}