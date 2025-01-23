use thiserror::Error;

#[derive(Error, Debug)]
pub enum RedflagError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
    
    #[error("Encoding error")]
    Encoding,
    
    #[error("Invalid path: {0}")]
    PathError(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
}

impl From<toml::de::Error> for RedflagError {
    fn from(e: toml::de::Error) -> Self {
        RedflagError::Config(e.to_string())
    }
}