use thiserror::Error;

#[derive(Error, Debug)]
pub enum RedflagError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Regex compilation error: {0}")]
    Regex(#[from] regex::Error),
    
    #[error("Encoding error")]
    Encoding,
}