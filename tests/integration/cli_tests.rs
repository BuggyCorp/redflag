use redflag::{scanner::Scanner, Config};
use std::{fs, path::Path};
use tempfile::tempdir;

#[test]
fn test_aws_key_detection() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempdir()?;
    let file_path = dir.path().join("test.env");
    fs::write(&file_path, "AWS_KEY=AKIAEXAMPLE1234567890")?;

    let scanner = Scanner::new()?;
    let findings = scanner.scan_directory(dir.path().to_str().unwrap());
    
    assert!(!findings.is_empty());
    Ok(())
}