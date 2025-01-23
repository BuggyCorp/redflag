use redflag::{Scanner, Finding};
use std::path::Path;

#[test]
fn test_detect_aws_key() {
    let scanner = Scanner::new().unwrap();
    let findings = scanner.scan_file(Path::new("tests/testdata/aws_credentials.txt"))
        .expect("Should scan file");
    
    assert!(!findings.is_empty());
    assert!(findings.iter().any(|f| f.pattern_name == "aws-access-key"));
}