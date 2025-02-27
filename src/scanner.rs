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
    sync::{Arc, Mutex},
};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

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
        // Print all extensions we're looking for
        println!("Extensions to scan: {:?}", self.extensions);
        
        let path = Path::new(path);
        if !path.is_dir() {
            if path.is_file() {
                println!("Scanning single file: {}", path.display());
                if let Some(file_findings) = self.scan_file(path, ExclusionPolicy::ScanButAllow) {
                    return file_findings;
                }
            }
            return Vec::new();
        }
        
        // First, collect all files to scan, properly filtering out excluded files
        let files_to_scan: Vec<PathBuf> = WalkDir::new(path)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| {
                let path = entry.path();
                
                // Skip directories but check exclusions for traversal
                if path.is_dir() {
                    // We're only collecting files, so return false for directories
                    return false;
                }
                
                // Check if file should be excluded based on path
                let path_str = path.to_string_lossy();
                let should_exclude = self.exclusions.iter()
                    .filter(|rule| rule.policy == ExclusionPolicy::Ignore)
                    .any(|rule| rule.pattern.matches(&path_str));
                
                if should_exclude {
                    return false;
                }
                
                // Check if file should be scanned based on extension
                if path.is_file() {
                    if let Some(ext) = path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        return self.extensions.iter().any(|e| e.to_lowercase() == ext_str);
                    }
                }
                
                false
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();
        
        // Create a progress bar with the accurate count of files to scan
        let total_files = files_to_scan.len();
        println!("Total files to scan: {}", total_files);
        
        let progress_bar = ProgressBar::new(total_files as u64);
        progress_bar.set_style(ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} files ({eta})")
            .unwrap()
            .progress_chars("=>-"));
        
        // Create a thread-safe container for findings
        let findings = Arc::new(Mutex::new(Vec::new()));
        
        // Process files in parallel
        files_to_scan.par_iter().for_each(|file_path| {
            // Get the policy for this file
            let policy = self.get_file_policy(file_path);
            
            // Scan the file
            if let Some(file_findings) = self.scan_file(file_path, policy) {
                // Add findings to the shared container
                if !file_findings.is_empty() {
                    let mut findings_lock = findings.lock().unwrap();
                    findings_lock.extend(file_findings);
                }
            }
            
            // Update progress
            progress_bar.inc(1);
        });
        
        progress_bar.finish_with_message("Scan complete");
        
        // Return the findings
        let result = findings.lock().unwrap().clone();
        result
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
                // Skip environment file pattern if it's just accessing an environment variable
                if name == "Environment File" && (line.contains("process.env.") || line.contains("env.") || line.contains("ENV[")) {
                    continue;
                }
                
                if pattern.is_match(line) {
                    findings.push(self.create_finding(path, line_num + 1, line, name, description, *severity));
                }
            }

            // Check entropy, but with improved filtering for false positives
            if self.entropy_config.enabled {
                // Skip entropy check for common programming patterns that cause false positives
                if should_skip_entropy_check(line) {
                    continue;
                }
                
                // Extract potential secrets from the line
                if let Some(potential_secret) = extract_potential_secret(line) {
                    // Only check entropy on the extracted potential secret
                    if potential_secret.len() >= self.entropy_config.min_length &&
                        calculate_shannon_entropy(&potential_secret) >= self.entropy_config.threshold {
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

// Helper function to determine if a line should skip entropy check
fn should_skip_entropy_check(line: &str) -> bool {
    // Skip common programming patterns that cause false positives
    
    // Skip environment variable access
    if line.contains("process.env.") || line.contains("env.") || 
       line.contains("ENV[") || line.contains("getenv(") ||
       line.contains("os.environ") {
        return true;
    }
    
    // Skip array/object assignments and method calls with simple values
    if line.contains(".push(") || line.contains(".append(") || 
       line.contains(".add(") || line.contains(".set(") ||
       line.contains(".map(") || line.contains(".filter(") ||
       line.contains(".forEach(") || line.contains(".reduce(") ||
       line.contains(".find(") || line.contains(".findIndex(") ||
       line.contains(".includes(") || line.contains(".indexOf(") ||
       line.contains(".some(") || line.contains(".every(") ||
       line.contains(".join(") || line.contains(".split(") {
        return true;
    }
    
    // Skip import statements
    if line.contains("import ") || line.contains("require(") || 
       line.contains("from '") || line.contains("from \"") ||
       line.contains("export ") || line.contains("module.exports") {
        return true;
    }
    
    // Skip common UI/display text patterns
    if line.contains("label") || line.contains("text:") || 
       line.contains("title:") || line.contains("message:") ||
       line.contains("placeholder") || line.contains("description:") ||
       line.contains("tooltip") || line.contains("caption") ||
       line.contains("heading") || line.contains("header") ||
       line.contains("footer") || line.contains("button") {
        return true;
    }
    
    // Skip HTML/JSX/TSX patterns
    if line.contains("<") && line.contains(">") && 
       (line.contains("className") || line.contains("style=") || 
        line.contains("id=") || line.contains("name=") ||
        line.contains("onClick") || line.contains("onChange") ||
        line.contains("onSubmit") || line.contains("onBlur") ||
        line.contains("value=") || line.contains("type=")) {
        return true;
    }
    
    // Skip common variable assignments with low-risk content
    if line.contains("const ") || line.contains("let ") || line.contains("var ") {
        if line.contains("name") || line.contains("title") || 
           line.contains("label") || line.contains("text") ||
           line.contains("options") || line.contains("config") ||
           line.contains("data") || line.contains("obj") ||
           line.contains("number") || line.contains("count") ||
           line.contains("index") || line.contains("value") ||
           line.contains("budget") || line.contains("goal") ||
           line.contains("total") || line.contains("sum") ||
           line.contains("result") || line.contains("info") ||
           line.contains("status") || line.contains("state") ||
           line.contains("props") || line.contains("params") ||
           line.contains("args") || line.contains("options") ||
           line.contains("settings") || line.contains("config") ||
           line.contains("format") || line.contains("style") ||
           line.contains("element") || line.contains("component") ||
           line.contains("handler") || line.contains("callback") ||
           line.contains("event") || line.contains("listener") ||
           line.contains("function") || line.contains("method") {
            return true;
        }
    }
    
    // Skip array/object property access and assignments
    if (line.contains("[") && line.contains("]")) ||
       (line.contains(".") && line.contains("=")) {
        return true;
    }
    
    // Skip TypeScript/JavaScript specific patterns
    if line.contains("?.") || line.contains("??") || 
       line.contains("||=") || line.contains("&&=") || 
       line.contains("+=") || line.contains("-=") || 
       line.contains("*=") || line.contains("/=") ||
       line.contains("++") || line.contains("--") ||
       line.contains("=>") || line.contains("?:") {
        return true;
    }
    
    // Skip lines with common programming variable naming patterns
    if line.contains("Id") || line.contains("Name") || 
       line.contains("Obj") || line.contains("Data") || 
       line.contains("Type") || line.contains("Info") || 
       line.contains("Config") || line.contains("Params") || 
       line.contains("Args") || line.contains("Props") || 
       line.contains("State") || line.contains("Context") ||
       line.contains("Service") || line.contains("Controller") ||
       line.contains("Component") || line.contains("Provider") ||
       line.contains("Factory") || line.contains("Builder") ||
       line.contains("Manager") || line.contains("Handler") ||
       line.contains("Callback") || line.contains("Listener") ||
       line.contains("Formatter") || line.contains("Parser") ||
       line.contains("Validator") || line.contains("Helper") ||
       line.contains("Util") || line.contains("Model") ||
       line.contains("View") || line.contains("Store") {
        return true;
    }
    
    // Skip lines with common programming operations
    if line.contains("typeof") || line.contains("instanceof") ||
       line.contains(" in ") || line.contains(" of ") ||
       line.contains(" as ") || line.contains(" is ") {
        return true;
    }
    
    // Skip lines with common programming function calls
    if line.contains("(") && line.contains(")") && 
       (line.contains("get") || line.contains("set") || 
        line.contains("find") || line.contains("filter") || 
        line.contains("map") || line.contains("reduce") || 
        line.contains("format") || line.contains("parse") || 
        line.contains("convert") || line.contains("transform") || 
        line.contains("calculate") || line.contains("compute") ||
        line.contains("create") || line.contains("update") ||
        line.contains("delete") || line.contains("remove") ||
        line.contains("add") || line.contains("insert") ||
        line.contains("sort") || line.contains("order") ||
        line.contains("group") || line.contains("join") ||
        line.contains("split") || line.contains("merge") ||
        line.contains("validate") || line.contains("check") ||
        line.contains("test") || line.contains("verify")) {
        return true;
    }
    
    false
}

// Helper function to extract potential secrets from a line
fn extract_potential_secret(line: &str) -> Option<String> {
    // Skip lines that are clearly code and not secrets
    if is_likely_code_not_secret(line) {
        return None;
    }
    
    // Direct check for AWS keys in the format: key: process.env.AWS_ACCESS_KEY_ID || 'AKIAJYMNBA2KL7M6CWLA'
    if line.contains("key:") && line.contains("AWS_ACCESS_KEY_ID") && line.contains("||") {
        if let Some(aws_key_start) = line.find("AKIA") {
            let aws_key_part = &line[aws_key_start..];
            if let Some(end_quote) = aws_key_part.find('\'') {
                let aws_key = &aws_key_part[0..end_quote];
                if aws_key.len() >= 20 {
                    return Some(aws_key.to_string());
                }
            } else if let Some(end_quote) = aws_key_part.find('"') {
                let aws_key = &aws_key_part[0..end_quote];
                if aws_key.len() >= 20 {
                    return Some(aws_key.to_string());
                }
            }
        }
    }
    
    // Direct check for AWS secrets in the format: secret: process.env.AWS_SECRET_ACCESS_KEY || 'nRHt9jK9SIcGrCIiiqYyWYqWg78w6uqieNrdaoQ9'
    if line.contains("secret:") && line.contains("AWS_SECRET_ACCESS_KEY") && line.contains("||") {
        let parts: Vec<&str> = line.split("||").collect();
        if parts.len() > 1 {
            let fallback_part = parts[1].trim();
            
            // Check for quoted content in the fallback
            if (fallback_part.starts_with('\'') && fallback_part.contains('\'')) || 
               (fallback_part.starts_with('"') && fallback_part.contains('"')) {
                let quote_char = if fallback_part.starts_with('\'') { '\'' } else { '"' };
                let start = fallback_part.find(quote_char).unwrap_or(0) + 1;
                if let Some(end) = fallback_part[start..].find(quote_char) {
                    let quoted = &fallback_part[start..start+end];
                    if quoted.len() >= 30 && quoted.len() <= 50 {
                        return Some(quoted.to_string());
                    }
                }
            }
        }
    }
    
    // Check for AWS key pattern in the format: key: process.env.AWS_ACCESS_KEY_ID || 'AKIAJYMNBA2KL7M6CWLA'
    if line.contains("key:") && line.contains("||") && line.contains("AKIA") {
        let parts: Vec<&str> = line.split("||").collect();
        if parts.len() > 1 {
            let fallback_part = parts[1].trim();
            
            // Check for quoted content in the fallback
            if (fallback_part.starts_with('\'') && fallback_part.contains('\'')) || 
               (fallback_part.starts_with('"') && fallback_part.contains('"')) {
                let quote_char = if fallback_part.starts_with('\'') { '\'' } else { '"' };
                let start = fallback_part.find(quote_char).unwrap_or(0) + 1;
                if let Some(end) = fallback_part[start..].find(quote_char) {
                    let quoted = &fallback_part[start..start+end];
                    if quoted.starts_with("AKIA") {
                        return Some(quoted.to_string());
                    }
                }
            }
        }
    }
    
    // Check for environment variable fallback pattern (process.env.X || 'secret')
    if line.contains("||") {
        let parts: Vec<&str> = line.split("||").collect();
        if parts.len() > 1 {
            let fallback_part = parts[1].trim();
            
            // Check for quoted content in the fallback
            if (fallback_part.starts_with('\'') && fallback_part.contains('\'')) || 
               (fallback_part.starts_with('"') && fallback_part.contains('"')) {
                let quote_char = if fallback_part.starts_with('\'') { '\'' } else { '"' };
                let start = fallback_part.find(quote_char).unwrap_or(0) + 1;
                if let Some(end) = fallback_part[start..].find(quote_char) {
                    let quoted = &fallback_part[start..start+end];
                    // Only consider it if it looks like it could be a secret
                    if quoted.len() >= 8 && 
                       (quoted.chars().any(|c| c.is_ascii_digit()) || 
                        quoted.chars().any(|c| !c.is_alphanumeric())) {
                        return Some(quoted.to_string());
                    }
                }
            }
        }
    }
    
    // Try to extract content between quotes that might be a secret
    if let Some(start) = line.find('"') {
        if let Some(end) = line[start+1..].find('"') {
            let quoted = &line[start+1..start+1+end];
            // Only consider it if it looks like it could be a secret (contains special chars or numbers)
            if quoted.chars().any(|c| c.is_ascii_digit() || !c.is_alphanumeric()) &&
               !is_likely_code_not_secret(quoted) {
                return Some(quoted.to_string());
            }
        }
    }
    
    if let Some(start) = line.find('\'') {
        if let Some(end) = line[start+1..].find('\'') {
            let quoted = &line[start+1..start+1+end];
            if quoted.chars().any(|c| c.is_ascii_digit() || !c.is_alphanumeric()) &&
               !is_likely_code_not_secret(quoted) {
                return Some(quoted.to_string());
            }
        }
    }
    
    // Special case for AWS keys in object properties
    if line.contains("key:") && line.contains("AKIA") {
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start+1..].find('"') {
                let quoted = &line[start+1..start+1+end];
                return Some(quoted.to_string());
            }
        }
    }
    
    // Special case for AWS secrets in object properties
    if line.contains("secret:") || line.contains("password:") {
        if let Some(start) = line.find('"') {
            if let Some(end) = line[start+1..].find('"') {
                let quoted = &line[start+1..start+1+end];
                return Some(quoted.to_string());
            }
        }
    }
    
    // If no quoted content found, fall back to the original approach but with better cleaning
    let clean_line = line
        .replace(|c: char| !c.is_ascii_alphanumeric(), "")
        .trim()
        .to_string();
        
    if !clean_line.is_empty() && !is_likely_code_not_secret(&clean_line) {
        Some(clean_line)
    } else {
        None
    }
}

// Helper function to determine if a string is likely code and not a secret
fn is_likely_code_not_secret(s: &str) -> bool {
    // If it looks like an AWS key, it's definitely a secret
    if s.starts_with("AKIA") {
        return false;
    }
    
    // If it contains special characters and numbers, it might be a password
    let has_special_chars = s.chars().any(|c| !c.is_alphanumeric());
    let has_numbers = s.chars().any(|c| c.is_ascii_digit());
    if has_special_chars && has_numbers && s.len() >= 8 {
        return false;
    }
    
    // Common code patterns that are not secrets
    let code_patterns = [
        // Variable names and common programming terms
        "row", "column", "table", "data", "obj", "array", "list", 
        "index", "count", "total", "sum", "value", "result",
        "budget", "goal", "target", "actual", "forecast",
        "daily", "monthly", "yearly", "quarter", "annual",
        "date", "time", "timestamp", "duration", "period",
        "start", "end", "begin", "finish", "complete",
        "min", "max", "average", "mean", "median", "mode",
        "first", "last", "next", "prev", "previous", "current",
        "temp", "temporary", "tmp", "buffer", "cache", "store",
        "key", "val", "pair", "entry", "item", "element",
        "size", "length", "width", "height", "depth", "dimension",
        "position", "location", "coordinate", "point", "vector",
        "source", "destination", "origin", "target", "endpoint",
        "input", "output", "param", "arg", "argument", "option",
        "config", "setting", "preference", "property", "attribute",
        "field", "column", "record", "document", "entity",
        "user", "customer", "client", "account", "profile",
        "request", "response", "query", "command", "action",
        "status", "state", "condition", "mode", "flag",
        
        // Common action/event names in applications
        "login", "logout", "signin", "signout", "register", "signup",
        "create", "read", "update", "delete", "view", "edit", "modify",
        "submit", "cancel", "confirm", "reject", "approve", "deny",
        "send", "receive", "upload", "download", "import", "export",
        "open", "close", "start", "stop", "pause", "resume", "reset",
        "enable", "disable", "activate", "deactivate", "block", "unblock",
        "lock", "unlock", "archive", "unarchive", "publish", "unpublish",
        "subscribe", "unsubscribe", "follow", "unfollow",
        
        // Common file types and formats
        "json", "xml", "yaml", "yml", "csv", "txt", "html", "css", "js", "ts",
        "md", "txt", "doc", "pdf", "png", "jpg", "svg", "gif",
        
        // Common password-related terms that are not actual passwords
        "forgot_password", "reset_password",
        "change_password", "password_reset", "password_change", "password_policy",
    ];
    
    let lower_s = s.to_lowercase();
    
    // Check if the string contains any common code patterns
    for pattern in &code_patterns {
        if lower_s.contains(pattern) {
            return true;
        }
    }
    
    // Check for camelCase or snake_case patterns which are common in code
    let has_camel_case = s.chars().any(|c| c.is_uppercase()) && 
                         s.chars().next().map_or(false, |c| c.is_lowercase());
    
    let has_snake_case = s.contains('_');
    
    // Check for property access patterns (obj.prop or obj['prop'])
    let has_property_access = s.contains('.') || (s.contains('[') && s.contains(']'));
    
    // Check for numeric operations
    let has_numeric_ops = s.contains('+') || s.contains('-') || 
                          s.contains('*') || s.contains('/') ||
                          s.contains('=');
    
    // Check for constant-like patterns (all caps with underscores)
    let has_constant_pattern = s.chars().all(|c| c.is_uppercase() || c.is_ascii_digit() || c == '_');
    
    // Check for enum-like patterns (PascalCase values often used in enums)
    let has_enum_pattern = s.chars().next().map_or(false, |c| c.is_uppercase()) &&
                          !s.contains(' ');
    
    has_camel_case || has_snake_case || has_property_access || has_numeric_ops || 
    has_constant_pattern || has_enum_pattern
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
