use git2::{Commit, DiffOptions, Repository, Tree};
use crate::{config::Config, scanner::Finding};
use std::path::Path;
use regex::Regex;
use crate::scanner::calculate_shannon_entropy;
use bstr::ByteSlice;
use crate::config::EntropyConfig;
use crate::config::SecretPattern;
use indicatif::{ProgressBar, ProgressStyle};
use crate::error::RedflagError;
use std::collections::HashMap;
use chrono::NaiveDateTime;
use std::sync::Mutex;
use once_cell::sync::Lazy;

struct ScanCache {
    commit_results: HashMap<String, Vec<Finding>>,
}

impl ScanCache {
    fn new() -> Self {
        ScanCache {
            commit_results: HashMap::new(),
        }
    }

    fn get(&self, commit_hash: &str) -> Option<&Vec<Finding>> {
        self.commit_results.get(commit_hash)
    }

    fn insert(&mut self, commit_hash: String, findings: Vec<Finding>) {
        self.commit_results.insert(commit_hash, findings);
    }
}

static SCAN_CACHE: Lazy<Mutex<ScanCache>> = Lazy::new(|| Mutex::new(ScanCache::new()));

pub fn scan_git_history(path: &Path, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let repo = Repository::open(path).map_err(RedflagError::Git)?;
    let mut revwalk = repo.revwalk().map_err(RedflagError::Git)?;
    revwalk.push_head().map_err(RedflagError::Git)?;

    let commit_count = revwalk.count() as u64;
    let progress = ProgressBar::new(commit_count);
    progress.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} commits")?);

    for oid in revwalk.filter_map(Result::ok) {
        if let Ok(commit) = repo.find_commit(oid) {
            process_commit(&repo, &commit, config, &mut findings);
        }
        progress.inc(1);
    }
    progress.finish();

    findings
}

fn process_commit(repo: &Repository, commit: &Commit, config: &Config, findings: &mut Vec<Finding>) {
    let parents = commit.parents();
    if parents.len() == 0 {
        if let Ok(tree) = commit.tree() {
            analyze_diff(repo, None, Some(&tree), commit, config, findings);
        }
    } else {
        for parent in parents {
            if let (Ok(parent_tree), Ok(commit_tree)) = (parent.tree(), commit.tree()) {
                analyze_diff(repo, Some(&parent_tree), Some(&commit_tree), commit, config, findings);
            }
        }
    }
}

fn analyze_diff(
    repo: &Repository,
    old_tree: Option<&Tree>,
    new_tree: Option<&Tree>,
    commit: &Commit,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    let mut diff_options = DiffOptions::new();
    if let Ok(diff) = repo.diff_tree_to_tree(old_tree, new_tree, Some(&mut diff_options)) {
        let _ = diff.foreach(&mut |delta, _| {
            if let Some(new_file) = delta.new_file().path() {
                process_file_diff(repo, delta, commit, config, findings, new_file);
            }
            true
        }, None, None, None);
    }
}

fn process_file_diff(
    repo: &Repository,
    delta: git2::DiffDelta<'_>,
    commit: &Commit,
    config: &Config,
    findings: &mut Vec<Finding>,
    file_path: &Path,
) {
    let extension = file_path.extension()
        .and_then(|e| e.to_str())
        .unwrap_or("");

    if !config.extensions.iter().any(|e| e.eq_ignore_ascii_case(extension)) {
        return;
    }

    let patch = delta.new_file().id();
    if let Ok(blob) = repo.find_blob(patch) {
        let content = blob.content().to_str_lossy();
        for (line_num, line) in content.lines().enumerate() {
            check_line(line, line_num + 1, file_path, commit, config, findings);
        }
    }
}

fn check_line(
    line: &str,
    line_num: usize,
    file_path: &Path,
    commit: &Commit,
    config: &Config,
    findings: &mut Vec<Finding>,
) {
    // Check regex patterns
    for pattern in &config.patterns {
        if let Ok(re) = Regex::new(&pattern.pattern) {
            if re.is_match(line) {
                findings.push(create_finding(
                    file_path,
                    line_num,
                    line,
                    &pattern.name,
                    &pattern.description,
                    commit,
                ));
            }
        }
    }

    // Check entropy
    if config.entropy.enabled {
        let clean_line = line.replace(|c: char| !c.is_ascii_alphanumeric(), "");
        if clean_line.len() >= config.entropy.min_length &&
           calculate_shannon_entropy(&clean_line) >= config.entropy.threshold {
            findings.push(create_finding(
                file_path,
                line_num,
                line,
                "high-entropy",
                "High entropy string detected",
                commit,
            ));
        }
    }
}

fn create_finding(
    file_path: &Path,
    line_num: usize,
    line: &str,
    pattern_name: &str,
    description: &str,
    commit: &Commit,
) -> Finding {
    Finding {
        file: file_path.to_path_buf(),
        line: line_num,
        pattern_name: pattern_name.to_string(),
        description: description.to_string(),
        snippet: line.chars().take(50).collect(),
        commit_hash: Some(commit.id().to_string()),
        commit_author: Some(commit.author().to_string()),
        commit_date: Some(commit.time().seconds().to_string()),
    }
}

pub fn scan_git_history_with_handler<H: FindingHandler>(
    path: &Path,
    config: &Config,
    handler: &mut H,
) -> Result<(), RedflagError> {
    let repo = Repository::open(path)?;
    let mut revwalk = repo.revwalk()?;
    
    // Configure revwalk based on config
    if !config.git.branches.is_empty() {
        for branch in &config.git.branches {
            if let Ok(branch_ref) = repo.find_branch(branch, git2::BranchType::Local) {
                if let Ok(branch_ref_name) = branch_ref.get().name() {
                    revwalk.push_ref(branch_ref_name)?;
                }
            }
        }
    } else {
        revwalk.push_head()?;
    }

    // Apply date filters if configured
    if let Some(since) = &config.git.since_date {
        if let Ok(timestamp) = NaiveDateTime::parse_from_str(since, "%Y-%m-%d") {
            revwalk.push(format!(">{}", timestamp.timestamp()).as_bytes())?;
        }
    }

    if let Some(until) = &config.git.until_date {
        if let Ok(timestamp) = NaiveDateTime::parse_from_str(until, "%Y-%m-%d") {
            revwalk.push(format!("<{}", timestamp.timestamp()).as_bytes())?;
        }
    }

    let commit_count = revwalk.count() as u64;
    let progress = ProgressBar::new(commit_count.min(config.git.max_depth as u64));
    progress.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} commits")?
        .progress_chars("=>-"));

    let mut cache = SCAN_CACHE.lock().unwrap();
    let mut processed = 0;

    for oid in revwalk.filter_map(Result::ok) {
        if processed >= config.git.max_depth {
            break;
        }

        let commit = repo.find_commit(oid)?;
        let commit_hash = commit.id().to_string();

        // Check cache first
        if let Some(cached_findings) = cache.get(&commit_hash) {
            for finding in cached_findings {
                handler.handle(finding.clone());
            }
        } else {
            let findings = process_commit(&repo, &commit, config, &mut Vec::new())?;
            for finding in &findings {
                handler.handle(finding.clone());
            }
            cache.insert(commit_hash, findings);
        }

        processed += 1;
        progress.inc(1);
    }

    progress.finish_with_message("Git history scan complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{Repository, Signature};
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    fn create_test_repo() -> (tempfile::TempDir, Repository) {
        let dir = tempdir().unwrap();
        let repo = Repository::init(&dir).unwrap();
        let sig = Signature::now("Test User", "test@example.com").unwrap();
    
        // First commit
        {
            let mut index = repo.index().unwrap();
            let config_file = dir.path().join("config.env");
            File::create(&config_file).unwrap()
                .write_all(b"API_KEY=test_123456789012345678901234").unwrap();
            
            index.add_path(Path::new("config.env")).unwrap();
            let oid = index.write_tree().unwrap();
            let tree = repo.find_tree(oid).unwrap();
            
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "Initial commit",
                &tree,
                &[],
            ).unwrap();
        } // index and tree dropped here
    
        // Second commit
        {
            let mut index = repo.index().unwrap();
            let config_file = dir.path().join("config.env");
            fs::remove_file(&config_file).unwrap();
            
            index.remove_path(Path::new("config.env")).unwrap();
            let oid = index.write_tree().unwrap();
            let tree = repo.find_tree(oid).unwrap();
            let parent = repo.head().unwrap().peel_to_commit().unwrap();
            
            repo.commit(
                Some("HEAD"),
                &sig,
                &sig,
                "Remove secret",
                &tree,
                &[&parent],
            ).unwrap();
        } // index, tree, and parent dropped here
    
        (dir, repo)
    }

    #[test]
    fn test_find_secret_in_history() {
        let (dir, _repo) = create_test_repo();
        let config = Config {
            patterns: vec![
                SecretPattern {
                    name: "test-api-key".to_string(),
                    pattern: r#"API_KEY=\w{28}"#.to_string(),
                    description: "Test API key pattern".to_string(),
                }
            ],
            extensions: vec!["env".to_string()],
            ..Config::default()
        };

        let findings = scan_git_history(dir.path(), &config);
        
        assert!(!findings.is_empty(), "No findings detected");
        let secret_finding = &findings[0];
        assert_eq!(secret_finding.pattern_name, "test-api-key");
        assert!(secret_finding.commit_hash.is_some());
        assert!(secret_finding.commit_author.as_ref().unwrap().contains("Test User"));
        assert_eq!(secret_finding.file, Path::new("config.env"));
    }

    #[test]
    fn test_ignore_unconfigured_extensions() {
        let (dir, _repo) = create_test_repo();
        let config = Config {
            extensions: vec!["txt".to_string()], // Different from test repo's .env
            ..Config::default()
        };

        let findings = scan_git_history(dir.path(), &config);
        assert!(findings.is_empty(), "Found secrets in ignored extension");
    }

    #[test]
    fn test_entropy_detection_in_history() {
        let dir = tempdir().unwrap();
        let repo = Repository::init(&dir).unwrap();
        let sig = Signature::now("Test User", "test@example.com").unwrap();

        // Create file with high entropy string
        let file_path = dir.path().join("creds.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "password = \"dK3@9x!2sQ#mYp5vRtHw}}\"").unwrap();

        // Commit the file
        let mut index = repo.index().unwrap();
        index.add_path(&Path::new("creds.txt")).unwrap();
        let oid = index.write_tree().unwrap();
        let tree = repo.find_tree(oid).unwrap();
        repo.commit(
            Some("HEAD"),
            &sig,
            &sig,
            "Add high entropy password",
            &tree,
            &[],
        ).unwrap();

        let config = Config {
            entropy: EntropyConfig {
                enabled: true,
                threshold: 3.5,
                min_length: 12,
            },
            extensions: vec!["txt".to_string()],
            ..Config::default()
        };

        let findings = scan_git_history(dir.path(), &config);
        assert!(!findings.is_empty(), "No entropy findings detected");
        assert_eq!(findings[0].pattern_name, "high-entropy");
    }
}