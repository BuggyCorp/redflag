use git2::{Commit, DiffOptions, Repository, Tree};
use crate::{config::Config, scanner::Finding};
use std::path::Path;

pub fn scan_git_history(path: &Path, config: &Config) -> Vec<Finding> {
    let mut findings = Vec::new();
    
    let repo = match Repository::open(path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to open repository: {}", e);
            return findings;
        }
    };

    let mut revwalk = match repo.revwalk() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to create revwalk: {}", e);
            return findings;
        }
    };

    if let Err(e) = revwalk.push_head() {
        eprintln!("Failed to push head: {}", e);
        return findings;
    }

    for oid in revwalk.filter_map(Result::ok) {
        if let Ok(commit) = repo.find_commit(oid) {
            process_commit(&repo, &commit, config, &mut findings);
        }
    }

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
                process_file_diff(delta, commit, config, findings, new_file);
            }
            true
        }, None, None, None);
    }
}

fn process_file_diff(
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
        if let Some(content) = blob.content().to_str().ok() {
            for (line_num, line) in content.lines().enumerate() {
                check_line(line, line_num + 1, file_path, commit, config, findings);
            }
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