# Redflag 🚩

A lightweight, cross-platform secret scanner for codebases with git history support

[![CI Status](https://github.com/BuggyCorp/redflag/actions/workflows/ci.yml/badge.svg)](https://github.com/BuggyCorp/redflag/actions)[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## Installation

### From Source

```bash
cargo install --git https://github.com/BuggyCorp/redflag
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/BuggyCorp/redflag/releases) for:

* Linux (x86_64)
* Windows (x86_64)
* macOS (x86_64/ARM)

## Usage

### Basic Scan

```bash
# Scan current directory
redflag scan .

# Scan specific path
redflag scan /path/to/code

# Scan with git history
redflag scan . --git-history

# Scan specific git branches
redflag scan . --git-history --git-branches main,develop

# Scan git history within date range
redflag scan . --git-history --git-since 2024-01-01 --git-until 2024-02-24

# Limit git history depth
redflag scan . --git-history --git-max-depth 100
```

### Output Formats

```bash
# Default text output
redflag scan .

# JSON output
redflag scan --format json > results.json
```

## Configuration

Create `redflag.toml`:

```toml
[entropy]
enabled = true
threshold = 4.0
min_length = 20

[git]
max_depth = 1000
branches = ["main", "develop"]
since_date = "2024-01-01"  # Optional
until_date = "2024-02-24"  # Optional

[[patterns]]
name = "stripe-key"
pattern = '''(?i)sk_(test|live)_[a-z0-9]{24}'''
description = "Stripe API Key"
severity = "Critical"  # Options: Critical, High, Medium, Low

[[exclusions]]
pattern = "**/node_modules/**"
policy = "Ignore"  # Options: Ignore, ScanButWarn, ScanButAllow

[[exclusions]]
pattern = "**/*.test.*"
policy = "ScanButWarn"
```

## Features

* 🔍 File content scanning with regex patterns
* 🎨 Colored output with severity levels:
  * 🔴 Critical - High-risk secrets (e.g., AWS keys)
  * 🟣 High - Sensitive credentials
  * 🟡 Medium - Potential security concerns
  * 🔵 Low - Items requiring review
* 🧮 Shannon entropy detection for high-entropy strings
* 🌳 Git history scanning with:
  * Branch selection
  * Date range filtering
  * Depth limiting
  * Commit information in findings
* 📝 Multiple output formats:
  * Human-readable text with color-coded severities
  * JSON for integration
* 🚫 Flexible exclusion policies:
  * Ignore - Skip files completely
  * ScanButWarn - Scan and report as warnings
  * ScanButAllow - Scan but don't fail the process
* 💾 Performance optimizations:
  * Git commit caching
  * Streaming output
  * Efficient file traversal

## Supported File Types

| Category | Extensions |
|----------|------------|
| Default | py, rs, js, ts, java, go, php, rb, sh, yml, yaml, toml |
| Config | env, tf, hcl, json, cfg, conf, properties |

## GitHub Integration

### GitHub Actions

```yaml
- name: Secret Scan
  run: |
    redflag scan --format json --git-history ./src > results.json
  continue-on-error: true

- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.json
```

## Building from Source

```bash
# Debug build
cargo build

# Release build
cargo build --release
```

## Contributing

Pattern contributions welcome! See [Pattern Guide](PATTERN_GUIDE.md).

**Disclaimer:** This tool provides heuristic checks, not security guarantees.

## Output Examples

### Text Output (with colors)

```
[CRITICAL] test.rs:42 - aws-key - AWS Access Key detected
Snippet: AKIAXXXXXXXXXXXXXXXX
Commit: abc123 (John Doe, 2024-02-24)

[HIGH    ] config.js:15 - stripe-key - Stripe API Key detected
Snippet: sk_test_XXXXXXXXXXXXXXXXXXXXXXXX

Scan Summary:
-------------
Total findings: 2
  Critical: 1
  High:     1
  Medium:   0
  Low:      0
```

### JSON Output

```json
[
  {
    "file": "test.rs",
    "line": 42,
    "pattern_name": "aws-key",
    "description": "AWS Access Key detected",
    "snippet": "AKIAXXXXXXXXXXXXXXXX",
    "severity": "Critical",
    "commit_hash": "abc123",
    "commit_author": "John Doe",
    "commit_date": "2024-02-24"
  }
]
```