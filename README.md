Redflag 🚩
==========

A lightweight, cross-platform secret scanner for codebases

 [![CI Status](https://github.com/BuggyCorp/redflag/actions/workflows/ci.yml/badge.svg)](https://github.com/BuggyCorp/redflag/actions)[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Installation
------------

### From Source

    cargo install --git https://github.com/BuggyCorp/redflag

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/BuggyCorp/redflag/releases) for:

*   Linux (x86\_64)
*   Windows (x86\_64)
*   macOS (x86\_64/ARM)

Usage
-----

### Basic Scan

    redflag scan /path/to/code

### Formatted Outputs

    # JSON output
    redflag scan --format json > results.json

Configuration
-------------

Create `redflag.toml`:

    [entropy]
    enabled = true
    threshold = 4.0
    
    [[patterns]]
    name = "stripe-key"
    pattern = '''(?i)sk_(test|live)_[a-z0-9]{24}'''

Supported File Types
--------------------

Category

Extensions

Default

py, rs, js, ts, java, go, php, rb, sh, yml, yaml, toml

Config

env, tf, hcl, json, cfg, conf, properties

GitHub Integration
------------------

### GitHub Actions

    - name: Secret Scan
      run: |
        redflag scan --format sarif ./src > results.sarif
      continue-on-error: true
    
    - name: Upload SARIF
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif

Building from Source
--------------------

    # Debug build
    cargo build
    
    # Release build
    cargo build --release

Contributing
------------

Pattern contributions welcome! See [Pattern Guide](PATTERN_GUIDE.md).

**Disclaimer:** This tool provides heuristic checks, not security guarantees.