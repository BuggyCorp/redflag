use crate::scanner::Finding;

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json
}

pub fn format_findings(findings: &[Finding], format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => text_format(findings),
        OutputFormat::Json => serde_json::to_string_pretty(&findings).unwrap(),
    }
}

fn text_format(findings: &[Finding]) -> String {
    let mut output = String::new();
    for finding in findings {
        output.push_str(&format!(
            "{}:{} - {} - {}\nSnippet: {}\n\n",
            finding.file.display(),
            finding.line,
            finding.pattern_name,
            finding.description,
            finding.snippet
        ));
    }
    output
}
