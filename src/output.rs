use crate::Finding;
use sarif_rs::{Artifact, Result, Sarif, Tool, ToolComponent};

pub fn format_findings(findings: &[Finding], format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => text_format(findings),
        OutputFormat::Json => serde_json::to_string_pretty(findings).unwrap(),
        OutputFormat::Sarif => sarif_format(findings),
    }
}

fn sarif_format(findings: &[Finding]) -> String {
    let mut results = Vec::new();
    
    for finding in findings {
        results.push(Result::new()
            .with_message(format!("Potential secret: {}", finding.pattern_name))
            .with_locations(vec![sarif_rs::Location::new()
                .with_physical_location(sarif_rs::PhysicalLocation::new()
                    .with_artifact_location(sarif_rs::ArtifactLocation::new()
                        .with_uri(finding.file.display().to_string()))
                    .with_region(sarif_rs::Region::new()
                        .with_start_line(finding.line as i64)))]) 
        );
    }

    let sarif = Sarif::new()
        .with_version("2.1.0")
        .with_runs(vec![sarif_rs::Run::new()
            .with_tool(Tool::new()
                .with_driver(ToolComponent::new()
                    .with_name("redflag")
                    .with_version(env!("CARGO_PKG_VERSION"))))
            .with_results(results)]);

    sarif.to_string_pretty().unwrap()
}