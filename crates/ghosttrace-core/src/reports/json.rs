//! Full-fidelity JSON report rendering (plan Sections 9, 12; P3.2).

use crate::error::{CoreError, CoreResult};

use super::ReportV1;

/// Render the report as stable, pretty JSON with a trailing newline.
pub fn render(report: &ReportV1) -> CoreResult<String> {
    let mut text = serde_json::to_string_pretty(report)
        .map_err(|error| CoreError::Storage(format!("report json: {error}")))?;
    text.push('\n');
    Ok(text)
}
