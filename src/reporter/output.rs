use crate::types::{IssueRecord, GlobalStats, IssueCategory, IssueType, IssueSeverity};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Report generator for analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub issues: Vec<IssueRecord>,
    pub stats: GlobalStats,
}

impl AnalysisReport {
    pub fn new(issues: Vec<IssueRecord>, stats: GlobalStats) -> Self {
        Self { issues, stats }
    }

    /// Get issues grouped by category
    pub fn issues_by_category(&self) -> HashMap<IssueCategory, Vec<&IssueRecord>> {
        let mut categorized: HashMap<IssueCategory, Vec<&IssueRecord>> = HashMap::new();

        for issue in &self.issues {
            categorized
                .entry(issue.issue_type.category())
                .or_insert_with(Vec::new)
                .push(issue);
        }

        categorized
    }

    /// Get issues grouped by severity
    pub fn issues_by_severity(&self) -> HashMap<IssueSeverity, Vec<&IssueRecord>> {
        let mut by_severity: HashMap<IssueSeverity, Vec<&IssueRecord>> = HashMap::new();

        for issue in &self.issues {
            by_severity
                .entry(issue.severity)
                .or_insert_with(Vec::new)
                .push(issue);
        }

        by_severity
    }

    /// Get issue count by type
    pub fn issue_counts(&self) -> HashMap<IssueType, usize> {
        let mut counts: HashMap<IssueType, usize> = HashMap::new();

        for issue in &self.issues {
            *counts.entry(issue.issue_type).or_insert(0) += 1;
        }

        counts
    }

    /// Get summary statistics
    pub fn summary(&self) -> ReportSummary {
        let by_severity = self.issues_by_severity();

        ReportSummary {
            total_issues: self.issues.len(),
            high_severity: by_severity.get(&IssueSeverity::High).map_or(0, |v| v.len()),
            medium_severity: by_severity.get(&IssueSeverity::Medium).map_or(0, |v| v.len()),
            low_severity: by_severity.get(&IssueSeverity::Low).map_or(0, |v| v.len()),
            total_packets: self.stats.total_packets,
            total_frames: self.stats.total_frames,
            duration: self.stats.end_time - self.stats.start_time,
            unique_stations: self.stats.stations.len(),
            unique_bss: self.stats.bss.len(),
            channels_analyzed: self.stats.channels.len(),
        }
    }
}

/// Summary statistics for a report
#[derive(Debug, Clone)]
pub struct ReportSummary {
    pub total_issues: usize,
    pub high_severity: usize,
    pub medium_severity: usize,
    pub low_severity: usize,
    pub total_packets: u64,
    pub total_frames: u64,
    pub duration: f64,
    pub unique_stations: usize,
    pub unique_bss: usize,
    pub channels_analyzed: usize,
}
