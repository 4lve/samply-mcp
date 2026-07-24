use std::collections::HashMap;
use std::sync::Arc;

use crate::profile::resolved::{ResolvedMarker, ResolvedThread};

#[derive(Debug, Clone, PartialEq)]
pub struct OnCpuInterval {
    pub start_time_ms: f64,
    pub end_time_ms: f64,
    pub cpu: Arc<str>,
    pub switch_out_reason: Arc<str>,
}

impl OnCpuInterval {
    fn from_marker(marker: &ResolvedMarker) -> Option<Self> {
        let context_switch = marker.context_switch.as_ref()?;

        let start_time_ms = marker.start_time?;
        let end_time_ms = marker.end_time?;
        if !start_time_ms.is_finite() || !end_time_ms.is_finite() || end_time_ms < start_time_ms {
            return None;
        }

        Some(Self {
            start_time_ms,
            end_time_ms,
            cpu: context_switch.cpu.clone(),
            switch_out_reason: context_switch.switch_out_reason.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CpuUsage {
    pub cpu: String,
    pub interval_count: usize,
    pub on_cpu_time_ms: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SwitchOutReason {
    pub reason: String,
    pub switch_count: usize,
    pub observed_off_cpu_time_ms: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OffCpuInterval {
    pub start_time_ms: f64,
    pub end_time_ms: f64,
    pub duration_ms: f64,
    pub reason: String,
    pub previous_cpu: String,
    pub next_cpu: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ContextSwitchAnalysis {
    pub observed_start_time_ms: f64,
    pub observed_end_time_ms: f64,
    pub observed_duration_ms: f64,
    pub on_cpu_time_ms: f64,
    pub off_cpu_time_ms: f64,
    pub on_cpu_interval_count: usize,
    pub switch_out_count: usize,
    pub cpus: Vec<CpuUsage>,
    pub switch_out_reasons: Vec<SwitchOutReason>,
    pub longest_off_cpu_intervals: Vec<OffCpuInterval>,
}

pub fn analyze_context_switches(
    thread: &ResolvedThread,
    requested_start_time_ms: Option<f64>,
    requested_end_time_ms: Option<f64>,
    interval_limit: usize,
) -> Option<ContextSwitchAnalysis> {
    let mut intervals: Vec<OnCpuInterval> = thread
        .markers
        .iter()
        .filter_map(OnCpuInterval::from_marker)
        .collect();
    intervals.sort_by(|a, b| {
        a.start_time_ms
            .total_cmp(&b.start_time_ms)
            .then_with(|| a.end_time_ms.total_cmp(&b.end_time_ms))
    });

    let first = intervals.first()?;
    let last_end = intervals
        .iter()
        .map(|interval| interval.end_time_ms)
        .max_by(f64::total_cmp)?;
    let observed_start_time_ms = requested_start_time_ms
        .unwrap_or(first.start_time_ms)
        .max(first.start_time_ms);
    let observed_end_time_ms = requested_end_time_ms.unwrap_or(last_end).min(last_end);
    if observed_end_time_ms <= observed_start_time_ms {
        return None;
    }

    let observed_duration_ms = observed_end_time_ms - observed_start_time_ms;
    let mut cpu_accum: HashMap<Arc<str>, (usize, f64)> = HashMap::new();
    let mut reason_accum: HashMap<Arc<str>, (usize, f64)> = HashMap::new();
    let mut on_cpu_time_ms = 0.0;
    let mut on_cpu_interval_count = 0;
    let mut switch_out_count = 0;

    for interval in &intervals {
        if interval.end_time_ms >= observed_start_time_ms
            && interval.end_time_ms <= observed_end_time_ms
        {
            reason_accum
                .entry(interval.switch_out_reason.clone())
                .or_default()
                .0 += 1;
            switch_out_count += 1;
        }

        let start = interval.start_time_ms.max(observed_start_time_ms);
        let end = interval.end_time_ms.min(observed_end_time_ms);
        if end <= start {
            continue;
        }

        let duration = end - start;
        on_cpu_time_ms += duration;
        on_cpu_interval_count += 1;
        let cpu = cpu_accum.entry(interval.cpu.clone()).or_default();
        cpu.0 += 1;
        cpu.1 += duration;
    }

    let mut off_cpu_intervals = Vec::new();
    let mut covered_until = intervals[0].end_time_ms;
    let mut previous = &intervals[0];
    for next in intervals.iter().skip(1) {
        if next.start_time_ms > covered_until {
            let start = covered_until.max(observed_start_time_ms);
            let end = next.start_time_ms.min(observed_end_time_ms);
            if end > start {
                let duration = end - start;
                reason_accum
                    .entry(previous.switch_out_reason.clone())
                    .or_default()
                    .1 += duration;
                off_cpu_intervals.push(OffCpuInterval {
                    start_time_ms: start,
                    end_time_ms: end,
                    duration_ms: duration,
                    reason: previous.switch_out_reason.to_string(),
                    previous_cpu: previous.cpu.to_string(),
                    next_cpu: next.cpu.to_string(),
                });
            }
        }
        if next.end_time_ms > covered_until {
            covered_until = next.end_time_ms;
            previous = next;
        }
    }

    // OnCpu markers for one thread should not overlap. Clamp malformed profiles so the
    // summary remains internally consistent even if they do.
    on_cpu_time_ms = on_cpu_time_ms.min(observed_duration_ms);
    let off_cpu_time_ms = (observed_duration_ms - on_cpu_time_ms).max(0.0);

    let mut cpus: Vec<CpuUsage> = cpu_accum
        .into_iter()
        .map(|(cpu, (interval_count, on_cpu_time_ms))| CpuUsage {
            cpu: cpu.to_string(),
            interval_count,
            on_cpu_time_ms,
        })
        .collect();
    cpus.sort_by(|a, b| {
        b.on_cpu_time_ms
            .total_cmp(&a.on_cpu_time_ms)
            .then_with(|| a.cpu.cmp(&b.cpu))
    });

    let mut switch_out_reasons: Vec<SwitchOutReason> = reason_accum
        .into_iter()
        .map(
            |(reason, (switch_count, observed_off_cpu_time_ms))| SwitchOutReason {
                reason: reason.to_string(),
                switch_count,
                observed_off_cpu_time_ms,
            },
        )
        .collect();
    switch_out_reasons.sort_by(|a, b| {
        b.observed_off_cpu_time_ms
            .total_cmp(&a.observed_off_cpu_time_ms)
            .then_with(|| b.switch_count.cmp(&a.switch_count))
            .then_with(|| a.reason.cmp(&b.reason))
    });

    off_cpu_intervals.sort_by(|a, b| {
        b.duration_ms
            .total_cmp(&a.duration_ms)
            .then_with(|| a.start_time_ms.total_cmp(&b.start_time_ms))
    });
    off_cpu_intervals.truncate(interval_limit);

    Some(ContextSwitchAnalysis {
        observed_start_time_ms,
        observed_end_time_ms,
        observed_duration_ms,
        on_cpu_time_ms,
        off_cpu_time_ms,
        on_cpu_interval_count,
        switch_out_count,
        cpus,
        switch_out_reasons,
        longest_off_cpu_intervals: off_cpu_intervals,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::resolved::{ResolvedContextSwitchMarker, ResolvedMarker, SampleWeightType};

    fn marker(start: f64, end: f64, cpu: &str, reason: &str) -> ResolvedMarker {
        ResolvedMarker {
            name: "Running on CPU".to_string(),
            start_time: Some(start),
            end_time: Some(end),
            phase: Some(1),
            category: "Other".to_string(),
            data: None,
            context_switch: Some(ResolvedContextSwitchMarker {
                cpu: Arc::from(cpu),
                switch_out_reason: Arc::from(reason),
            }),
        }
    }

    fn thread(markers: Vec<ResolvedMarker>) -> ResolvedThread {
        ResolvedThread {
            name: "worker".to_string(),
            pid: "1".to_string(),
            tid: "2".to_string(),
            is_main: false,
            sample_weight_type: SampleWeightType::Samples,
            samples: vec![],
            markers,
            duration_ms: 0.0,
        }
    }

    #[test]
    fn summarizes_on_and_off_cpu_intervals() {
        let thread = thread(vec![
            marker(0.0, 4.0, "CPU 0", "blocked"),
            marker(10.0, 13.0, "CPU 1", "preempted"),
            marker(15.0, 20.0, "CPU 0", "blocked"),
        ]);

        let analysis = analyze_context_switches(&thread, None, None, 10).unwrap();

        assert_eq!(analysis.observed_duration_ms, 20.0);
        assert_eq!(analysis.on_cpu_time_ms, 12.0);
        assert_eq!(analysis.off_cpu_time_ms, 8.0);
        assert_eq!(analysis.switch_out_count, 3);
        assert_eq!(analysis.cpus[0].cpu, "CPU 0");
        assert_eq!(analysis.cpus[0].on_cpu_time_ms, 9.0);
        assert_eq!(analysis.longest_off_cpu_intervals[0].duration_ms, 6.0);
        assert_eq!(analysis.longest_off_cpu_intervals[0].reason, "blocked");
        assert_eq!(analysis.switch_out_reasons[0].observed_off_cpu_time_ms, 6.0);
    }

    #[test]
    fn clips_analysis_to_requested_time_range_and_limit() {
        let thread = thread(vec![
            marker(0.0, 4.0, "CPU 0", "blocked"),
            marker(10.0, 13.0, "CPU 1", "preempted"),
            marker(18.0, 20.0, "CPU 0", "blocked"),
        ]);

        let analysis = analyze_context_switches(&thread, Some(2.0), Some(19.0), 1).unwrap();

        assert_eq!(analysis.observed_duration_ms, 17.0);
        assert_eq!(analysis.on_cpu_time_ms, 6.0);
        assert_eq!(analysis.off_cpu_time_ms, 11.0);
        assert_eq!(analysis.longest_off_cpu_intervals.len(), 1);
        assert_eq!(analysis.longest_off_cpu_intervals[0].duration_ms, 6.0);
    }
}
