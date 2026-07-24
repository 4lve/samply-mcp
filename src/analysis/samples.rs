use crate::profile::resolved::{ResolvedProfile, ResolvedSample, ResolvedThread, SampleWeightType};

/// A profile-relative, inclusive analysis window.
///
/// Sample timestamps remain in their original clock domain inside the resolved
/// profile. This type owns the translation between that raw clock and the
/// profile-relative milliseconds exposed by the MCP API.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AnalysisRange {
    observed_start_time_ms: f64,
    pub start_time_ms: f64,
    pub end_time_ms: f64,
}

impl AnalysisRange {
    pub fn resolve(
        profile: &ResolvedProfile,
        requested_start_time_ms: Option<f64>,
        requested_end_time_ms: Option<f64>,
    ) -> Result<Self, String> {
        if requested_start_time_ms.is_some_and(|value| !value.is_finite())
            || requested_end_time_ms.is_some_and(|value| !value.is_finite())
        {
            return Err("start_time_ms and end_time_ms must be finite numbers".to_string());
        }
        if let (Some(start), Some(end)) = (requested_start_time_ms, requested_end_time_ms)
            && end <= start
        {
            return Err("end_time_ms must be greater than start_time_ms".to_string());
        }

        let start_time_ms = requested_start_time_ms.unwrap_or(0.0).max(0.0);
        let end_time_ms = requested_end_time_ms
            .unwrap_or(profile.duration_ms)
            .min(profile.duration_ms);

        if end_time_ms < start_time_ms {
            return Err(format!(
                "Requested time range does not overlap the profile range 0..{} ms",
                profile.duration_ms
            ));
        }

        Ok(Self {
            observed_start_time_ms: profile.observed_start_time_ms,
            start_time_ms,
            end_time_ms,
        })
    }

    pub fn contains(&self, sample: &ResolvedSample) -> bool {
        let timestamp_ms = self.relative_time_ms(sample.timestamp_ms);
        timestamp_ms.is_finite()
            && timestamp_ms >= self.start_time_ms
            && timestamp_ms <= self.end_time_ms
    }

    pub fn duration_ms(&self) -> f64 {
        (self.end_time_ms - self.start_time_ms).max(0.0)
    }

    pub fn raw_start_time_ms(&self) -> f64 {
        self.observed_start_time_ms + self.start_time_ms
    }

    pub fn raw_end_time_ms(&self) -> f64 {
        self.observed_start_time_ms + self.end_time_ms
    }

    pub fn relative_time_ms(&self, raw_time_ms: f64) -> f64 {
        raw_time_ms - self.observed_start_time_ms
    }

    pub fn is_full_profile(&self, profile: &ResolvedProfile) -> bool {
        self.start_time_ms == 0.0 && self.end_time_ms == profile.duration_ms
    }
}

pub fn sample_count(thread: &ResolvedThread, range: Option<&AnalysisRange>) -> usize {
    thread
        .samples
        .iter()
        .filter(|sample| range.is_none_or(|range| range.contains(sample)))
        .count()
}

pub fn sample_weight(sample: &ResolvedSample) -> u32 {
    sample.weight.unsigned_abs()
}

pub fn sample_time_ms(thread: &ResolvedThread, sample: &ResolvedSample, interval_ms: f64) -> f64 {
    let weight = f64::from(sample_weight(sample));
    match thread.sample_weight_type {
        SampleWeightType::Samples => interval_ms * weight,
        SampleWeightType::TracingMilliseconds => weight,
        // Byte weights are useful for allocation flamegraphs, but are not a
        // duration. Count each row as one sample for the time-based tools.
        SampleWeightType::Bytes => interval_ms,
    }
}

pub fn thread_sample_time_ms(
    thread: &ResolvedThread,
    interval_ms: f64,
    range: Option<&AnalysisRange>,
) -> f64 {
    thread
        .samples
        .iter()
        .filter(|sample| range.is_none_or(|range| range.contains(sample)))
        .map(|sample| sample_time_ms(thread, sample, interval_ms))
        .sum()
}

pub fn thread_wall_time_ms(thread: &ResolvedThread, range: Option<&AnalysisRange>) -> f64 {
    let Some(range) = range else {
        return thread.duration_ms;
    };

    let mut first_time_ms = f64::INFINITY;
    let mut last_time_ms = f64::NEG_INFINITY;
    for sample in &thread.samples {
        let relative_time_ms = range.relative_time_ms(sample.timestamp_ms);
        if relative_time_ms.is_finite() {
            first_time_ms = first_time_ms.min(relative_time_ms);
            last_time_ms = last_time_ms.max(relative_time_ms);
        }
    }

    if !first_time_ms.is_finite() || !last_time_ms.is_finite() {
        return 0.0;
    }

    let start_time_ms = first_time_ms.max(range.start_time_ms);
    let end_time_ms = last_time_ms.min(range.end_time_ms);
    (end_time_ms - start_time_ms).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::resolved::{ResolvedProfile, ResolvedSample, ResolvedThread};

    fn sample(timestamp_ms: f64) -> ResolvedSample {
        ResolvedSample {
            timestamp_ms,
            weight: 1,
            cpu_delta_us: None,
            stack: Default::default(),
        }
    }

    fn profile() -> ResolvedProfile {
        ResolvedProfile {
            threads: vec![ResolvedThread {
                name: "main".to_string(),
                pid: "1".to_string(),
                tid: "1".to_string(),
                is_main: true,
                sample_weight_type: SampleWeightType::Samples,
                samples: vec![sample(35_000.0), sample(35_010.0), sample(35_020.0)],
                markers: vec![],
                duration_ms: 20.0,
            }],
            libraries: vec![],
            product: "test".to_string(),
            interval_ms: 2.0,
            categories: vec![],
            observed_start_time_ms: 35_000.0,
            duration_ms: 20.0,
            total_sample_count: 3,
        }
    }

    #[test]
    fn resolves_and_applies_profile_relative_range() {
        let profile = profile();
        let range = AnalysisRange::resolve(&profile, Some(5.0), Some(15.0)).unwrap();

        assert_eq!(range.raw_start_time_ms(), 35_005.0);
        assert_eq!(range.raw_end_time_ms(), 35_015.0);
        assert_eq!(sample_count(&profile.threads[0], Some(&range)), 1);
    }

    #[test]
    fn sample_time_uses_interval_and_weight_not_wall_clock_gaps() {
        let profile = profile();
        let range = AnalysisRange::resolve(&profile, None, None).unwrap();

        assert_eq!(
            thread_sample_time_ms(&profile.threads[0], profile.interval_ms, Some(&range)),
            6.0
        );

        let mut weighted_sample = sample(99_000.0);
        weighted_sample.weight = 3;
        assert_eq!(
            sample_time_ms(&profile.threads[0], &weighted_sample, profile.interval_ms),
            6.0
        );

        let mut tracing_thread = profile.threads[0].clone();
        tracing_thread.sample_weight_type = SampleWeightType::TracingMilliseconds;
        assert_eq!(
            sample_time_ms(&tracing_thread, &weighted_sample, profile.interval_ms),
            3.0
        );

        tracing_thread.sample_weight_type = SampleWeightType::Bytes;
        assert_eq!(
            sample_time_ms(&tracing_thread, &weighted_sample, profile.interval_ms),
            2.0
        );
    }
}
