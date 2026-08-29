// OTLP/HTTP JSON exporter for metrics and logs (docs/E-otel.md).
//
// Tier 2 of that design: the gate never exports. A long-lived reader tails `hook.jsonl`,
// feeds each record to `OtelPipeline::ingest`, and periodically calls `export`, which POSTs
// to `{endpoint}/v1/metrics` and `{endpoint}/v1/logs`.
//
// Encoding follows the protobuf JSON mapping OTLP mandates: field names are lowerCamelCase,
// 64-bit integers are decimal *strings*, enum fields are integers, and attribute values use
// the AnyValue wrapper. Getting any of those wrong makes a collector reject the payload (or,
// worse, accept it and drop the points), so `to_otlp_metrics` / `logs_payload` are the only
// places that build wire JSON and they are covered by shape tests below.
//
// Failure policy (CLAUDE.md principle 4): every export failure is a typed `Err` for the
// caller to report; nothing here panics and nothing is retried silently. On failure the
// checkpoint is not advanced, so a later run replays from the JSONL — the deliberate,
// documented gap from E-otel §2.
//
// Not yet referenced by any command: the integrator wires `[otel]` into config parsing and
// adds the reader. The allow keeps clippy clean until then.
#![allow(dead_code)]

use crate::config::expand_tilde;
use crate::queue::write_atomic;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) const GATE_DECISIONS: &str = "lordkali.gate.decisions";
pub(crate) const GATE_DURATION: &str = "lordkali.gate.duration";
pub(crate) const APPROVAL_REQUESTS: &str = "lordkali.approval.requests";
pub(crate) const APPROVAL_RESOLUTIONS: &str = "lordkali.approval.resolutions";
pub(crate) const APPROVAL_WAIT: &str = "lordkali.approval.wait";
pub(crate) const LLM_CONSULTS: &str = "lordkali.llm.consults";
pub(crate) const LLM_LATENCY: &str = "lordkali.llm.latency";
pub(crate) const LLM_TOKENS: &str = "lordkali.llm.tokens";
pub(crate) const LLM_AGREEMENT: &str = "lordkali.llm.agreement";
pub(crate) const RULES_PERSISTED: &str = "lordkali.rules.persisted";
pub(crate) const RULES_ACTIVE: &str = "lordkali.rules.active";
// Claude Code's own denials of calls lord-kali passed through — including auto mode's
// classifier, which is otherwise invisible to the gate.
pub(crate) const CLAUDE_DENIED: &str = "lordkali.claude.denied";
pub(crate) const TOOL_FAILURES: &str = "lordkali.tool.failures";

pub(crate) const DEFAULT_ENDPOINT: &str = "http://localhost:4318";
pub(crate) const DEFAULT_PROTOCOL: &str = "http/json";
pub(crate) const DEFAULT_HEADERS_ENV: &str = "LORD_KALI_OTEL_HEADERS";
pub(crate) const DEFAULT_EXPORT_INTERVAL_MS: u64 = 10_000;
pub(crate) const DEFAULT_SERVICE_NAME: &str = "lord-kali";
pub(crate) const DEFAULT_CHECKPOINT: &str = "~/.local/state/lord-kali/otel.checkpoint";

pub(crate) const REDACTION_PLACEHOLDER: &str = "[REDACTED]";
// A dead collector must not stall the exporter for longer than one export interval's worth
// of headroom; this bounds a single POST.
const EXPORT_TIMEOUT_MS: u64 = 10_000;
// Logs buffered while the collector is unreachable. Past this the oldest are dropped and
// counted in `dropped_logs` — deliberate bounded-memory degradation, surfaced to the caller
// rather than hidden, with the JSONL still holding the full record.
const MAX_PENDING_LOGS: usize = 4_096;

// AGGREGATION_TEMPORALITY_CUMULATIVE. Every instrument here is cumulative: a restart begins
// a new series with a fresh startTimeUnixNano, which backends read as a counter reset.
const CUMULATIVE: u32 = 2;

// Millisecond-scale boundaries (the OTel SDK default set): every histogram in E-otel §5
// measures a duration in ms, so one shared set keeps this simple and comparable.
pub(crate) const HISTOGRAM_BOUNDS: &[f64] = &[
    0.0, 5.0, 10.0, 25.0, 50.0, 75.0, 100.0, 250.0, 500.0, 750.0, 1000.0, 2500.0, 5000.0, 7500.0,
    10000.0,
];

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub(crate) struct OtelConfig {
    pub(crate) enabled: bool,
    pub(crate) endpoint: String,
    pub(crate) protocol: String,
    // Name of the env var holding `key=value,key=value` auth headers. The value is read at
    // export time and never logged or echoed into an error.
    pub(crate) headers_env: String,
    pub(crate) export_interval_ms: u64,
    pub(crate) metrics: bool,
    pub(crate) logs: bool,
    pub(crate) include_command: bool,
    // `/regex/`-delimited patterns; every match is replaced before any command text leaves
    // the machine.
    pub(crate) redact: Vec<String>,
    pub(crate) service_name: String,
    pub(crate) checkpoint: String,
}

impl Default for OtelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: DEFAULT_ENDPOINT.to_string(),
            protocol: DEFAULT_PROTOCOL.to_string(),
            headers_env: DEFAULT_HEADERS_ENV.to_string(),
            export_interval_ms: DEFAULT_EXPORT_INTERVAL_MS,
            metrics: true,
            logs: true,
            include_command: true,
            redact: Vec::new(),
            service_name: DEFAULT_SERVICE_NAME.to_string(),
            checkpoint: DEFAULT_CHECKPOINT.to_string(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum OtelError {
    Config(String),
    Transport(String),
    Status(u16, String),
    Io(String),
}

impl std::fmt::Display for OtelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtelError::Config(m) => write!(f, "otel config error: {m}"),
            OtelError::Transport(m) => write!(f, "otel transport error: {m}"),
            OtelError::Status(code, body) => write!(f, "otel export http {code}: {body}"),
            OtelError::Io(m) => write!(f, "otel io error: {m}"),
        }
    }
}

impl std::error::Error for OtelError {}

// --- attributes -----------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum AttrValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<AttrValue>),
}

impl AttrValue {
    pub(crate) fn to_any_value(&self) -> Value {
        match self {
            AttrValue::Str(s) => serde_json::json!({ "stringValue": s }),
            AttrValue::Int(i) => serde_json::json!({ "intValue": i.to_string() }),
            AttrValue::Bool(b) => serde_json::json!({ "boolValue": b }),
            AttrValue::Array(items) => serde_json::json!({
                "arrayValue": {
                    "values": items.iter().map(AttrValue::to_any_value).collect::<Vec<_>>()
                }
            }),
        }
    }
}

pub(crate) type Attributes = Vec<(String, AttrValue)>;

fn attributes_json(attrs: &[(String, AttrValue)]) -> Value {
    Value::Array(
        attrs
            .iter()
            .map(|(k, v)| serde_json::json!({ "key": k, "value": v.to_any_value() }))
            .collect(),
    )
}

// Metric attribute sets are string-only and sorted, so the same logical set always produces
// the same series key regardless of the order the caller listed them in.
type MetricAttrs = Vec<(String, String)>;

fn metric_attrs(pairs: &[(&str, &str)]) -> MetricAttrs {
    let mut out: MetricAttrs = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    out.sort();
    out
}

fn metric_attrs_json(attrs: &MetricAttrs) -> Value {
    Value::Array(
        attrs
            .iter()
            .map(|(k, v)| serde_json::json!({ "key": k, "value": { "stringValue": v } }))
            .collect(),
    )
}

pub(crate) fn resource_attributes(service_name: &str) -> Attributes {
    vec![
        (
            "service.name".to_string(),
            AttrValue::Str(service_name.to_string()),
        ),
        (
            "service.version".to_string(),
            AttrValue::Str(env!("CARGO_PKG_VERSION").to_string()),
        ),
        ("host.name".to_string(), AttrValue::Str(hostname())),
    ]
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn scope_json() -> Value {
    serde_json::json!({ "name": "lord-kali", "version": env!("CARGO_PKG_VERSION") })
}

// --- metrics --------------------------------------------------------------------------

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct HistogramPoint {
    pub(crate) count: u64,
    pub(crate) sum: f64,
    pub(crate) buckets: Vec<u64>,
}

impl HistogramPoint {
    fn record(&mut self, value: f64) {
        if self.buckets.len() != HISTOGRAM_BOUNDS.len() + 1 {
            self.buckets = vec![0; HISTOGRAM_BOUNDS.len() + 1];
        }
        let idx = HISTOGRAM_BOUNDS
            .iter()
            .position(|b| value <= *b)
            .unwrap_or(HISTOGRAM_BOUNDS.len());
        self.buckets[idx] += 1;
        self.count += 1;
        self.sum += value;
    }
}

#[derive(Debug)]
pub(crate) struct MetricRegistry {
    start_time_ns: u64,
    counters: BTreeMap<(String, MetricAttrs), u64>,
    histograms: BTreeMap<(String, MetricAttrs), HistogramPoint>,
    gauges: BTreeMap<(String, MetricAttrs), i64>,
}

impl MetricRegistry {
    pub(crate) fn new(start_time_ms: u64) -> Self {
        Self {
            start_time_ns: ms_to_ns(start_time_ms),
            counters: BTreeMap::new(),
            histograms: BTreeMap::new(),
            gauges: BTreeMap::new(),
        }
    }

    pub(crate) fn add(&mut self, name: &str, attrs: &[(&str, &str)], value: u64) {
        *self
            .counters
            .entry((name.to_string(), metric_attrs(attrs)))
            .or_default() += value;
    }

    pub(crate) fn record(&mut self, name: &str, attrs: &[(&str, &str)], value_ms: f64) {
        self.histograms
            .entry((name.to_string(), metric_attrs(attrs)))
            .or_default()
            .record(value_ms);
    }

    pub(crate) fn set(&mut self, name: &str, attrs: &[(&str, &str)], value: i64) {
        self.gauges
            .insert((name.to_string(), metric_attrs(attrs)), value);
    }

    pub(crate) fn counter(&self, name: &str, attrs: &[(&str, &str)]) -> u64 {
        self.counters
            .get(&(name.to_string(), metric_attrs(attrs)))
            .copied()
            .unwrap_or(0)
    }

    pub(crate) fn histogram(&self, name: &str, attrs: &[(&str, &str)]) -> Option<&HistogramPoint> {
        self.histograms
            .get(&(name.to_string(), metric_attrs(attrs)))
    }

    pub(crate) fn gauge(&self, name: &str, attrs: &[(&str, &str)]) -> Option<i64> {
        self.gauges
            .get(&(name.to_string(), metric_attrs(attrs)))
            .copied()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.counters.is_empty() && self.histograms.is_empty() && self.gauges.is_empty()
    }

    pub(crate) fn to_otlp_metrics(&self, resource: &Attributes, now_ms: u64) -> Value {
        let now_ns = ms_to_ns(now_ms);
        let start = self.start_time_ns.to_string();
        let now = now_ns.to_string();
        let mut by_name: BTreeMap<&str, Vec<Value>> = BTreeMap::new();

        for ((name, attrs), value) in &self.counters {
            by_name.entry(name).or_default().push(serde_json::json!({
                "attributes": metric_attrs_json(attrs),
                "startTimeUnixNano": start,
                "timeUnixNano": now,
                "asInt": value.to_string(),
            }));
        }
        let mut metrics: Vec<Value> = by_name
            .iter()
            .map(|(name, points)| {
                serde_json::json!({
                    "name": name,
                    "sum": {
                        "dataPoints": points,
                        "aggregationTemporality": CUMULATIVE,
                        "isMonotonic": true,
                    }
                })
            })
            .collect();

        by_name.clear();
        for ((name, attrs), point) in &self.histograms {
            by_name.entry(name).or_default().push(serde_json::json!({
                "attributes": metric_attrs_json(attrs),
                "startTimeUnixNano": start,
                "timeUnixNano": now,
                "count": point.count.to_string(),
                "sum": point.sum,
                "bucketCounts": point.buckets.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                "explicitBounds": HISTOGRAM_BOUNDS,
            }));
        }
        metrics.extend(by_name.iter().map(|(name, points)| {
            serde_json::json!({
                "name": name,
                "unit": "ms",
                "histogram": {
                    "dataPoints": points,
                    "aggregationTemporality": CUMULATIVE,
                }
            })
        }));

        by_name.clear();
        for ((name, attrs), value) in &self.gauges {
            by_name.entry(name).or_default().push(serde_json::json!({
                "attributes": metric_attrs_json(attrs),
                "startTimeUnixNano": start,
                "timeUnixNano": now,
                "asInt": value.to_string(),
            }));
        }
        metrics.extend(by_name.iter().map(
            |(name, points)| serde_json::json!({ "name": name, "gauge": { "dataPoints": points } }),
        ));

        serde_json::json!({
            "resourceMetrics": [{
                "resource": { "attributes": attributes_json(resource) },
                "scopeMetrics": [{ "scope": scope_json(), "metrics": metrics }],
            }]
        })
    }
}

// --- logs -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub(crate) fn number(self) -> u32 {
        match self {
            Severity::Info => 9,
            Severity::Warn => 13,
            Severity::Error => 17,
        }
    }

    pub(crate) fn text(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        }
    }
}

// E-otel §6. An unrecognised verdict is INFO: severity is a display concern and inventing a
// higher one for a string we don't know would be a false alarm.
pub(crate) fn severity_for_decision(decision: &str) -> Severity {
    match decision {
        "deny" => Severity::Error,
        "ask" => Severity::Warn,
        _ => Severity::Info,
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct OtelLogRecord {
    pub(crate) time_ms: u64,
    pub(crate) severity: Severity,
    pub(crate) body: String,
    pub(crate) attributes: Attributes,
}

impl OtelLogRecord {
    fn to_json(&self) -> Value {
        let ns = ms_to_ns(self.time_ms).to_string();
        serde_json::json!({
            "timeUnixNano": ns,
            "observedTimeUnixNano": ns,
            "severityNumber": self.severity.number(),
            "severityText": self.severity.text(),
            "body": { "stringValue": self.body },
            "attributes": attributes_json(&self.attributes),
        })
    }
}

pub(crate) fn logs_payload(resource: &Attributes, records: &[OtelLogRecord]) -> Value {
    serde_json::json!({
        "resourceLogs": [{
            "resource": { "attributes": attributes_json(resource) },
            "scopeLogs": [{
                "scope": scope_json(),
                "logRecords": records.iter().map(OtelLogRecord::to_json).collect::<Vec<_>>(),
            }],
        }]
    })
}

// --- redaction ------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct Redactor {
    patterns: Vec<regex::Regex>,
}

impl Redactor {
    // Patterns are written `/.../` in config; the delimiters are stripped. A pattern that
    // does not compile is an error, never a silently skipped rule — a redaction that
    // quietly stops applying is exactly the failure that ships a secret to a collector.
    pub(crate) fn new(patterns: &[String]) -> Result<Self, OtelError> {
        let mut compiled = Vec::with_capacity(patterns.len());
        for raw in patterns {
            let body = raw
                .strip_prefix('/')
                .and_then(|s| s.strip_suffix('/'))
                .unwrap_or(raw);
            compiled.push(
                regex::Regex::new(body)
                    .map_err(|e| OtelError::Config(format!("redact pattern {raw}: {e}")))?,
            );
        }
        Ok(Self { patterns: compiled })
    }

    pub(crate) fn apply(&self, text: &str) -> String {
        let mut out = text.to_string();
        for re in &self.patterns {
            out = re
                .replace_all(&out, regex::NoExpand(REDACTION_PLACEHOLDER))
                .into_owned();
        }
        out
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

// --- checkpoint -----------------------------------------------------------------------

pub(crate) fn checkpoint_path(cfg: &OtelConfig) -> PathBuf {
    expand_tilde(&cfg.checkpoint)
}

// The last exported `ts_ms`, not a byte offset: `prune-logs` rewrites hook.jsonl atomically,
// so an offset would silently point into the wrong record after a prune.
pub(crate) fn read_checkpoint(path: &Path) -> Result<Option<u64>, OtelError> {
    match std::fs::read_to_string(path) {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map(Some)
            .map_err(|e| OtelError::Config(format!("{}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(OtelError::Io(format!("{}: {e}", path.display()))),
    }
}

pub(crate) fn write_checkpoint(path: &Path, ts_ms: u64) -> Result<(), OtelError> {
    write_atomic(path, &ts_ms.to_string())
        .map_err(|e| OtelError::Io(format!("{}: {e}", path.display())))
}

// --- transport ------------------------------------------------------------------------

pub(crate) fn metrics_url(endpoint: &str) -> String {
    format!("{}/v1/metrics", endpoint.trim_end_matches('/'))
}

pub(crate) fn logs_url(endpoint: &str) -> String {
    format!("{}/v1/logs", endpoint.trim_end_matches('/'))
}

pub(crate) fn parse_headers(raw: &str) -> Vec<(String, String)> {
    raw.split(',')
        .filter_map(|pair| pair.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .filter(|(k, _)| !k.is_empty())
        .collect()
}

fn headers_from_env(var: &str) -> Vec<(String, String)> {
    std::env::var(var)
        .map(|raw| parse_headers(&raw))
        .unwrap_or_default()
}

fn post_json(url: &str, headers: &[(String, String)], body: &Value) -> Result<(), OtelError> {
    let mut req = ureq::post(url)
        .set("Content-Type", "application/json")
        .timeout(Duration::from_millis(EXPORT_TIMEOUT_MS));
    for (k, v) in headers {
        req = req.set(k, v);
    }
    match req.send_json(body) {
        Ok(_) => Ok(()),
        // The response body is safe to surface; the request headers are never included.
        Err(ureq::Error::Status(code, r)) => {
            Err(OtelError::Status(code, r.into_string().unwrap_or_default()))
        }
        Err(ureq::Error::Transport(t)) => Err(OtelError::Transport(t.to_string())),
    }
}

// --- pipeline -------------------------------------------------------------------------

const CALLER_ATTRS: &[(&str, &str)] = &[
    ("session.id", "session_id"),
    ("claude.prompt_id", "prompt_id"),
    ("claude.agent_id", "agent_id"),
    ("claude.agent_type", "agent_type"),
    ("claude.permission_mode", "permission_mode"),
    ("claude.tool_use_id", "tool_use_id"),
    ("claude.hook_event", "hook_event_name"),
];

// Reads `hook.jsonl` records, accumulates metrics, buffers log records, and exports both.
#[derive(Debug)]
pub(crate) struct OtelPipeline {
    cfg: OtelConfig,
    redactor: Redactor,
    resource: Attributes,
    metrics: MetricRegistry,
    logs: Vec<OtelLogRecord>,
    dropped_logs: u64,
    high_water_ms: u64,
}

impl OtelPipeline {
    pub(crate) fn new(cfg: OtelConfig, start_time_ms: u64) -> Result<Self, OtelError> {
        if cfg.protocol != DEFAULT_PROTOCOL {
            return Err(OtelError::Config(format!(
                "protocol {:?} is not supported (only {DEFAULT_PROTOCOL})",
                cfg.protocol
            )));
        }
        let redactor = Redactor::new(&cfg.redact)?;
        let resource = resource_attributes(&cfg.service_name);
        Ok(Self {
            cfg,
            redactor,
            resource,
            metrics: MetricRegistry::new(start_time_ms),
            logs: Vec::new(),
            dropped_logs: 0,
            high_water_ms: 0,
        })
    }

    pub(crate) fn config(&self) -> &OtelConfig {
        &self.cfg
    }

    pub(crate) fn metrics(&self) -> &MetricRegistry {
        &self.metrics
    }

    // The instruments E-otel §5 lists that hook.jsonl cannot supply — approval.resolutions
    // for operator outcomes, approval.wait, rules.persisted for operator rules, and the
    // rules.active gauge — are recorded by the approval/live-rules code through this.
    pub(crate) fn metrics_mut(&mut self) -> &mut MetricRegistry {
        &mut self.metrics
    }

    pub(crate) fn pending_logs(&self) -> &[OtelLogRecord] {
        &self.logs
    }

    pub(crate) fn dropped_logs(&self) -> u64 {
        self.dropped_logs
    }

    pub(crate) fn high_water_ms(&self) -> u64 {
        self.high_water_ms
    }

    // Map one JSONL record. Returns false for a record with no `lk_event` or an event this
    // build does not know — a newer writer's event is skipped, never an error.
    pub(crate) fn ingest(&mut self, record: &Value) -> bool {
        let Some(event) = record.get("lk_event").and_then(Value::as_str) else {
            return false;
        };
        let mapped = match event {
            "pre_tool_use" => self.map_pre_tool_use(record),
            "post_tool_use" => self.map_post_tool_use(record),
            "llm_consult" => self.map_llm_consult(record),
            "llm_result" => self.map_llm_result(record),
            "llm_auto_approve" => self.map_llm_auto_approve(record),
            "llm_cache_hit" => self.map_llm_cache_hit(record),
            "operator_commit" => self.map_operator_commit(record),
            "permission_request" => self.map_pre_tool_use(record),
            "permission_denied" => self.map_permission_denied(record),
            "post_tool_use_failure" => self.map_post_tool_use_failure(record),
            _ => return false,
        };
        let ts_ms = record.get("ts_ms").and_then(Value::as_u64).unwrap_or(0);
        self.high_water_ms = self.high_water_ms.max(ts_ms);
        if self.cfg.logs {
            let (severity, body, mut attributes) = mapped;
            attributes.push((
                "lordkali.event".to_string(),
                AttrValue::Str(event.to_string()),
            ));
            caller_attributes(record, &mut attributes);
            self.push_log(OtelLogRecord {
                time_ms: ts_ms,
                severity,
                body,
                attributes,
            });
        }
        true
    }

    // POST whatever has accumulated, then advance the checkpoint. Metrics are cumulative so
    // they are not cleared; logs are only dropped once the collector has taken them. A
    // partial failure leaves the checkpoint where it was, so the next run replays.
    pub(crate) fn export(&mut self, now_ms: u64) -> Result<(), OtelError> {
        let headers = headers_from_env(&self.cfg.headers_env);
        if self.cfg.metrics && !self.metrics.is_empty() {
            let payload = self.metrics.to_otlp_metrics(&self.resource, now_ms);
            post_json(&metrics_url(&self.cfg.endpoint), &headers, &payload)?;
        }
        if self.cfg.logs && !self.logs.is_empty() {
            let payload = logs_payload(&self.resource, &self.logs);
            post_json(&logs_url(&self.cfg.endpoint), &headers, &payload)?;
            self.logs.clear();
        }
        if self.high_water_ms > 0 {
            write_checkpoint(&checkpoint_path(&self.cfg), self.high_water_ms)?;
        }
        Ok(())
    }

    fn push_log(&mut self, record: OtelLogRecord) {
        if self.logs.len() >= MAX_PENDING_LOGS {
            self.logs.remove(0);
            self.dropped_logs += 1;
        }
        self.logs.push(record);
    }

    fn count(&mut self, name: &str, attrs: &[(&str, &str)], value: u64) {
        if self.cfg.metrics {
            self.metrics.add(name, attrs, value);
        }
    }

    fn observe(&mut self, name: &str, attrs: &[(&str, &str)], value_ms: f64) {
        if self.cfg.metrics {
            self.metrics.record(name, attrs, value_ms);
        }
    }

    // Command text leaves the machine only when `include_command` is on, and only after
    // every `redact` pattern has been applied (E-otel §6).
    fn push_command(&self, attrs: &mut Attributes, key: &str, text: Option<&str>) {
        if !self.cfg.include_command {
            return;
        }
        if let Some(t) = text.filter(|s| !s.is_empty()) {
            attrs.push((key.to_string(), AttrValue::Str(self.redactor.apply(t))));
        }
    }

    fn push_nodes(&self, attrs: &mut Attributes, decision: Option<&Value>) {
        if !self.cfg.include_command {
            return;
        }
        let Some(nodes) = decision
            .and_then(|d| d.get("nodes"))
            .and_then(Value::as_array)
        else {
            return;
        };
        let values: Vec<AttrValue> = nodes
            .iter()
            .map(|n| {
                let command = n.get("command").and_then(Value::as_str).unwrap_or("");
                let args = n.get("args").and_then(Value::as_str).unwrap_or("");
                AttrValue::Str(self.redactor.apply(format!("{command} {args}").trim()))
            })
            .collect();
        if !values.is_empty() {
            attrs.push(("lordkali.nodes".to_string(), AttrValue::Array(values)));
        }
    }

    fn map_pre_tool_use(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let decision = r.get("lk_decision");
        let final_decision = field(decision, "final").unwrap_or("passthrough");
        let kind = field(decision, "kind").unwrap_or("unknown");
        let tool = r.get("tool_name").and_then(Value::as_str).unwrap_or("");
        let deciding = decision
            .and_then(|d| d.get("deciding"))
            .filter(|d| !d.is_null());

        let mut series: Vec<(&str, &str)> = vec![
            ("decision", final_decision),
            ("kind", kind),
            ("tool", tool),
            ("matched", bool_str(deciding.is_some())),
        ];
        let rule_kind = field(deciding, "rule_kind");
        let source_file = field(deciding, "source_file");
        if let Some(k) = rule_kind {
            series.push(("rule_kind", k));
        }
        if let Some(s) = source_file {
            series.push(("source_file", s));
        }
        self.count(GATE_DECISIONS, &series, 1);

        // "Reached the queue" = the operator (or the LLM lane) still has to rule on it.
        let blocked = matches!(final_decision, "ask" | "passthrough");
        if let Some(ms) = r.get("lk_duration_ms").and_then(Value::as_f64) {
            self.observe(
                GATE_DURATION,
                &[("decision", final_decision), ("blocked", bool_str(blocked))],
                ms,
            );
        }
        if blocked {
            self.count(APPROVAL_REQUESTS, &[("tool", tool), ("kind", kind)], 1);
        }

        let mut attrs: Attributes = Vec::new();
        push_str_attr(&mut attrs, "lordkali.tool", Some(tool));
        push_str_attr(&mut attrs, "lordkali.decision", Some(final_decision));
        push_str_attr(&mut attrs, "lordkali.kind", Some(kind));
        push_str_attr(
            &mut attrs,
            "lordkali.cwd",
            r.get("cwd").and_then(Value::as_str),
        );
        push_str_attr(&mut attrs, "lordkali.rule.source_file", source_file);
        push_str_attr(
            &mut attrs,
            "lordkali.rule.command",
            field(deciding, "rule_command"),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.rule.args",
            field(deciding, "rule_args"),
        );
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.get("tool_input")
                .and_then(|t| t.get("command"))
                .and_then(Value::as_str),
        );
        self.push_nodes(&mut attrs, decision);

        let body = field(decision, "reason")
            .unwrap_or(final_decision)
            .to_string();
        (severity_for_decision(final_decision), body, attrs)
    }

    fn map_post_tool_use(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let mut attrs: Attributes = Vec::new();
        push_str_attr(
            &mut attrs,
            "lordkali.tool",
            r.get("tool_name").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.cwd",
            r.get("cwd").and_then(Value::as_str),
        );
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.get("tool_input")
                .and_then(|t| t.get("command"))
                .and_then(Value::as_str),
        );
        (Severity::Info, "executed".to_string(), attrs)
    }

    // The consult itself carries no verdict, so it is counted at `llm_result` where the
    // `verdict` attribute E-otel §5 requires is known.
    fn map_llm_consult(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let mut attrs: Attributes = Vec::new();
        push_str_attr(
            &mut attrs,
            "lordkali.llm.id",
            r.get("id").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.llm.model",
            r.get("model").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.tool",
            r.get("tool").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.cwd",
            r.get("cwd").and_then(Value::as_str),
        );
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.get("target").and_then(Value::as_str),
        );
        (Severity::Info, "model consulted".to_string(), attrs)
    }

    fn map_llm_result(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let model = r.get("model").and_then(Value::as_str).unwrap_or("");
        let verdict = r.get("verdict").and_then(Value::as_str).unwrap_or("error");
        self.count(LLM_CONSULTS, &[("model", model), ("verdict", verdict)], 1);
        if let Some(ms) = r.get("latency_ms").and_then(Value::as_f64) {
            self.observe(LLM_LATENCY, &[("model", model), ("verdict", verdict)], ms);
        }
        if let Some(tokens) = r.get("total_tokens").and_then(Value::as_u64) {
            self.count(LLM_TOKENS, &[("model", model)], tokens);
        }

        let mut attrs: Attributes = Vec::new();
        push_str_attr(
            &mut attrs,
            "lordkali.llm.id",
            r.get("id").and_then(Value::as_str),
        );
        push_str_attr(&mut attrs, "lordkali.llm.model", Some(model));
        push_str_attr(&mut attrs, "lordkali.llm.verdict", Some(verdict));
        if let Some(ms) = r.get("latency_ms").and_then(Value::as_i64) {
            attrs.push(("lordkali.llm.latency_ms".to_string(), AttrValue::Int(ms)));
        }
        if let Some(b) = r.get("will_auto_approve").and_then(Value::as_bool) {
            attrs.push((
                "lordkali.llm.will_auto_approve".to_string(),
                AttrValue::Bool(b),
            ));
        }
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.get("target").and_then(Value::as_str),
        );

        let body = r
            .get("reason")
            .and_then(Value::as_str)
            .or_else(|| r.get("detail").and_then(Value::as_str))
            .unwrap_or(verdict)
            .to_string();
        // An `error` verdict is a real failure of the consult, not a routine outcome.
        let severity = if verdict == "error" {
            Severity::Error
        } else {
            Severity::Info
        };
        (severity, body, attrs)
    }

    fn map_llm_auto_approve(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let llm = r.get("lk_llm");
        let model = field(llm, "model").unwrap_or("");
        let verdict = field(llm, "verdict").unwrap_or("safe");
        self.count(
            APPROVAL_RESOLUTIONS,
            &[("outcome", "llm_auto"), ("lane", "llm")],
            1,
        );
        // The operator was away by construction, which is the "unattended" cell of the
        // agreement table in B §B6.
        self.count(
            LLM_AGREEMENT,
            &[("verdict", verdict), ("operator_outcome", "unattended")],
            1,
        );
        self.count(RULES_PERSISTED, &[("source", "llm")], 1);

        let mut attrs: Attributes = Vec::new();
        push_str_attr(
            &mut attrs,
            "lordkali.llm.id",
            r.get("id").and_then(Value::as_str),
        );
        push_str_attr(&mut attrs, "lordkali.llm.model", Some(model));
        push_str_attr(&mut attrs, "lordkali.llm.verdict", Some(verdict));
        push_str_attr(
            &mut attrs,
            "lordkali.tool",
            r.get("tool_name").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.cwd",
            r.get("cwd").and_then(Value::as_str),
        );
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.get("target").and_then(Value::as_str),
        );

        let body = field(llm, "reason").unwrap_or("auto-approved").to_string();
        (Severity::Info, body, attrs)
    }

    // A verdict reused from cache resolved a call without a call. Counted under the same
    // instrument with `cached="true"`, so consult volume stays comparable to spend.
    fn map_llm_cache_hit(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let model = r.get("model").and_then(Value::as_str).unwrap_or("");
        let verdict = r.get("verdict").and_then(Value::as_str).unwrap_or("");
        self.count(
            LLM_CONSULTS,
            &[("model", model), ("verdict", verdict), ("cached", "true")],
            1,
        );
        let mut attrs: Attributes = Vec::new();
        push_str_attr(
            &mut attrs,
            "lordkali.llm.id",
            r.get("id").and_then(Value::as_str),
        );
        push_str_attr(&mut attrs, "lordkali.llm.model", Some(model));
        push_str_attr(&mut attrs, "lordkali.llm.verdict", Some(verdict));
        attrs.push(("lordkali.llm.cached".to_string(), AttrValue::Bool(true)));
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.get("target").and_then(Value::as_str),
        );
        (
            Severity::Info,
            "verdict reused from cache".to_string(),
            attrs,
        )
    }

    // What the operator decided, and — when the model had already answered — whether they
    // agreed with it. This is the only record carrying both, so it is the only source for
    // the operator half of the agreement table (docs/B-ai-first-gating.md §B6).
    fn map_operator_commit(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let mode = r.get("mode").and_then(Value::as_str).unwrap_or("once");
        let lanes = r.get("lanes").and_then(Value::as_array);
        let dominant = dominant_lane(lanes);
        let outcome = format!("operator_{mode}");
        self.count(
            APPROVAL_RESOLUTIONS,
            &[("outcome", &outcome), ("lane", dominant)],
            1,
        );

        // A verdict is attributed only when the model had reached one; acting before it
        // answered is not a disagreement and must not be scored as one.
        if let Some(verdict) = r.pointer("/lk_llm/verdict").and_then(Value::as_str) {
            let operator_outcome = match dominant {
                "allow" => "allowed",
                "deny" => "denied",
                _ => "asked",
            };
            self.count(
                LLM_AGREEMENT,
                &[("verdict", verdict), ("operator_outcome", operator_outcome)],
                1,
            );
        }

        // Only an *-always commit persists rules, and only for the lanes that took a side.
        if mode == "always" {
            for lane in lanes.into_iter().flatten() {
                let l = lane.get("lane").and_then(Value::as_str).unwrap_or("");
                if l != "allow" && l != "deny" {
                    continue;
                }
                let shell = lane.get("shell").and_then(Value::as_str).unwrap_or("");
                let rung = lane
                    .get("scope_rung")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
                    .to_string();
                self.count(
                    RULES_PERSISTED,
                    &[("source", "operator"), ("shell", shell), ("rung", &rung)],
                    1,
                );
            }
        }

        let mut attrs: Attributes = Vec::new();
        push_str_attr(&mut attrs, "lordkali.approval.mode", Some(mode));
        push_str_attr(&mut attrs, "lordkali.approval.lane", Some(dominant));
        push_str_attr(
            &mut attrs,
            "lordkali.llm.verdict",
            r.pointer("/lk_llm/verdict").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.tool",
            r.get("tool_name").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.cwd",
            r.get("cwd").and_then(Value::as_str),
        );
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.get("target").and_then(Value::as_str),
        );
        (
            Severity::Info,
            format!("operator {mode}: {dominant}"),
            attrs,
        )
    }

    // Claude Code denied a call lord-kali had passed through — including auto mode's
    // classifier. Nothing else records that this happened.
    fn map_permission_denied(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let by = r.get("denied_by").and_then(Value::as_str).unwrap_or("");
        self.count(CLAUDE_DENIED, &[("denied_by", by)], 1);

        let mut attrs: Attributes = Vec::new();
        push_str_attr(&mut attrs, "lordkali.denied_by", Some(by));
        push_str_attr(
            &mut attrs,
            "lordkali.classifier_verdict",
            r.get("classifier_verdict").and_then(Value::as_str),
        );
        push_str_attr(
            &mut attrs,
            "lordkali.tool",
            r.get("tool_name").and_then(Value::as_str),
        );
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.pointer("/tool_input/command").and_then(Value::as_str),
        );
        let body = r
            .get("classifier_verdict")
            .and_then(Value::as_str)
            .unwrap_or("denied by Claude Code")
            .to_string();
        (Severity::Warn, body, attrs)
    }

    // A failed call fires this, not post_tool_use. Without it, "ran" and "did not run" are
    // indistinguishable in the record.
    fn map_post_tool_use_failure(&mut self, r: &Value) -> (Severity, String, Attributes) {
        let tool = r.get("tool_name").and_then(Value::as_str).unwrap_or("");
        self.count(TOOL_FAILURES, &[("tool", tool)], 1);

        let mut attrs: Attributes = Vec::new();
        push_str_attr(&mut attrs, "lordkali.tool", Some(tool));
        self.push_command(
            &mut attrs,
            "lordkali.command",
            r.pointer("/tool_input/command").and_then(Value::as_str),
        );
        let body = r
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("tool call failed")
            .to_string();
        (Severity::Error, body, attrs)
    }
}

// The most restrictive lane the operator assigned, which is what the call as a whole did:
// any deny denies it, else any ask defers it, else it ran.
fn dominant_lane(lanes: Option<&Vec<Value>>) -> &'static str {
    let Some(lanes) = lanes else {
        return "allow";
    };
    let has = |want: &str| {
        lanes
            .iter()
            .any(|l| l.get("lane").and_then(Value::as_str) == Some(want))
    };
    if has("deny") {
        "deny"
    } else if has("ask") {
        "ask"
    } else {
        "allow"
    }
}

fn ms_to_ns(ms: u64) -> u64 {
    ms.saturating_mul(1_000_000)
}

fn bool_str(b: bool) -> &'static str {
    if b {
        "true"
    } else {
        "false"
    }
}

fn field<'a>(parent: Option<&'a Value>, key: &str) -> Option<&'a str> {
    parent?.get(key)?.as_str()
}

fn push_str_attr(attrs: &mut Attributes, key: &str, value: Option<&str>) {
    if let Some(v) = value.filter(|s| !s.is_empty()) {
        attrs.push((key.to_string(), AttrValue::Str(v.to_string())));
    }
}

fn caller_attributes(record: &Value, attrs: &mut Attributes) {
    for (otel_key, json_key) in CALLER_ATTRS {
        push_str_attr(
            attrs,
            otel_key,
            record.get(json_key).and_then(Value::as_str),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TS: u64 = 1_724_930_000_000;

    fn pipeline(cfg: OtelConfig) -> OtelPipeline {
        OtelPipeline::new(cfg, TS).unwrap()
    }

    fn pre_tool_use_record() -> Value {
        serde_json::json!({
            "session_id": "s1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": "git push && echo GITHUB_TOKEN=abc123" },
            "cwd": "/proj",
            "ts_ms": TS,
            "lk_event": "pre_tool_use",
            "lk_decision": {
                "final": "deny",
                "kind": "command_chain",
                "reason": "pushing to a remote is blocked",
                "deciding": {
                    "shell": "bash",
                    "command": "git",
                    "args": "push",
                    "decision": "deny",
                    "matched": true,
                    "reason": "pushing to a remote is blocked",
                    "rule_kind": "explicit",
                    "rule_command": "git",
                    "rule_args": "push{, **}",
                    "source_file": "/rules/10-git.toml"
                },
                "nodes": [
                    { "shell": "bash", "command": "git", "args": "push", "decision": "deny", "matched": true },
                    { "shell": "bash", "command": "echo", "args": "GITHUB_TOKEN=abc123", "decision": "passthrough", "matched": false }
                ]
            }
        })
    }

    fn attr<'a>(record: &'a OtelLogRecord, key: &str) -> Option<&'a AttrValue> {
        record
            .attributes
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    // --- OTLP JSON encoding ---

    #[test]
    fn sixty_four_bit_fields_encode_as_json_strings() {
        let mut reg = MetricRegistry::new(TS);
        reg.add(GATE_DECISIONS, &[("decision", "allow")], 42);
        reg.record(GATE_DURATION, &[("decision", "allow")], 12.5);
        reg.set(RULES_ACTIVE, &[("state", "live")], 7);

        let payload = reg.to_otlp_metrics(&resource_attributes("lord-kali"), TS + 1000);
        let metrics = &payload["resourceMetrics"][0]["scopeMetrics"][0]["metrics"];

        let sum = metrics
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == GATE_DECISIONS)
            .unwrap();
        let point = &sum["sum"]["dataPoints"][0];
        assert_eq!(point["asInt"], Value::String("42".into()));
        assert_eq!(
            point["timeUnixNano"],
            Value::String(((TS + 1000) * 1_000_000).to_string())
        );
        assert_eq!(
            point["startTimeUnixNano"],
            Value::String((TS * 1_000_000).to_string())
        );
        assert_eq!(sum["sum"]["aggregationTemporality"], serde_json::json!(2));
        assert_eq!(sum["sum"]["isMonotonic"], serde_json::json!(true));

        let hist = metrics
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == GATE_DURATION)
            .unwrap();
        let hp = &hist["histogram"]["dataPoints"][0];
        assert_eq!(hp["count"], Value::String("1".into()));
        // `sum` is a protobuf double, so it stays a JSON number while count/buckets do not.
        assert!(hp["sum"].is_f64());
        assert!(hp["bucketCounts"]
            .as_array()
            .unwrap()
            .iter()
            .all(Value::is_string));
        assert_eq!(hist["unit"], "ms");

        let gauge = metrics
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["name"] == RULES_ACTIVE)
            .unwrap();
        assert_eq!(
            gauge["gauge"]["dataPoints"][0]["asInt"],
            Value::String("7".into())
        );
    }

    #[test]
    fn attribute_any_value_shapes() {
        let attrs: Attributes = vec![
            ("a.str".into(), AttrValue::Str("x".into())),
            ("a.int".into(), AttrValue::Int(9)),
            ("a.bool".into(), AttrValue::Bool(true)),
            (
                "a.arr".into(),
                AttrValue::Array(vec![AttrValue::Str("n1".into())]),
            ),
        ];
        let json = attributes_json(&attrs);
        assert_eq!(
            json[0],
            serde_json::json!({ "key": "a.str", "value": { "stringValue": "x" } })
        );
        // int64 AnyValue is a decimal string, not a number.
        assert_eq!(
            json[1],
            serde_json::json!({ "key": "a.int", "value": { "intValue": "9" } })
        );
        assert_eq!(
            json[2],
            serde_json::json!({ "key": "a.bool", "value": { "boolValue": true } })
        );
        assert_eq!(
            json[3],
            serde_json::json!({
                "key": "a.arr",
                "value": { "arrayValue": { "values": [{ "stringValue": "n1" }] } }
            })
        );
    }

    #[test]
    fn resource_carries_service_and_host() {
        let attrs = resource_attributes("lord-kali");
        let keys: Vec<&str> = attrs.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(keys, ["service.name", "service.version", "host.name"]);
        assert_eq!(
            attrs[1].1,
            AttrValue::Str(env!("CARGO_PKG_VERSION").to_string())
        );
    }

    #[test]
    fn logs_payload_shape_and_string_timestamps() {
        let record = OtelLogRecord {
            time_ms: TS,
            severity: Severity::Error,
            body: "denied".into(),
            attributes: vec![("lordkali.tool".into(), AttrValue::Str("Bash".into()))],
        };
        let payload = logs_payload(&resource_attributes("lord-kali"), &[record]);
        let lr = &payload["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0];
        assert_eq!(
            lr["timeUnixNano"],
            Value::String((TS * 1_000_000).to_string())
        );
        assert_eq!(lr["observedTimeUnixNano"], lr["timeUnixNano"]);
        assert_eq!(lr["severityNumber"], serde_json::json!(17));
        assert_eq!(lr["severityText"], "ERROR");
        assert_eq!(lr["body"], serde_json::json!({ "stringValue": "denied" }));
        assert_eq!(
            payload["resourceLogs"][0]["scopeLogs"][0]["scope"]["name"],
            "lord-kali"
        );
    }

    // --- severity ---

    #[test]
    fn severity_mapping() {
        assert_eq!(severity_for_decision("deny"), Severity::Error);
        assert_eq!(severity_for_decision("ask"), Severity::Warn);
        assert_eq!(severity_for_decision("allow"), Severity::Info);
        assert_eq!(severity_for_decision("passthrough"), Severity::Info);
        assert_eq!(Severity::Error.number(), 17);
        assert_eq!(Severity::Warn.number(), 13);
        assert_eq!(Severity::Info.number(), 9);
        assert_eq!(Severity::Warn.text(), "WARN");
    }

    // --- redaction / include_command ---

    #[test]
    fn redaction_removes_matching_text() {
        let r =
            Redactor::new(&["/[A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|KEY|PAT)=\\S+/".into()]).unwrap();
        let out = r.apply("curl -H GITHUB_TOKEN=ghp_abc123 https://x");
        assert!(!out.contains("ghp_abc123"));
        assert!(!out.contains("GITHUB_TOKEN"));
        assert!(out.contains(REDACTION_PLACEHOLDER));
        assert!(out.contains("https://x"));
    }

    #[test]
    fn redaction_without_slash_delimiters_still_compiles() {
        let r = Redactor::new(&["secret".into()]).unwrap();
        assert_eq!(
            r.apply("a secret b"),
            format!("a {REDACTION_PLACEHOLDER} b")
        );
    }

    #[test]
    fn invalid_redact_pattern_is_an_error() {
        let err = Redactor::new(&["/[unclosed/".into()]).unwrap_err();
        assert!(matches!(err, OtelError::Config(_)));
    }

    #[test]
    fn redaction_applies_to_exported_command_and_nodes() {
        let cfg = OtelConfig {
            redact: vec!["/[A-Za-z0-9_]*(TOKEN|SECRET)=\\S+/".into()],
            ..Default::default()
        };
        let mut p = pipeline(cfg);
        assert!(p.ingest(&pre_tool_use_record()));
        let log = &p.pending_logs()[0];
        let AttrValue::Str(command) = attr(log, "lordkali.command").unwrap() else {
            panic!("command attribute should be a string");
        };
        assert!(!command.contains("abc123"));
        assert!(command.contains("git push"));
        let AttrValue::Array(nodes) = attr(log, "lordkali.nodes").unwrap() else {
            panic!("nodes attribute should be an array");
        };
        assert_eq!(nodes[0], AttrValue::Str("git push".into()));
        assert_eq!(
            nodes[1],
            AttrValue::Str(format!("echo {REDACTION_PLACEHOLDER}"))
        );
    }

    #[test]
    fn include_command_false_omits_command_entirely() {
        let cfg = OtelConfig {
            include_command: false,
            ..Default::default()
        };
        let mut p = pipeline(cfg);
        assert!(p.ingest(&pre_tool_use_record()));
        let log = &p.pending_logs()[0];
        assert!(attr(log, "lordkali.command").is_none());
        assert!(attr(log, "lordkali.nodes").is_none());
        // The decision itself is still reported.
        assert_eq!(
            attr(log, "lordkali.decision"),
            Some(&AttrValue::Str("deny".into()))
        );
        let serialised = logs_payload(&resource_attributes("x"), p.pending_logs()).to_string();
        assert!(!serialised.contains("abc123"));
        assert!(!serialised.contains("git push"));
    }

    // --- record mapping ---

    #[test]
    fn pre_tool_use_maps_to_expected_metrics_and_log() {
        let mut p = pipeline(OtelConfig::default());
        assert!(p.ingest(&pre_tool_use_record()));

        assert_eq!(
            p.metrics().counter(
                GATE_DECISIONS,
                &[
                    ("decision", "deny"),
                    ("kind", "command_chain"),
                    ("tool", "Bash"),
                    ("matched", "true"),
                    ("rule_kind", "explicit"),
                    ("source_file", "/rules/10-git.toml"),
                ]
            ),
            1
        );
        // A deny never reaches the approval queue.
        assert_eq!(
            p.metrics().counter(
                APPROVAL_REQUESTS,
                &[("tool", "Bash"), ("kind", "command_chain")]
            ),
            0
        );

        let log = &p.pending_logs()[0];
        assert_eq!(log.severity, Severity::Error);
        assert_eq!(log.body, "pushing to a remote is blocked");
        assert_eq!(log.time_ms, TS);
        assert_eq!(
            attr(log, "lordkali.rule.source_file"),
            Some(&AttrValue::Str("/rules/10-git.toml".into()))
        );
        assert_eq!(
            attr(log, "lordkali.rule.args"),
            Some(&AttrValue::Str("push{, **}".into()))
        );
        assert_eq!(attr(log, "session.id"), Some(&AttrValue::Str("s1".into())));
        assert_eq!(
            attr(log, "claude.hook_event"),
            Some(&AttrValue::Str("PreToolUse".into()))
        );
        assert_eq!(p.high_water_ms(), TS);
    }

    #[test]
    fn passthrough_counts_an_approval_request_and_no_rule_attributes() {
        let mut p = pipeline(OtelConfig::default());
        let record = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": "gh pr list" },
            "cwd": "/proj",
            "ts_ms": TS,
            "lk_event": "pre_tool_use",
            "lk_decision": {
                "final": "passthrough",
                "kind": "command_chain",
                "deciding": null,
                "nodes": [{ "command": "gh", "args": "pr list", "decision": "passthrough", "matched": false }]
            }
        });
        assert!(p.ingest(&record));

        assert_eq!(
            p.metrics().counter(
                GATE_DECISIONS,
                &[
                    ("decision", "passthrough"),
                    ("kind", "command_chain"),
                    ("tool", "Bash"),
                    ("matched", "false"),
                ]
            ),
            1
        );
        assert_eq!(
            p.metrics().counter(
                APPROVAL_REQUESTS,
                &[("tool", "Bash"), ("kind", "command_chain")]
            ),
            1
        );
        let log = &p.pending_logs()[0];
        assert_eq!(log.severity, Severity::Info);
        assert_eq!(log.body, "passthrough");
        assert!(attr(log, "lordkali.rule.source_file").is_none());
    }

    #[test]
    fn gate_duration_recorded_only_when_the_record_carries_it() {
        let mut p = pipeline(OtelConfig::default());
        assert!(p.ingest(&pre_tool_use_record()));
        assert!(p
            .metrics()
            .histogram(GATE_DURATION, &[("decision", "deny"), ("blocked", "false")])
            .is_none());

        let mut timed = pre_tool_use_record();
        timed["lk_duration_ms"] = serde_json::json!(30);
        assert!(p.ingest(&timed));
        let h = p
            .metrics()
            .histogram(GATE_DURATION, &[("decision", "deny"), ("blocked", "false")])
            .unwrap();
        assert_eq!(h.count, 1);
        assert_eq!(h.sum, 30.0);
    }

    #[test]
    fn counters_and_histograms_accumulate_across_records() {
        let mut p = pipeline(OtelConfig::default());
        for latency in [40u64, 900, 6000] {
            let record = serde_json::json!({
                "lk_event": "llm_result",
                "ts_ms": TS + latency,
                "id": "r1",
                "model": "m1",
                "verdict": "safe",
                "reason": "read-only",
                "latency_ms": latency,
                "total_tokens": 100,
            });
            assert!(p.ingest(&record));
        }
        let series = [("model", "m1"), ("verdict", "safe")];
        assert_eq!(p.metrics().counter(LLM_CONSULTS, &series), 3);
        assert_eq!(p.metrics().counter(LLM_TOKENS, &[("model", "m1")]), 300);

        let h = p.metrics().histogram(LLM_LATENCY, &series).unwrap();
        assert_eq!(h.count, 3);
        assert_eq!(h.sum, 6940.0);
        assert_eq!(h.buckets.len(), HISTOGRAM_BOUNDS.len() + 1);
        assert_eq!(h.buckets.iter().sum::<u64>(), 3);
        // 40 -> (25,50], 900 -> (750,1000], 6000 -> (5000,7500]
        assert_eq!(h.buckets[4], 1);
        assert_eq!(h.buckets[10], 1);
        assert_eq!(h.buckets[13], 1);
        assert_eq!(p.high_water_ms(), TS + 6000);
        assert_eq!(p.pending_logs().len(), 3);
    }

    #[test]
    fn metric_attribute_order_does_not_split_a_series() {
        let mut reg = MetricRegistry::new(TS);
        reg.add(
            GATE_DECISIONS,
            &[("decision", "allow"), ("tool", "Bash")],
            1,
        );
        reg.add(
            GATE_DECISIONS,
            &[("tool", "Bash"), ("decision", "allow")],
            1,
        );
        assert_eq!(
            reg.counter(GATE_DECISIONS, &[("decision", "allow"), ("tool", "Bash")]),
            2
        );
    }

    #[test]
    fn llm_error_verdict_is_error_severity() {
        let mut p = pipeline(OtelConfig::default());
        let record = serde_json::json!({
            "lk_event": "llm_result",
            "ts_ms": TS,
            "model": "m1",
            "verdict": "error",
            "detail": "http 503",
            "latency_ms": 8000,
        });
        assert!(p.ingest(&record));
        let log = &p.pending_logs()[0];
        assert_eq!(log.severity, Severity::Error);
        assert_eq!(log.body, "http 503");
        assert_eq!(
            p.metrics()
                .counter(LLM_CONSULTS, &[("model", "m1"), ("verdict", "error")]),
            1
        );
    }

    #[test]
    fn llm_auto_approve_maps_resolution_agreement_and_persisted_rule() {
        let mut p = pipeline(OtelConfig::default());
        let record = serde_json::json!({
            "lk_event": "llm_auto_approve",
            "ts_ms": TS,
            "id": "q1",
            "tool_name": "Bash",
            "target": "cargo test",
            "cwd": "/proj",
            "lk_llm": { "model": "m1", "verdict": "safe", "reason": "local test run", "auto_applied": true }
        });
        assert!(p.ingest(&record));
        assert_eq!(
            p.metrics().counter(
                APPROVAL_RESOLUTIONS,
                &[("outcome", "llm_auto"), ("lane", "llm")]
            ),
            1
        );
        assert_eq!(
            p.metrics().counter(
                LLM_AGREEMENT,
                &[("verdict", "safe"), ("operator_outcome", "unattended")]
            ),
            1
        );
        assert_eq!(
            p.metrics().counter(RULES_PERSISTED, &[("source", "llm")]),
            1
        );
        assert_eq!(p.pending_logs()[0].body, "local test run");
    }

    #[test]
    fn llm_consult_logs_without_touching_metrics() {
        let mut p = pipeline(OtelConfig::default());
        let record = serde_json::json!({
            "lk_event": "llm_consult",
            "ts_ms": TS,
            "id": "q1",
            "model": "m1",
            "tool": "Bash",
            "target": "cargo test",
            "cwd": "/proj",
        });
        assert!(p.ingest(&record));
        assert!(p.metrics().is_empty());
        assert_eq!(p.pending_logs().len(), 1);
    }

    #[test]
    fn post_tool_use_logs_without_touching_metrics() {
        let mut p = pipeline(OtelConfig::default());
        let record = serde_json::json!({
            "lk_event": "post_tool_use",
            "ts_ms": TS,
            "tool_name": "Bash",
            "tool_input": { "command": "ls" },
            "cwd": "/proj",
        });
        assert!(p.ingest(&record));
        assert!(p.metrics().is_empty());
        assert_eq!(p.pending_logs()[0].severity, Severity::Info);
    }

    // ---- events from workstreams B and D ------------------------------------------------

    fn commit(mode: &str, lanes: Value, llm: Value) -> Value {
        serde_json::json!({
            "lk_event": "operator_commit", "ts_ms": TS,
            "tool_name": "Bash", "target": "gh pr list", "cwd": "/p",
            "mode": mode, "lanes": lanes, "lk_llm": llm,
        })
    }

    fn lane(l: &str, shell: &str, rung: u64) -> Value {
        serde_json::json!({ "lane": l, "shell": shell, "scope_rung": rung, "node": "gh" })
    }

    // The expensive cell: the model said safe and the operator overrode it.
    #[test]
    fn an_operator_override_of_a_safe_verdict_is_scored_as_disagreement() {
        let mut p = pipeline(OtelConfig::default());
        assert!(p.ingest(&commit(
            "once",
            serde_json::json!([lane("allow", "bash", 1), lane("deny", "bash", 0)]),
            serde_json::json!({ "model": "m", "verdict": "safe" }),
        )));
        assert_eq!(
            p.metrics().counter(
                LLM_AGREEMENT,
                &[("verdict", "safe"), ("operator_outcome", "denied")]
            ),
            1
        );
        assert_eq!(
            p.metrics().counter(
                APPROVAL_RESOLUTIONS,
                &[("outcome", "operator_once"), ("lane", "deny")]
            ),
            1
        );
    }

    // Acting before the model answered is not a disagreement and must not be scored.
    #[test]
    fn a_commit_with_no_model_verdict_scores_no_agreement() {
        let mut p = pipeline(OtelConfig::default());
        assert!(p.ingest(&commit(
            "always",
            serde_json::json!([lane("allow", "bash", 1)]),
            Value::Null,
        )));
        assert_eq!(
            p.metrics().counter(
                LLM_AGREEMENT,
                &[("verdict", "safe"), ("operator_outcome", "allowed")]
            ),
            0
        );
        assert_eq!(
            p.metrics().counter(
                APPROVAL_RESOLUTIONS,
                &[("outcome", "operator_always"), ("lane", "allow")]
            ),
            1
        );
    }

    // Only an *-always commit persists rules, and only for lanes that took a side.
    #[test]
    fn rules_are_counted_only_for_always_commits_and_decided_lanes() {
        let mut p = pipeline(OtelConfig::default());
        p.ingest(&commit(
            "always",
            serde_json::json!([lane("allow", "bash", 1), lane("ask", "bash", 0)]),
            Value::Null,
        ));
        assert_eq!(
            p.metrics().counter(
                RULES_PERSISTED,
                &[("source", "operator"), ("shell", "bash"), ("rung", "1")]
            ),
            1
        );
        assert_eq!(
            p.metrics().counter(
                RULES_PERSISTED,
                &[("source", "operator"), ("shell", "bash"), ("rung", "0")]
            ),
            0,
            "an ASK lane persists nothing"
        );

        p.ingest(&commit(
            "once",
            serde_json::json!([lane("allow", "bash", 1)]),
            Value::Null,
        ));
        assert_eq!(
            p.metrics().counter(
                RULES_PERSISTED,
                &[("source", "operator"), ("shell", "bash"), ("rung", "1")]
            ),
            1,
            "an apply-once must not count as a persisted rule"
        );
    }

    #[test]
    fn a_skip_is_recorded_as_its_own_outcome() {
        let mut p = pipeline(OtelConfig::default());
        p.ingest(&commit(
            "skip",
            serde_json::json!([lane("allow", "bash", 1)]),
            Value::Null,
        ));
        assert_eq!(
            p.metrics().counter(
                APPROVAL_RESOLUTIONS,
                &[("outcome", "operator_skip"), ("lane", "allow")]
            ),
            1
        );
    }

    #[test]
    fn a_cached_verdict_counts_as_a_consult_marked_cached() {
        let mut p = pipeline(OtelConfig::default());
        assert!(p.ingest(&serde_json::json!({
            "lk_event": "llm_cache_hit", "ts_ms": TS,
            "model": "m", "verdict": "safe", "target": "ls",
        })));
        assert_eq!(
            p.metrics().counter(
                LLM_CONSULTS,
                &[("model", "m"), ("verdict", "safe"), ("cached", "true")]
            ),
            1
        );
    }

    #[test]
    fn a_claude_code_denial_is_counted_and_logged_as_a_warning() {
        let mut p = pipeline(OtelConfig::default());
        assert!(p.ingest(&serde_json::json!({
            "lk_event": "permission_denied", "ts_ms": TS,
            "tool_name": "Bash", "tool_input": { "command": "rm -rf /" },
            "denied_by": "classifier", "classifier_verdict": "destructive",
        })));
        assert_eq!(
            p.metrics()
                .counter(CLAUDE_DENIED, &[("denied_by", "classifier")]),
            1
        );
        let rec = &p.pending_logs()[0];
        assert_eq!(rec.severity, Severity::Warn);
        assert_eq!(rec.body, "destructive");
    }

    #[test]
    fn a_tool_failure_is_counted_and_logged_as_an_error() {
        let mut p = pipeline(OtelConfig::default());
        assert!(p.ingest(&serde_json::json!({
            "lk_event": "post_tool_use_failure", "ts_ms": TS,
            "tool_name": "Bash", "tool_input": { "command": "ls /nope" },
            "error": "No such file",
        })));
        assert_eq!(p.metrics().counter(TOOL_FAILURES, &[("tool", "Bash")]), 1);
        assert_eq!(p.pending_logs()[0].severity, Severity::Error);
    }

    // PermissionRequest is a gate decision with the same shape as PreToolUse, so it feeds
    // the same instruments rather than a parallel set.
    #[test]
    fn a_permission_request_decision_feeds_the_gate_instruments() {
        let mut p = pipeline(OtelConfig::default());
        let mut r = pre_tool_use_record();
        r["lk_event"] = serde_json::json!("permission_request");
        assert!(p.ingest(&r));
        assert!(!p.metrics().is_empty());
        assert_eq!(
            p.pending_logs()[0]
                .attributes
                .iter()
                .find(|(k, _)| k == "lordkali.event")
                .map(|(_, v)| v.clone()),
            Some(AttrValue::Str("permission_request".into()))
        );
    }

    #[test]
    fn unknown_and_missing_events_are_skipped_without_error() {
        let mut p = pipeline(OtelConfig::default());
        assert!(!p.ingest(&serde_json::json!({ "lk_event": "future_event", "ts_ms": TS })));
        assert!(!p.ingest(&serde_json::json!({ "ts_ms": TS })));
        assert!(!p.ingest(&serde_json::json!("not an object")));
        assert!(p.metrics().is_empty());
        assert!(p.pending_logs().is_empty());
        assert_eq!(p.high_water_ms(), 0);
    }

    #[test]
    fn logs_disabled_still_accumulates_metrics() {
        let cfg = OtelConfig {
            logs: false,
            ..Default::default()
        };
        let mut p = pipeline(cfg);
        assert!(p.ingest(&pre_tool_use_record()));
        assert!(p.pending_logs().is_empty());
        assert!(!p.metrics().is_empty());
    }

    #[test]
    fn metrics_disabled_still_produces_logs() {
        let cfg = OtelConfig {
            metrics: false,
            ..Default::default()
        };
        let mut p = pipeline(cfg);
        assert!(p.ingest(&pre_tool_use_record()));
        assert!(p.metrics().is_empty());
        assert_eq!(p.pending_logs().len(), 1);
    }

    // --- config / checkpoint / transport helpers ---

    #[test]
    fn default_config_matches_the_documented_block() {
        let cfg = OtelConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.endpoint, "http://localhost:4318");
        assert_eq!(cfg.protocol, "http/json");
        assert_eq!(cfg.headers_env, "LORD_KALI_OTEL_HEADERS");
        assert_eq!(cfg.export_interval_ms, 10_000);
        assert!(cfg.metrics && cfg.logs && cfg.include_command);
        assert!(cfg.redact.is_empty());
        assert_eq!(cfg.service_name, "lord-kali");
        assert_eq!(cfg.checkpoint, DEFAULT_CHECKPOINT);
    }

    #[test]
    fn config_deserialises_partially_with_defaults() {
        let cfg: OtelConfig =
            toml::from_str("enabled = true\nendpoint = \"http://c:4318\"\nredact = [\"/x/\"]")
                .unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.endpoint, "http://c:4318");
        assert_eq!(cfg.redact, vec!["/x/".to_string()]);
        assert_eq!(cfg.protocol, DEFAULT_PROTOCOL);
        assert!(cfg.include_command);
    }

    #[test]
    fn unsupported_protocol_is_rejected_not_silently_downgraded() {
        let cfg = OtelConfig {
            protocol: "http/protobuf".into(),
            ..Default::default()
        };
        let err = OtelPipeline::new(cfg, TS).unwrap_err();
        assert!(matches!(err, OtelError::Config(_)));
        assert!(err.to_string().contains("http/protobuf"));
    }

    #[test]
    fn checkpoint_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("state").join("otel.checkpoint");
        assert_eq!(read_checkpoint(&path).unwrap(), None);
        write_checkpoint(&path, TS).unwrap();
        assert_eq!(read_checkpoint(&path).unwrap(), Some(TS));
        write_checkpoint(&path, TS + 5).unwrap();
        assert_eq!(read_checkpoint(&path).unwrap(), Some(TS + 5));
    }

    #[test]
    fn unreadable_checkpoint_is_an_error_not_a_silent_restart() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("otel.checkpoint");
        std::fs::write(&path, "not-a-timestamp").unwrap();
        assert!(matches!(
            read_checkpoint(&path).unwrap_err(),
            OtelError::Config(_)
        ));
    }

    #[test]
    fn export_urls_tolerate_a_trailing_slash() {
        assert_eq!(
            metrics_url("http://localhost:4318"),
            "http://localhost:4318/v1/metrics"
        );
        assert_eq!(
            logs_url("http://localhost:4318/"),
            "http://localhost:4318/v1/logs"
        );
    }

    #[test]
    fn header_env_parsing() {
        let parsed = parse_headers("api-key=abc, x-scope-orgid = tenant1 ,,broken");
        assert_eq!(
            parsed,
            vec![
                ("api-key".to_string(), "abc".to_string()),
                ("x-scope-orgid".to_string(), "tenant1".to_string()),
            ]
        );
        assert!(parse_headers("").is_empty());
    }

    #[test]
    fn export_reports_a_failure_instead_of_swallowing_it() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = OtelConfig {
            // Nothing listens on port 1, so the POST is refused immediately.
            endpoint: "http://127.0.0.1:1".into(),
            checkpoint: tmp
                .path()
                .join("otel.checkpoint")
                .to_string_lossy()
                .into_owned(),
            ..Default::default()
        };
        let mut p = pipeline(cfg);
        assert!(p.ingest(&pre_tool_use_record()));
        let err = p.export(TS).unwrap_err();
        assert!(matches!(
            err,
            OtelError::Transport(_) | OtelError::Status(_, _)
        ));
        // Nothing was acknowledged, so the checkpoint stays put and the logs stay buffered.
        assert!(!tmp.path().join("otel.checkpoint").exists());
        assert_eq!(p.pending_logs().len(), 1);
    }

    #[test]
    fn export_with_nothing_to_send_still_advances_the_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let checkpoint = tmp.path().join("otel.checkpoint");
        let cfg = OtelConfig {
            metrics: false,
            logs: false,
            checkpoint: checkpoint.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let mut p = pipeline(cfg);
        assert!(p.ingest(&pre_tool_use_record()));
        p.export(TS).unwrap();
        assert_eq!(read_checkpoint(&checkpoint).unwrap(), Some(TS));
    }
}
