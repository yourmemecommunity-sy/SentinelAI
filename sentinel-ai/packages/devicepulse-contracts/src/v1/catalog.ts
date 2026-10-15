/**
 * DevicePulse v1 catalog: every enumerated value the API accepts or returns.
 *
 * The request deliberately carries no free text. Everything a client sends is one of these enums, a bounded number or an
 * opaque identifier, so there is no field in which a device could smuggle logs, messages, contacts, app names or prompt
 * text. Adding a value here is an API change: bump SCHEMA_VERSION's minor version and update docs/devicepulse/api-contracts.md.
 */

export const SCHEMA_VERSION = "1.0" as const;
export const SUPPORTED_SCHEMA_VERSIONS = [SCHEMA_VERSION] as const;

export const DIAGNOSTIC_TYPES = ["battery_drain", "thermal", "storage", "memory", "network", "performance"] as const;
export type DiagnosticType = (typeof DIAGNOSTIC_TYPES)[number];

export const UNITS = [
  "percent", "percent_per_hour", "celsius", "count", "minutes", "hours", "level", "megabytes", "milliseconds", "dbm", "mbps",
] as const;
export type Unit = (typeof UNITS)[number];

export interface MetricSpec {
  unit: Unit;
  min: number;
  max: number;
  /** Whole numbers only (counts, levels). */
  integer: boolean;
}

/**
 * Bounds are physical or platform limits, not "normal" ranges: a value outside them is a client bug or forged telemetry.
 * Sizes are in megabytes on purpose: raw byte counts are long digit strings that can resemble card or account numbers to
 * the security scanner and would get legitimate requests blocked.
 */
export const METRICS = {
  battery_level:              { unit: "percent",          min: 0,    max: 100,        integer: false },
  battery_drain_rate:         { unit: "percent_per_hour", min: 0,    max: 100,        integer: false },
  battery_temperature:        { unit: "celsius",          min: -20,  max: 80,         integer: false },
  battery_capacity_health:    { unit: "percent",          min: 0,    max: 150,        integer: false },
  charge_cycles:              { unit: "count",            min: 0,    max: 10_000,     integer: true },
  screen_on_time_24h:         { unit: "minutes",          min: 0,    max: 1440,       integer: false },
  wakelock_time_24h:          { unit: "minutes",          min: 0,    max: 1440,       integer: false },
  cpu_temperature:            { unit: "celsius",          min: -20,  max: 130,        integer: false },
  skin_temperature:           { unit: "celsius",          min: -20,  max: 80,         integer: false },
  /** Android PowerManager thermal status: 0 NONE … 6 SHUTDOWN. */
  thermal_status:             { unit: "level",            min: 0,    max: 6,          integer: true },
  cpu_usage:                  { unit: "percent",          min: 0,    max: 100,        integer: false },
  storage_free:               { unit: "megabytes",        min: 0,    max: 16_000_000, integer: false },
  storage_total:              { unit: "megabytes",        min: 1,    max: 16_000_000, integer: false },
  storage_free_ratio:         { unit: "percent",          min: 0,    max: 100,        integer: false },
  cache_size_total:           { unit: "megabytes",        min: 0,    max: 16_000_000, integer: false },
  ram_available:              { unit: "megabytes",        min: 0,    max: 262_144,    integer: false },
  ram_total:                  { unit: "megabytes",        min: 1,    max: 262_144,    integer: false },
  low_memory_events_24h:      { unit: "count",            min: 0,    max: 10_000,     integer: true },
  background_process_count:   { unit: "count",            min: 0,    max: 1000,       integer: true },
  network_latency:            { unit: "milliseconds",     min: 0,    max: 60_000,     integer: false },
  packet_loss:                { unit: "percent",          min: 0,    max: 100,        integer: false },
  wifi_signal:                { unit: "dbm",              min: -127, max: 0,          integer: false },
  cellular_signal:            { unit: "dbm",              min: -140, max: -40,        integer: false },
  download_throughput:        { unit: "mbps",             min: 0,    max: 10_000,     integer: false },
  upload_throughput:          { unit: "mbps",             min: 0,    max: 10_000,     integer: false },
  dns_resolution_time:        { unit: "milliseconds",     min: 0,    max: 60_000,     integer: false },
  app_cold_start_time:        { unit: "milliseconds",     min: 0,    max: 60_000,     integer: false },
  frame_drop_ratio:           { unit: "percent",          min: 0,    max: 100,        integer: false },
  anr_count_24h:              { unit: "count",            min: 0,    max: 10_000,     integer: true },
  crash_count_24h:            { unit: "count",            min: 0,    max: 10_000,     integer: true },
  uptime:                     { unit: "hours",            min: 0,    max: 8760,       integer: false },
} as const satisfies Record<string, MetricSpec>;
export type MetricId = keyof typeof METRICS;
export const METRIC_IDS = Object.keys(METRICS) as [MetricId, ...MetricId[]];

/** Codes the Android app's own (local) rules may report. */
export const LOCAL_FINDING_CODES = [
  "high_drain_rate", "high_screen_on_time", "excessive_wakelocks", "battery_capacity_degraded", "high_battery_temperature",
  "device_overheating", "sustained_high_cpu", "thermal_throttling",
  "low_free_storage", "large_cache",
  "low_available_memory", "frequent_low_memory_events",
  "high_latency", "packet_loss", "weak_wifi_signal", "weak_cellular_signal", "slow_dns", "low_throughput",
  "frequent_anrs", "frequent_crashes", "frame_drops", "slow_app_start", "long_uptime",
] as const;
export type LocalFindingCode = (typeof LOCAL_FINDING_CODES)[number];

/**
 * Approved actions. The model may only pick from the list for the request's diagnostic type; the Android app maps each id to
 * localized text and, where applicable, a system settings screen. Nothing destructive or irreversible is in the catalog
 * (no factory reset, no network reset, no uninstall of a named app): those are never recommended by this API.
 */
export const ACTION_IDS = [
  "open_battery_settings", "enable_battery_saver", "reduce_screen_brightness", "shorten_screen_timeout", "review_background_usage",
  "let_device_cool_down", "remove_case_while_charging", "avoid_heavy_use_while_charging",
  "open_storage_settings", "clear_app_cache", "review_large_files", "remove_unused_apps",
  "restart_device", "review_running_apps",
  "toggle_airplane_mode", "forget_and_rejoin_wifi", "move_closer_to_router", "restart_router", "open_network_settings", "contact_carrier",
  "check_for_system_update", "contact_manufacturer_support",
] as const;
export type ActionId = (typeof ACTION_IDS)[number];

export const SEVERITIES = ["low", "medium", "high"] as const;
export type Severity = (typeof SEVERITIES)[number];
/** Response findings may also be purely informational. */
export const FINDING_SEVERITIES = ["info", "low", "medium", "high"] as const;
export type FindingSeverity = (typeof FINDING_SEVERITIES)[number];

export interface DiagnosticSpec {
  metrics: readonly MetricId[];
  localFindingCodes: readonly LocalFindingCode[];
  actions: readonly ActionId[];
}

export const DIAGNOSTICS: Readonly<Record<DiagnosticType, DiagnosticSpec>> = {
  battery_drain: {
    metrics: ["battery_level", "battery_drain_rate", "battery_temperature", "battery_capacity_health", "charge_cycles",
      "screen_on_time_24h", "wakelock_time_24h", "cpu_usage"],
    localFindingCodes: ["high_drain_rate", "high_screen_on_time", "excessive_wakelocks", "battery_capacity_degraded", "high_battery_temperature"],
    actions: ["open_battery_settings", "enable_battery_saver", "reduce_screen_brightness", "shorten_screen_timeout", "review_background_usage",
      "check_for_system_update", "contact_manufacturer_support"],
  },
  thermal: {
    metrics: ["battery_temperature", "cpu_temperature", "skin_temperature", "thermal_status", "cpu_usage", "battery_level"],
    localFindingCodes: ["device_overheating", "sustained_high_cpu", "thermal_throttling", "high_battery_temperature"],
    actions: ["let_device_cool_down", "remove_case_while_charging", "avoid_heavy_use_while_charging", "review_running_apps",
      "check_for_system_update", "contact_manufacturer_support"],
  },
  storage: {
    metrics: ["storage_free", "storage_total", "storage_free_ratio", "cache_size_total"],
    localFindingCodes: ["low_free_storage", "large_cache"],
    actions: ["open_storage_settings", "clear_app_cache", "review_large_files", "remove_unused_apps"],
  },
  memory: {
    metrics: ["ram_available", "ram_total", "low_memory_events_24h", "background_process_count", "uptime"],
    localFindingCodes: ["low_available_memory", "frequent_low_memory_events", "long_uptime"],
    actions: ["restart_device", "review_running_apps", "remove_unused_apps", "check_for_system_update"],
  },
  network: {
    metrics: ["network_latency", "packet_loss", "wifi_signal", "cellular_signal", "download_throughput", "upload_throughput", "dns_resolution_time"],
    localFindingCodes: ["high_latency", "packet_loss", "weak_wifi_signal", "weak_cellular_signal", "slow_dns", "low_throughput"],
    actions: ["toggle_airplane_mode", "forget_and_rejoin_wifi", "move_closer_to_router", "restart_router", "open_network_settings", "contact_carrier"],
  },
  performance: {
    metrics: ["app_cold_start_time", "frame_drop_ratio", "anr_count_24h", "crash_count_24h", "cpu_usage", "ram_available", "storage_free_ratio", "uptime"],
    localFindingCodes: ["frequent_anrs", "frequent_crashes", "frame_drops", "slow_app_start", "long_uptime", "low_free_storage", "low_available_memory"],
    actions: ["restart_device", "check_for_system_update", "clear_app_cache", "open_storage_settings", "review_running_apps", "remove_unused_apps"],
  },
};

/** BCP 47 tags the explanation can be written in. */
export const LOCALES = ["en-US", "en-GB", "en-IN", "hi-IN", "es-ES", "es-MX", "fr-FR", "de-DE", "pt-BR"] as const;
export type Locale = (typeof LOCALES)[number];
export const LOCALE_LANGUAGE: Readonly<Record<Locale, string>> = {
  "en-US": "English (United States)", "en-GB": "English (United Kingdom)", "en-IN": "English (India)", "hi-IN": "Hindi",
  "es-ES": "Spanish (Spain)", "es-MX": "Spanish (Mexico)", "fr-FR": "French", "de-DE": "German", "pt-BR": "Portuguese (Brazil)",
};

/** Why an explanation may be incomplete. The server always adds the first two. */
export const LIMITATION_CODES = [
  "model_generated_explanation", "model_confidence_uncalibrated",
  "limited_observation_window", "no_historical_baseline", "insufficient_observations", "metrics_not_hardware_verified",
  "manufacturer_customization_possible",
] as const;
export type LimitationCode = (typeof LIMITATION_CODES)[number];

/** Chosen by the server (never by the model) from the request and the approved actions. */
export const DISCLAIMER_CODES = [
  "ai_generated_content", "not_professional_repair_advice", "battery_safety_warning", "backup_before_deleting_data",
] as const;
export type DisclaimerCode = (typeof DISCLAIMER_CODES)[number];

export const PROCESSING_STATUSES = ["completed", "insufficient_data"] as const;
export type ProcessingStatus = (typeof PROCESSING_STATUSES)[number];

export const FEEDBACK_RATINGS = ["helpful", "not_helpful"] as const;
export const FEEDBACK_REASON_CODES = ["inaccurate", "unclear", "not_actionable", "too_generic", "wrong_language", "other"] as const;

/** Limits enforced by the schema. The request body limit is enforced by the gateway (see LIMITS.maxRequestBytes). */
export const LIMITS = {
  maxRequestBytes: 16_384,
  maxObservations: 40,
  maxLocalFindings: 20,
  maxEvidenceIdsPerFinding: 10,
  /** Observations older than this are stale; newer than now + clock skew are rejected as forged or misconfigured clocks. */
  observationMaxAgeHours: 168,
  clockSkewSeconds: 300,
  /** Consent older than this must be re-confirmed by the user. */
  consentMaxAgeDays: 395,
  maxResponseFindings: 8,
  maxRecommendedActions: 6,
  summaryMaxChars: 600,
  findingTitleMaxChars: 120,
  findingExplanationMaxChars: 600,
} as const;

/** Every `error` code a DevicePulse endpoint can return (including the gateway-wide ones). */
export const ERROR_CODES = [
  // gateway-wide (authentication, rate limit, parsing)
  "unauthorized", "forbidden", "auth_unavailable", "rate_limited", "payload_too_large", "bad_request", "not_found", "internal_error",
  // request validation
  "invalid_request", "unsupported_schema_version", "unsupported_diagnostic_type", "invalid_observation", "invalid_evidence_reference",
  "invalid_local_finding", "insufficient_evidence",
  // consent
  "consent_required", "consent_outdated", "consent_expired",
  // processing
  "remote_analysis_unavailable", "security_unavailable", "blocked_by_security_policy", "model_timeout", "model_unavailable",
  "model_response_invalid", "audit_unavailable",
  // feedback
  "unknown_request", "feedback_exists",
] as const;
export type ErrorCode = (typeof ERROR_CODES)[number];
