/**
 * T11 / #57: offline completeness guard for operator-supplied 48h single-device
 * nonproduction evidence. This NEVER accesses Cloudflare or devices and
 * NEVER certifies that a Durable Object actually hibernated.
 */
import { readFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const FREE_LIMITS = Object.freeze({
  workers_requests: 100_000,
  do_requests: 100_000,
  do_gb_seconds: 13_000,
  sqlite_rows_read: 5_000_000,
  sqlite_rows_written: 100_000,
  sqlite_storage_bytes: 5_000_000_000,
});
const MIN_DURATION_MS = 48 * 60 * 60 * 1000;
const MAX_SAMPLE_GAP_MS = 60 * 60 * 1000;
const MAX_USAGE_RATIO = 0.8;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const UTC = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/;
const DAY = /^\d{4}-\d\d-\d\d$/;
const EVIDENCE_KEYS = [
  "human_confirmation", "do_hibernation", "idle_duration_comparison",
  "reconnect_epoch", "offline_denial", "revocation", "unknown_receipt",
  "v1_isolation",
];

function time(value) {
  if (typeof value !== "string" || !UTC.test(value)) return NaN;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19)
    ? parsed : NaN;
}

function dateKeys(start, end) {
  const keys = [];
  const first = Math.floor(start / 86_400_000) * 86_400_000;
  for (let moment = first; moment < end; moment += 86_400_000) {
    keys.push(new Date(moment).toISOString().slice(0, 10));
    if (keys.length > 31) return [];
  }
  return keys;
}

/**
 * Only structural completeness and conservative budget risk are machine-checked.
 * Reported observations MUST be independently reviewed against official
 * Cloudflare analytics, actual socket events, and human client evidence.
 */
export function checkSoakEvidence(report) {
  const findings = [];
  const note = key => findings.push(key);
  if (!report || typeof report !== "object" || Array.isArray(report)) {
    return { ready_for_manual_review: false, findings: ["invalid_report"] };
  }
  if (report.environment !== "nonproduction") note("nonproduction_required");
  const start = time(report.start_utc), end = time(report.end_utc);
  if (!Number.isFinite(start) || !Number.isFinite(end) ||
      end - start < MIN_DURATION_MS || end - start > 31 * 86_400_000) {
    note("invalid_48h_window");
  }
  const devices = report.device_ids;
  const idSet = new Set(Array.isArray(devices) ? devices : []);
  if (!Array.isArray(devices) || devices.length !== 1 || idSet.size !== 1 ||
      !devices.every(id => typeof id === "string" && UUID.test(id))) {
    note("one_device_id_required");
  }

  const samples = report.hourly_samples;
  if (!Array.isArray(samples) || !Number.isFinite(start) || !Number.isFinite(end) ||
      samples.length < 49 || samples.length > 800) {
    note("hourly_samples_incomplete");
  } else {
    let previous = NaN;
    for (let index = 0; index < samples.length; index++) {
      const sample = samples[index];
      const at = time(sample?.at_utc);
      const online = sample?.online_device_ids;
      if (!Number.isFinite(at) ||
          at < start || at > end || (index === 0 && at !== start) ||
          (index === samples.length - 1 && at !== end) ||
          (index > 0 && (at <= previous || at - previous > MAX_SAMPLE_GAP_MS)) ||
          !Array.isArray(online) || online.length > 1 ||
          new Set(online).size !== online.length ||
          !online.every(id => idSet.has(id)) ||
          ((index === 0 || index === samples.length - 1) &&
            (online.length !== 1 || online[0] !== devices[0]))) {
        note("hourly_samples_incomplete");
        break;
      }
      previous = at;
    }
  }
  const dates = Number.isFinite(start) && Number.isFinite(end) && end > start
    ? dateKeys(start, end) : [];
  const daily = report.daily_account_usage;
  if (!Array.isArray(daily) || daily.length !== dates.length || !dates.length) {
    note("utc_account_daily_coverage_missing");
  } else {
    const seen = new Set();
    for (const item of daily) {
      if (!item || typeof item !== "object" || !DAY.test(item.date_utc ?? "") ||
          seen.has(item.date_utc) || !dates.includes(item.date_utc) ||
          item.includes_other_durable_objects !== true ||
          typeof item.source_ref !== "string" || item.source_ref.trim().length < 5) {
        note("utc_account_daily_coverage_missing");
        break;
      }
      seen.add(item.date_utc);
      for (const [key, limit] of Object.entries(FREE_LIMITS)) {
        const value = item[key];
        if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
          note("account_metric_incomplete_" + key);
        } else if (value >= limit * MAX_USAGE_RATIO) {
          note("account_quota_headroom_low_" + key);
        }
      }
      if (item.workers_requests === 0 || item.do_requests === 0) {
        note("no_recorded_nonproduction_traffic");
      }
    }
    if (seen.size !== dates.length) note("utc_account_daily_coverage_missing");
  }
  const evidence = report.evidence_refs;
  if (!evidence || typeof evidence !== "object" || Array.isArray(evidence)) {
    note("manual_evidence_refs_missing");
  } else {
    for (const key of EVIDENCE_KEYS) {
      const ref = evidence[key];
      if (typeof ref !== "string" || ref.trim().length < 5) note("evidence_missing_" + key);
    }
  }
  const unique = [...new Set(findings)];
  return {
    ready_for_manual_review: unique.length === 0,
    findings: unique,
    // Intentionally NOT "passed"; numbers and links can be fabricated, and
    // an hourly snapshot cannot prove continuous connection or true sleep.
    disclaimer: "Completeness only: no proof of 48h continuous connectivity, DO hibernation, owner consent, or production readiness.",
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const location = process.argv[2];
  if (!location || process.argv.length !== 3) {
    process.stderr.write("Usage: node scripts/check-v2-soak-evidence.mjs <local-evidence.json>\n");
    process.exitCode = 2;
  } else {
    try {
      const meta = await stat(location);
      if (!meta.isFile() || meta.size > 128_000) throw new Error("invalid evidence file");
      const report = JSON.parse(await readFile(location, "utf8"));
      const result = checkSoakEvidence(report);
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
      if (!result.ready_for_manual_review) process.exitCode = 1;
    } catch {
      // Never echo input contents or exceptions containing local paths/secrets.
      process.stderr.write("Evidence is unavailable or invalid; nothing was submitted.\n");
      process.exitCode = 2;
    }
  }
}
