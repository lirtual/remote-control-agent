import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { checkSoakEvidence, FREE_LIMITS } from "../scripts/check-v2-soak-evidence.mjs";

const start = Date.parse("2026-10-16T13:00:00.000Z");
function syntheticFixture() {
  const devices = [randomUUID()];
  const date = offset => new Date(start + offset).toISOString();
  return {
    environment:"nonproduction",
    start_utc:date(0),
    end_utc:date(48*3600_000),
    device_ids: devices,
    hourly_samples: Array.from({length:49},(_,i)=>({
      at_utc:date(i*3600_000),online_device_ids:[...devices],
    })),
    // A 48-hour UTC window spanning parts of three calendar days needs
    // three separate account-wide daily totals, not an average.
    daily_account_usage: Array.from({length:3},(_,i)=>({
      date_utc:new Date(Date.UTC(2026,9,16+i)).toISOString().slice(0,10),
      source_ref:"nonprod-account-dashboard-" + i,
      includes_other_durable_objects:true,
      workers_requests:200,
      do_requests:400,
      do_gb_seconds:8,
      sqlite_rows_read:500,
      sqlite_rows_written:25,
      sqlite_storage_bytes:50_000,
    })),
    evidence_refs:{
      human_confirmation:"operator-evidence",
      do_hibernation:"cloudflare-analytics-and-wake-evidence",
      idle_duration_comparison:"billed-duration-comparison",
      reconnect_epoch:"reconnect-transcripts",
      offline_denial:"offline-request-results",
      revocation:"revoke-tombstone-fixture",
      unknown_receipt:"receipt-recovery-fixture",
      v1_isolation:"pre-and-post-v1-health",
    },
  };
}
test("synthetic full 48h/single-device/account-wide 3 UTC date coverage is complete but not proof", () => {
  const res=checkSoakEvidence(syntheticFixture());
  assert.equal(res.ready_for_manual_review,true);
  assert.deepEqual(res.findings,[]);
  assert.match(res.disclaimer,/no proof/);
});
test("missing 1h sample, bad device coverage and shortened window cannot pass",()=>{
  const report=syntheticFixture();
  report.hourly_samples.splice(18,1);
  assert.ok(checkSoakEvidence(report).findings.includes("hourly_samples_incomplete"));
  const report2=syntheticFixture();
  report2.hourly_samples[4].online_device_ids=[randomUUID()];
  assert.ok(checkSoakEvidence(report2).findings.includes("hourly_samples_incomplete"));
  const report3=syntheticFixture();
  report3.end_utc="2026-10-18T12:00:00.000Z";
  assert.ok(checkSoakEvidence(report3).findings.includes("invalid_48h_window"));
  const report4=syntheticFixture();
  report4.device_ids.push(randomUUID());
  assert.ok(checkSoakEvidence(report4).findings.includes("one_device_id_required"));
});
test("a recorded intermediate offline snapshot is allowed but startup and end must be online",()=>{
  const report=syntheticFixture();
  report.hourly_samples[18].online_device_ids=[];
  assert.equal(checkSoakEvidence(report).ready_for_manual_review,true);
  report.hourly_samples[0].online_device_ids=[];
  assert.ok(checkSoakEvidence(report).findings.includes("hourly_samples_incomplete"));
});
test("account-wide missing IMA/other DO inclusion and UTC partial days fail",()=>{
  const report=syntheticFixture();
  report.daily_account_usage.pop();
  assert.ok(checkSoakEvidence(report).findings.includes("utc_account_daily_coverage_missing"));
  const report2=syntheticFixture();
  report2.daily_account_usage[0].includes_other_durable_objects=false;
  assert.ok(checkSoakEvidence(report2).findings.includes("utc_account_daily_coverage_missing"));
});
test("daily Free plan headroom is evaluated across shared account metrics",()=>{
  for(const [key,limit] of Object.entries(FREE_LIMITS)){
    const report=syntheticFixture();
    report.daily_account_usage[0][key]=limit*0.8;
    assert.ok(checkSoakEvidence(report).findings.includes("account_quota_headroom_low_"+key),key);
  }
  const report=syntheticFixture();
  report.daily_account_usage[1].sqlite_rows_read=-1;
  assert.ok(checkSoakEvidence(report).findings.includes("account_metric_incomplete_sqlite_rows_read"));
});
test("missing independent human/hibernation/receipt/v1 evidence never becomes an automatic gate PASS",()=>{
  for(const key of Object.keys(syntheticFixture().evidence_refs)){
    const report=syntheticFixture();
    delete report.evidence_refs[key];
    assert.ok(checkSoakEvidence(report).findings.includes("evidence_missing_"+key),key);
  }
  assert.equal(checkSoakEvidence(null).ready_for_manual_review,false);
});
