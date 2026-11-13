// SPDX-License-Identifier: GPL-2.0-only

pub mod audit;
pub mod config;
pub mod crypto_tls;
pub mod cwmp;
pub mod http;
pub mod model;
pub mod net_iso;

use std::fs;
use std::io;
use std::path::Path;
use std::sync::{atomic::AtomicBool, Arc, Mutex};

use serde_json::{json, Map as JsonMap, Value as JsonValue};

use audit::AuditLogger;
use config::FakeConfig;
use cwmp::{build_fault, build_inform, build_transfer_complete, dispatch_rpc, parse_cwmp_envelope};
use http::{AcsHttpClient, ConnReqCreds};
pub use model::dump_sanitized_model_json;
use model::{CwmpFault, ManagementEffects, PendingEvent, VirtualModel};
use net_iso::InterfaceRuntime;

pub fn load_raw_cfg_and_model(config_path: &Path) -> Result<(FakeConfig, VirtualModel), String> {
    let cfg = if config_path.exists() {
        FakeConfig::load_json_file(config_path)?
    } else {
        FakeConfig::default()
    };
    let model = VirtualModel::load_or_init(&cfg)?;
    Ok((cfg, model))
}

pub fn load_effective_cfg_and_model(
    config_path: &Path,
) -> Result<(FakeConfig, VirtualModel), String> {
    let (mut cfg, model) = load_raw_cfg_and_model(config_path)?;
    apply_effects_to_config(&mut cfg, &model.current_management_effects(), None);
    Ok((cfg, model))
}

pub fn apply_overlay_from_config(config_path: &Path) -> Result<(FakeConfig, VirtualModel), String> {
    let (cfg, mut model) = load_raw_cfg_and_model(config_path)?;
    model.apply_config_overlay(&cfg)?;
    Ok((cfg, model))
}

fn redact_json_secrets(val: JsonValue) -> JsonValue {
    match val {
        JsonValue::Object(map) => {
            let mut out = JsonMap::new();
            for (k, v) in map {
                let lower = k.to_ascii_lowercase();
                let is_secret = lower.contains("password") || lower.contains("secret");
                let next_v = match v {
                    JsonValue::String(s) if is_secret => {
                        JsonValue::String(if s.is_empty() { String::new() } else { "***".to_owned() })
                    }
                    other => redact_json_secrets(other),
                };
                out.insert(k, next_v);
            }
            JsonValue::Object(out)
        }
        JsonValue::Array(arr) => JsonValue::Array(arr.into_iter().map(redact_json_secrets).collect()),
        other => other,
    }
}

fn is_valid_pon_line(line: &str) -> bool {
    !line.is_empty()
        && line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Builds a read-only `{"daemon":...,"omci":...,"pending":...}` JSON snapshot with OMCI
/// passwords redacted and zero filesystem writes.
pub fn dump_sanitized_status_json(
    config_path: &Path,
    pon_line_override: Option<&str>,
    daemon_status_raw: Option<&str>,
    omci_dir: &Path,
) -> String {
    let cfg = if config_path.exists() {
        FakeConfig::load_json_file(config_path).unwrap_or_default()
    } else {
        FakeConfig::default()
    };
    let daemon_val = daemon_status_raw
        .and_then(|s| serde_json::from_str::<JsonValue>(s).ok())
        .filter(|v| v.as_object().is_some())
        .map(redact_json_secrets)
        .unwrap_or_else(|| JsonValue::Object(JsonMap::new()));

    let chosen_line = pon_line_override
        .filter(|s| is_valid_pon_line(s))
        .or_else(|| {
            if is_valid_pon_line(&cfg.pon_line) {
                Some(cfg.pon_line.as_str())
            } else {
                None
            }
        })
        .unwrap_or("line0");
    let omci_path = omci_dir.join(format!("airoha-pond-tr069.{chosen_line}.json"));
    let omci_val = fs::read_to_string(&omci_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<JsonValue>(&raw).ok())
        .map(redact_json_secrets)
        .unwrap_or(JsonValue::Null);

    let pending_path = Path::new(&cfg.state_dir).join("pending_events.json");
    let pending_val = fs::read_to_string(&pending_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<JsonValue>(&raw).ok())
        .map(redact_json_secrets)
        .unwrap_or(JsonValue::Null);

    json!({
        "daemon": daemon_val,
        "omci": omci_val,
        "pending": pending_val,
    })
    .to_string()
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionSummary {
    pub rpcs_handled: usize,
    pub virtual_reboot_requested: bool,
    pub effects_applied: ManagementEffects,
}

pub fn apply_effects_to_config(
    cfg: &mut FakeConfig,
    eff: &ManagementEffects,
    conn_creds: Option<&Arc<Mutex<ConnReqCreds>>>,
) {
    if let Some(v) = &eff.acs_url {
        cfg.acs_url = v.clone();
    }
    if let Some(v) = &eff.acs_username {
        cfg.acs_username = v.clone();
    }
    if let Some(v) = &eff.acs_password {
        cfg.acs_password = v.clone();
    }
    if let Some(v) = eff.periodic_inform_enable {
        cfg.periodic_inform_enable = v;
    }
    if let Some(v) = eff.periodic_inform_interval {
        cfg.periodic_inform_interval = v;
    }
    if let Some(v) = &eff.conn_req_username {
        cfg.conn_req_username = v.clone();
    }
    if let Some(v) = &eff.conn_req_password {
        cfg.conn_req_password = v.clone();
    }
    if let Some(lock) = conn_creds {
        let mut g = lock.lock().expect("conn_creds mutex poisoned");
        g.username = cfg.conn_req_username.clone();
        g.password = cfg.conn_req_password.clone();
    }
}

pub fn run_cwmp_session(
    cfg: &mut FakeConfig,
    model: &mut VirtualModel,
    rt: &InterfaceRuntime,
    extra_event: Option<&str>,
    audit: &AuditLogger,
    conn_creds: Option<&Arc<Mutex<ConnReqCreds>>>,
) -> io::Result<SessionSummary> {
    if cfg.acs_url.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ACS URL is empty",
        ));
    }
    let mut client = AcsHttpClient::new(
        &cfg.acs_url,
        &cfg.acs_username,
        &cfg.acs_password,
        cfg.insecure_tls,
        rt.clone(),
    )?;

    let mut events = model.pending.events.clone();
    if let Some(ev) = extra_event {
        if !events.iter().any(|e| e.event_code == ev) {
            events.push(PendingEvent {
                event_code: ev.to_owned(),
                command_key: String::new(),
            });
        }
    }
    if events.is_empty() {
        events.push(PendingEvent {
            event_code: "2 PERIODIC".to_owned(),
            command_key: String::new(),
        });
    }

    let conn_req_url = if cfg.conn_req_enable {
        rt.conn_req_bind_addrs(cfg.conn_req_port)
            .first()
            .map(|sa| format!("http://{}{}", sa, cfg.conn_req_path))
            .unwrap_or_default()
    } else {
        String::new()
    };
    let runtime_conn_url = if !conn_req_url.is_empty() {
        Some(conn_req_url.as_str())
    } else if !cfg.conn_req_enable {
        Some("")
    } else {
        None
    };
    let _ = model.update_runtime_endpoints(runtime_conn_url, rt.ipv4_addrs.first().copied());

    let inform_xml = build_inform("1", model, &events, &conn_req_url, 0);
    audit.record(
        "INFO",
        "cwmp",
        &format!(
            "Sending Inform to {} events={:?}",
            cfg.acs_url,
            events.iter().map(|e| e.event_code.as_str()).collect::<Vec<_>>()
        ),
    );
    let resp = client.post_cwmp(&inform_xml, Some("urn:dslforum-org:cwmp-1-0#Inform"))?;
    if resp.status < 200 || resp.status >= 300 {
        return Err(io::Error::other(format!(
            "ACS rejected Inform with HTTP {}",
            resp.status
        )));
    }
    let _ = model.consume_pending_events();

    while let Some(tr) = model.pending.transfers.first().cloned() {
        let tc_xml = build_transfer_complete("tc-1", &tr);
        audit.record(
            "INFO",
            "cwmp",
            &format!("Sending TransferComplete command_key={}", tr.command_key),
        );
        let tc_resp = client.post_cwmp(&tc_xml, Some("urn:dslforum-org:cwmp-1-0#TransferComplete"))?;
        if tc_resp.status >= 200 && tc_resp.status < 300 {
            let _ = model.consume_pending_transfer();
        } else {
            break;
        }
    }

    let mut summary = SessionSummary::default();
    let mut next_body = String::new();
    for _ in 0..32 {
        let acs_resp = client.post_cwmp(&next_body, None)?;
        if acs_resp.status == 204
            || ((200..300).contains(&acs_resp.status) && acs_resp.body.is_empty())
        {
            break;
        }
        if acs_resp.status < 200 || acs_resp.status >= 300 {
            return Err(io::Error::other(format!(
                "ACS returned HTTP {} during CWMP session",
                acs_resp.status
            )));
        }
        let acs_xml = String::from_utf8_lossy(&acs_resp.body).to_string();
        audit.record("DEBUG", "cwmp_rx", &acs_xml);
        let env = match parse_cwmp_envelope(&acs_xml) {
            Ok(e) => e,
            Err(err) => {
                audit.record("WARN", "cwmp", &format!("Malformed ACS SOAP XML: {err}"));
                next_body = build_fault(None, &CwmpFault::simple(9003, err));
                continue;
            }
        };
        summary.rpcs_handled += 1;
        let (reply_opt, eff, reboot_req) = dispatch_rpc(&env, model, cfg);
        apply_effects_to_config(cfg, &eff, conn_creds);
        merge_effects(&mut summary.effects_applied, &eff);
        if reboot_req {
            summary.virtual_reboot_requested = true;
        }
        match reply_opt {
            Some(reply) => {
                audit.record("DEBUG", "cwmp_tx", &reply);
                next_body = reply;
            }
            None => break,
        }
    }
    Ok(summary)
}

fn merge_effects(dst: &mut ManagementEffects, src: &ManagementEffects) {
    if src.acs_url.is_some() {
        dst.acs_url = src.acs_url.clone();
    }
    if src.acs_username.is_some() {
        dst.acs_username = src.acs_username.clone();
    }
    if src.acs_password.is_some() {
        dst.acs_password = src.acs_password.clone();
    }
    if src.periodic_inform_enable.is_some() {
        dst.periodic_inform_enable = src.periodic_inform_enable;
    }
    if src.periodic_inform_interval.is_some() {
        dst.periodic_inform_interval = src.periodic_inform_interval;
    }
    if src.conn_req_username.is_some() {
        dst.conn_req_username = src.conn_req_username.clone();
    }
    if src.conn_req_password.is_some() {
        dst.conn_req_password = src.conn_req_password.clone();
    }
}

pub fn trigger_flag_new() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
