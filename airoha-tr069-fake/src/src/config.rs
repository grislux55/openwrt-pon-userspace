// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadMapping {
    #[serde(default)]
    pub pattern: String,
    #[serde(default)]
    pub file_type: String,
    #[serde(default)]
    pub target_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OmciExportData {
    pub line: String,
    pub management_vlan: Option<u16>,
    pub mac_address: String,
    pub ipv4_mode: String,
    pub ipv4_address: String,
    pub ipv4_mask: String,
    pub ipv4_gateway: String,
    pub ipv4_dns: String,
    pub ipv6_mode: String,
    pub ipv6_address: String,
    pub ipv6_gateway: String,
    pub ipv6_dns: String,
    pub acs_url: String,
    pub acs_username: String,
    pub acs_password: String,
}

#[derive(Clone, Debug)]
pub struct FakeConfig {
    pub enabled: bool,
    pub omci_sync: bool,
    pub pon_line: String,
    pub uplink: String,
    pub vlan_id: Option<u16>,
    pub tr069_ifname: String,
    pub macaddr: String,
    pub option60: String,
    pub ipv4_mode: String,
    pub ipv6_mode: String,
    pub acs_url: String,
    pub acs_username: String,
    pub acs_password: String,
    pub insecure_tls: bool,
    pub periodic_inform_enable: bool,
    pub periodic_inform_interval: u64,
    pub conn_req_enable: bool,
    pub conn_req_port: u16,
    pub conn_req_path: String,
    pub conn_req_username: String,
    pub conn_req_password: String,
    pub manufacturer: String,
    pub oui: String,
    pub product_class: String,
    pub serial_number: String,
    pub hardware_version: String,
    pub software_version: String,
    pub state_dir: String,
    pub audit_log_path: String,
    pub custom_params: BTreeMap<String, String>,
    pub download_mappings: Vec<DownloadMapping>,
    pub omci_snapshot_path: String,
}

impl Default for FakeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            omci_sync: false,
            pon_line: "line0".to_owned(),
            uplink: "pon0".to_owned(),
            vlan_id: None,
            tr069_ifname: "tr069-if".to_owned(),
            macaddr: String::new(),
            option60: String::new(),
            ipv4_mode: "dhcp".to_owned(),
            ipv6_mode: "dhcpv6".to_owned(),
            acs_url: "http://acs.example.invalid:9090/acs".to_owned(),
            acs_username: String::new(),
            acs_password: String::new(),
            insecure_tls: false,
            periodic_inform_enable: true,
            periodic_inform_interval: 43200,
            conn_req_enable: false,
            conn_req_port: 7547,
            conn_req_path: "/tr069".to_owned(),
            conn_req_username: String::new(),
            conn_req_password: String::new(),
            manufacturer: "NNRRWrt".to_owned(),
            oui: "000000".to_owned(),
            product_class: "XG-040G-MD".to_owned(),
            serial_number: "FAKE00000000".to_owned(),
            hardware_version: "AN7581-1.0".to_owned(),
            software_version: "NNRRWrt-1.0.0".to_owned(),
            state_dir: "/etc/tr069-fake".to_owned(),
            audit_log_path: "/tmp/tr069-fake.log".to_owned(),
            custom_params: BTreeMap::new(),
            download_mappings: Vec::new(),
            omci_snapshot_path: "/tmp/airoha-pond-tr069.line0.json".to_owned(),
        }
    }
}

impl FakeConfig {
    pub fn load_json_file(path: &Path) -> Result<Self, String> {
        let raw = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let val: JsonValue = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
        let mut cfg = Self::default();
        if let Some(b) = val.get("enabled").and_then(|v| v.as_bool()) {
            cfg.enabled = b;
        }
        if let Some(b) = val.get("omci_sync").and_then(|v| v.as_bool()) {
            cfg.omci_sync = b;
        }
        if let Some(s) = val.get("pon_line").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                if !is_valid_pon_line(s) {
                    return Err(format!("invalid pon_line '{s}'"));
                }
                cfg.pon_line = s.to_owned();
                cfg.omci_snapshot_path = format!("/tmp/airoha-pond-tr069.{}.json", cfg.pon_line);
            }
        }
        if let Some(s) = val.get("omci_snapshot_path").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                cfg.omci_snapshot_path = s.to_owned();
            }
        }
        if let Some(s) = val.get("uplink").and_then(|v| v.as_str()) {
            if !s.is_empty() {
                cfg.uplink = s.to_owned();
            }
        }
        if let Some(n) = val.get("vlan_id").and_then(|v| v.as_u64()) {
            if (1..=4094).contains(&n) {
                cfg.vlan_id = Some(n as u16);
            }
        }
        assign_str(&val, "tr069_ifname", &mut cfg.tr069_ifname);
        assign_str(&val, "macaddr", &mut cfg.macaddr);
        assign_str(&val, "option60", &mut cfg.option60);
        assign_str_nonempty(&val, "ipv4_mode", &mut cfg.ipv4_mode);
        assign_str_nonempty(&val, "ipv6_mode", &mut cfg.ipv6_mode);
        assign_str(&val, "acs_url", &mut cfg.acs_url);
        assign_str(&val, "acs_username", &mut cfg.acs_username);
        assign_str(&val, "acs_password", &mut cfg.acs_password);
        if let Some(b) = val.get("insecure_tls").and_then(|v| v.as_bool()) {
            cfg.insecure_tls = b;
        }
        if let Some(b) = val.get("periodic_inform_enable").and_then(|v| v.as_bool()) {
            cfg.periodic_inform_enable = b;
        }
        if let Some(n) = val.get("periodic_inform_interval").and_then(|v| v.as_u64()) {
            cfg.periodic_inform_interval = n.max(10);
        }
        if let Some(b) = val.get("conn_req_enable").and_then(|v| v.as_bool()) {
            cfg.conn_req_enable = b;
        }
        if let Some(n) = val.get("conn_req_port").and_then(|v| v.as_u64()) {
            if (1..=65535).contains(&n) {
                cfg.conn_req_port = n as u16;
            }
        }
        assign_str_nonempty(&val, "conn_req_path", &mut cfg.conn_req_path);
        assign_str(&val, "conn_req_username", &mut cfg.conn_req_username);
        assign_str(&val, "conn_req_password", &mut cfg.conn_req_password);
        assign_str_nonempty(&val, "manufacturer", &mut cfg.manufacturer);
        assign_str_nonempty(&val, "oui", &mut cfg.oui);
        assign_str_nonempty(&val, "product_class", &mut cfg.product_class);
        assign_str_nonempty(&val, "serial_number", &mut cfg.serial_number);
        assign_str_nonempty(&val, "hardware_version", &mut cfg.hardware_version);
        assign_str_nonempty(&val, "software_version", &mut cfg.software_version);
        assign_str_nonempty(&val, "state_dir", &mut cfg.state_dir);
        assign_str_nonempty(&val, "audit_log_path", &mut cfg.audit_log_path);

        if let Some(obj) = val.get("custom_params").and_then(|v| v.as_object()) {
            for (k, v) in obj {
                if let Some(s) = v.as_str() {
                    cfg.custom_params.insert(k.clone(), s.to_owned());
                }
            }
        }
        if let Some(arr) = val.get("download_mappings").and_then(|v| v.as_array()) {
            for item in arr {
                let pattern = item
                    .get("pattern")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let file_type = item
                    .get("file_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                let target_version = item
                    .get("target_version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned();
                if !pattern.is_empty() && !target_version.is_empty() {
                    cfg.download_mappings.push(DownloadMapping {
                        pattern,
                        file_type,
                        target_version,
                    });
                }
            }
        }
        if cfg.omci_sync {
            if let Ok(omci) = parse_omci_export_file(Path::new(&cfg.omci_snapshot_path)) {
                cfg.apply_omci_fallback(&omci);
            }
        }
        Ok(cfg)
    }

    /// Applies OMCI-exported parameters ONLY where manual config is empty/unset.
    pub fn apply_omci_fallback(&mut self, omci: &OmciExportData) {
        if self.vlan_id.is_none() {
            self.vlan_id = omci.management_vlan;
        }
        if self.macaddr.is_empty() && !omci.mac_address.is_empty() {
            self.macaddr = omci.mac_address.clone();
        }
        if (self.acs_url.is_empty() || self.acs_url == "http://acs.example.invalid:9090/acs")
            && !omci.acs_url.is_empty()
        {
            self.acs_url = omci.acs_url.clone();
        }
        if self.acs_username.is_empty() && !omci.acs_username.is_empty() {
            self.acs_username = omci.acs_username.clone();
        }
        if self.acs_password.is_empty() && !omci.acs_password.is_empty() {
            self.acs_password = omci.acs_password.clone();
        }
    }
}

pub fn parse_omci_export_file(path: &Path) -> Result<OmciExportData, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read OMCI snapshot {}: {e}", path.display()))?;
    parse_omci_export_json(&raw)
}

pub fn parse_omci_export_json(raw: &str) -> Result<OmciExportData, String> {
    let val: JsonValue = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    let line = val
        .get("line")
        .and_then(|v| v.as_str())
        .unwrap_or("line0")
        .to_owned();
    let management_vlan = val
        .get("management_vlan")
        .and_then(|v| v.as_u64())
        .and_then(|n| if (1..=4094).contains(&n) { Some(n as u16) } else { None });

    let mut out = OmciExportData {
        line,
        management_vlan,
        mac_address: String::new(),
        ipv4_mode: "none".to_owned(),
        ipv4_address: String::new(),
        ipv4_mask: String::new(),
        ipv4_gateway: String::new(),
        ipv4_dns: String::new(),
        ipv6_mode: "none".to_owned(),
        ipv6_address: String::new(),
        ipv6_gateway: String::new(),
        ipv6_dns: String::new(),
        acs_url: String::new(),
        acs_username: String::new(),
        acs_password: String::new(),
    };

    if let Some(v4) = val.get("ipv4_hosts").and_then(|v| v.as_array()).and_then(|a| a.first()) {
        if let Some(mac) = v4.get("mac_address").and_then(|v| v.as_str()) {
            if mac != "00:00:00:00:00:00" {
                out.mac_address = mac.to_owned();
            }
        }
        let ip_opts = v4.get("ip_options").and_then(|v| v.as_u64()).unwrap_or(0);
        out.ipv4_mode = if (ip_opts & 0x01) != 0 {
            "dhcp".to_owned()
        } else {
            "static".to_owned()
        };
        out.ipv4_address = str_field(v4, "ip_address");
        out.ipv4_mask = str_field(v4, "mask");
        out.ipv4_gateway = str_field(v4, "gateway");
        out.ipv4_dns = str_field(v4, "primary_dns");
    }

    if let Some(v6) = val.get("ipv6_hosts").and_then(|v| v.as_array()).and_then(|a| a.first()) {
        if out.mac_address.is_empty() {
            if let Some(mac) = v6.get("mac_address").and_then(|v| v.as_str()) {
                if mac != "00:00:00:00:00:00" {
                    out.mac_address = mac.to_owned();
                }
            }
        }
        let ip_opts = v6.get("ip_options").and_then(|v| v.as_u64()).unwrap_or(0);
        out.ipv6_mode = if (ip_opts & 0x01) != 0 {
            "dhcpv6".to_owned()
        } else if (ip_opts & 0x02) != 0 {
            "slaac".to_owned()
        } else {
            "static".to_owned()
        };
        out.ipv6_address = str_field(v6, "ipv6_address");
        out.ipv6_gateway = str_field(v6, "gateway");
        out.ipv6_dns = str_field(v6, "primary_dns");
    }

    if let Some(srv) = val
        .get("tr069_servers")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
    {
        out.acs_url = str_field(srv, "acs_url");
        out.acs_username = str_field(srv, "acs_username");
        out.acs_password = str_field(srv, "acs_password");
    }
    Ok(out)
}

fn str_field(val: &JsonValue, key: &str) -> String {
    val.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned()
}

fn assign_str(val: &JsonValue, key: &str, target: &mut String) {
    if let Some(s) = val.get(key).and_then(|v| v.as_str()) {
        *target = s.to_owned();
    }
}

fn assign_str_nonempty(val: &JsonValue, key: &str, target: &mut String) {
    if let Some(s) = val.get(key).and_then(|v| v.as_str()) {
        if !s.is_empty() {
            *target = s.to_owned();
        }
    }
}

pub fn is_valid_pon_line(line: &str) -> bool {
    !line.is_empty()
        && line
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
