// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;

use crate::config::{DownloadMapping, FakeConfig};

fn default_ptype() -> String {
    "xsd:string".to_owned()
}

const fn default_true() -> bool {
    true
}

fn default_access_list() -> Vec<String> {
    vec!["Subscriber".to_owned()]
}

const fn default_boot_epoch() -> u64 {
    1
}

fn deserialize_notification<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = i64::deserialize(deserializer)?;
    Ok(raw.clamp(0, 2) as u8)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamEntry {
    #[serde(default)]
    pub value: String,
    #[serde(rename = "type", default = "default_ptype")]
    pub ptype: String,
    #[serde(default = "default_true")]
    pub writable: bool,
    #[serde(default, deserialize_with = "deserialize_notification")]
    pub notification: u8,
    #[serde(default = "default_access_list")]
    pub access_list: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CwmpFault {
    pub code: u32,
    pub message: String,
    pub param_faults: Vec<(String, u32, String)>,
}

impl CwmpFault {
    pub fn simple(code: u32, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            param_faults: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingEvent {
    #[serde(default)]
    pub event_code: String,
    #[serde(default)]
    pub command_key: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTransfer {
    #[serde(default)]
    pub command_key: String,
    #[serde(default)]
    pub fault_code: u32,
    #[serde(default)]
    pub fault_string: String,
    #[serde(default)]
    pub start_time: String,
    #[serde(default)]
    pub complete_time: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingState {
    #[serde(default)]
    pub events: Vec<PendingEvent>,
    #[serde(default)]
    pub transfers: Vec<PendingTransfer>,
    #[serde(default = "default_boot_epoch")]
    pub virtual_boot_epoch: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ManagementEffects {
    pub acs_url: Option<String>,
    pub acs_username: Option<String>,
    pub acs_password: Option<String>,
    pub periodic_inform_enable: Option<bool>,
    pub periodic_inform_interval: Option<u64>,
    pub conn_req_username: Option<String>,
    pub conn_req_password: Option<String>,
}

#[derive(Clone, Debug)]
pub struct VirtualModel {
    pub template_path: PathBuf,
    pub model_path: PathBuf,
    pub events_path: PathBuf,
    pub template: BTreeMap<String, ParamEntry>,
    pub params: BTreeMap<String, ParamEntry>,
    pub objects: BTreeSet<String>,
    pub pending: PendingState,
}

impl VirtualModel {
    pub fn load_or_init(cfg: &FakeConfig) -> Result<Self, String> {
        let dir = PathBuf::from(&cfg.state_dir);
        fs::create_dir_all(&dir)
            .map_err(|e| format!("failed to create state dir {}: {e}", dir.display()))?;

        let template_path = dir.join("template.json");
        let model_path = dir.join("model.json");
        let events_path = dir.join("pending_events.json");

        let template = build_initial_template(cfg);
        let (mut params, mut objects) = if model_path.exists() {
            load_model_file(&model_path)?
        } else {
            let objs = derive_objects(&template);
            (template.clone(), objs)
        };

        for (k, v) in &cfg.custom_params {
            params.entry(k.clone()).or_insert_with(|| ParamEntry {
                value: v.clone(),
                ptype: "xsd:string".to_owned(),
                writable: true,
                notification: 0,
                access_list: vec!["Subscriber".to_owned()],
            });
            add_ancestor_objects(&mut objects, k);
        }
        objects.extend(derive_objects(&params));
        objects.insert("InternetGatewayDevice.".to_owned());
        objects.insert("InternetGatewayDevice.WANDevice.".to_owned());
        objects.insert("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.".to_owned());
        objects.insert("Device.".to_owned());

        let mut pending = if events_path.exists() {
            load_pending_file(&events_path)?
        } else {
            PendingState {
                events: vec![PendingEvent {
                    event_code: "0 BOOTSTRAP".to_owned(),
                    command_key: String::new(),
                }],
                transfers: Vec::new(),
                virtual_boot_epoch: 1,
            }
        };
        if pending.events.is_empty() && !model_path.exists() {
            pending.events.push(PendingEvent {
                event_code: "0 BOOTSTRAP".to_owned(),
                command_key: String::new(),
            });
        }

        let vm = Self {
            template_path,
            model_path,
            events_path,
            template,
            params,
            objects,
            pending,
        };
        vm.save_template()?;
        if !vm.model_path.exists() {
            vm.save_model()?;
        }
        if !vm.events_path.exists() {
            vm.save_pending()?;
        }
        Ok(vm)
    }

    /// Updates template & applies explicit LuCI/config overlay into active model (last-write-wins).
    pub fn apply_config_overlay(&mut self, cfg: &FakeConfig) -> Result<(), String> {
        let fresh = build_initial_template(cfg);
        self.template = fresh.clone();
        self.save_template()?;
        let overlay_keys = [
            "InternetGatewayDevice.DeviceInfo.Manufacturer",
            "InternetGatewayDevice.DeviceInfo.ManufacturerOUI",
            "InternetGatewayDevice.DeviceInfo.ProductClass",
            "InternetGatewayDevice.DeviceInfo.SerialNumber",
            "InternetGatewayDevice.DeviceInfo.HardwareVersion",
            "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
            "InternetGatewayDevice.ManagementServer.URL",
            "InternetGatewayDevice.ManagementServer.Username",
            "InternetGatewayDevice.ManagementServer.Password",
            "InternetGatewayDevice.ManagementServer.PeriodicInformEnable",
            "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
            "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername",
            "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword",
            "Device.DeviceInfo.Manufacturer",
            "Device.DeviceInfo.ManufacturerOUI",
            "Device.DeviceInfo.ProductClass",
            "Device.DeviceInfo.SerialNumber",
            "Device.DeviceInfo.HardwareVersion",
            "Device.DeviceInfo.SoftwareVersion",
            "Device.ManagementServer.URL",
            "Device.ManagementServer.Username",
            "Device.ManagementServer.Password",
            "Device.ManagementServer.PeriodicInformEnable",
            "Device.ManagementServer.PeriodicInformInterval",
            "Device.ManagementServer.ConnectionRequestUsername",
            "Device.ManagementServer.ConnectionRequestPassword",
        ];
        let mut new_sig_map = BTreeMap::new();
        for key in overlay_keys {
            if let Some(entry) = fresh.get(key) {
                new_sig_map.insert(key.to_owned(), entry.value.clone());
            }
        }
        for (k, v) in &cfg.custom_params {
            new_sig_map.insert(format!("custom:{k}"), v.clone());
        }
        let sig_path = self
            .model_path
            .parent()
            .map(|p| p.join("overlay.sig.json"))
            .unwrap_or_else(|| PathBuf::from("/tmp/overlay.sig.json"));
        let prev_sig_map = load_overlay_sig(&sig_path);
        if let Some(prev) = &prev_sig_map {
            if prev == &new_sig_map && self.model_path.exists() {
                return Ok(());
            }
        }
        for key in overlay_keys {
            if let Some(entry) = fresh.get(key) {
                let should_apply = match &prev_sig_map {
                    Some(prev) => prev.get(key) != Some(&entry.value) || !self.params.contains_key(key),
                    None => !self.model_path.exists() || self.params.get(key).map(|e| e.value.is_empty()).unwrap_or(true),
                };
                if should_apply {
                    self.params.insert(key.to_owned(), entry.clone());
                }
            }
        }
        for (k, v) in &cfg.custom_params {
            let custom_key = format!("custom:{k}");
            let should_apply = match &prev_sig_map {
                Some(prev) => prev.get(&custom_key) != Some(v) || !self.params.contains_key(k),
                None => true,
            };
            if should_apply {
                self.params.insert(
                    k.clone(),
                    ParamEntry {
                        value: v.clone(),
                        ptype: "xsd:string".to_owned(),
                        writable: true,
                        notification: 0,
                        access_list: vec!["Subscriber".to_owned()],
                    },
                );
                add_ancestor_objects(&mut self.objects, k);
            }
        }
        self.save_model()?;
        save_overlay_sig(&sig_path, &new_sig_map)
    }

    pub fn current_management_effects(&self) -> ManagementEffects {
        let mut eff = ManagementEffects::default();
        for (key, entry) in &self.params {
            if key.starts_with("InternetGatewayDevice.ManagementServer.") {
                mirror_mgmt_side_effect(key, &entry.value, &mut eff);
            }
        }
        eff
    }

    pub fn reset_virtual(&mut self) -> Result<(), String> {
        self.params = self.template.clone();
        self.objects = derive_objects(&self.params);
        self.objects.insert("InternetGatewayDevice.".to_owned());
        self.objects.insert("InternetGatewayDevice.WANDevice.".to_owned());
        self.objects
            .insert("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.".to_owned());
        self.objects.insert("Device.".to_owned());
        self.pending = PendingState {
            events: vec![PendingEvent {
                event_code: "0 BOOTSTRAP".to_owned(),
                command_key: String::new(),
            }],
            transfers: Vec::new(),
            virtual_boot_epoch: self.pending.virtual_boot_epoch + 1,
        };
        self.save_model()?;
        self.save_pending()?;
        Ok(())
    }

    pub fn set_single_from_ui(&mut self, path: &str, value: &str) -> Result<(), String> {
        let pairs = vec![(path.to_owned(), value.to_owned(), None)];
        self.set_parameter_values(&pairs, "luci-ui")
            .map(|_| ())
            .map_err(|f| format!("CWMP {}: {}", f.code, f.message))
    }

    pub fn get_value(&self, path: &str) -> Option<&str> {
        self.params.get(path).map(|e| e.value.as_str())
    }

    /// Updates read-only runtime endpoint fields derived from the isolated interface without
    /// triggering CWMP Fault 9008, persisting `model.json` only when a value actually changes.
    pub fn update_runtime_endpoints(
        &mut self,
        conn_req_url: Option<&str>,
        ipv4: Option<std::net::Ipv4Addr>,
    ) -> Result<(), String> {
        let mut changed = false;
        if let Some(url) = conn_req_url {
            for key in [
                "InternetGatewayDevice.ManagementServer.ConnectionRequestURL",
                "Device.ManagementServer.ConnectionRequestURL",
            ] {
                if let Some(entry) = self.params.get_mut(key) {
                    if entry.value != url {
                        entry.value = url.to_owned();
                        changed = true;
                    }
                }
            }
        }
        if let Some(ip) = ipv4 {
            let ip_str = ip.to_string();
            if let Some(entry) = self.params.get_mut(
                "InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress",
            ) {
                if entry.value != ip_str {
                    entry.value = ip_str;
                    changed = true;
                }
            }
        }
        if changed {
            self.save_model()?;
        }
        Ok(())
    }

    pub fn get_parameter_values(&self, names: &[String]) -> Result<Vec<(String, String, String)>, CwmpFault> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        for query in names {
            let q = if query.is_empty() {
                "InternetGatewayDevice."
            } else {
                query.as_str()
            };
            if q.ends_with('.') {
                let mut matched = false;
                for (k, v) in &self.params {
                    if k.starts_with(q) {
                        matched = true;
                        if seen.insert(k.clone()) {
                            out.push((k.clone(), v.value.clone(), v.ptype.clone()));
                        }
                    }
                }
                if !matched && !self.objects.contains(q) {
                    return Err(CwmpFault::simple(9005, format!("Invalid parameter name: {query}")));
                }
            } else if let Some(v) = self.params.get(q) {
                if seen.insert(q.to_owned()) {
                    out.push((q.to_owned(), v.value.clone(), v.ptype.clone()));
                }
            } else {
                return Err(CwmpFault::simple(9005, format!("Invalid parameter name: {query}")));
            }
        }
        Ok(out)
    }

    pub fn get_parameter_names(
        &self,
        path: &str,
        next_level: bool,
    ) -> Result<Vec<(String, bool)>, CwmpFault> {
        let prefix = if path.is_empty() { "" } else { path };
        if !prefix.is_empty() && !prefix.ends_with('.') {
            return if let Some(entry) = self.params.get(prefix) {
                Ok(vec![(prefix.to_owned(), entry.writable)])
            } else {
                Err(CwmpFault::simple(9005, format!("Invalid parameter name: {path}")))
            };
        }
        if !prefix.is_empty() && !self.objects.contains(prefix) && !self.params.keys().any(|k| k.starts_with(prefix)) {
            return Err(CwmpFault::simple(9005, format!("Invalid parameter path: {path}")));
        }
        let mut entries: BTreeMap<String, bool> = BTreeMap::new();
        for obj in &self.objects {
            if obj.starts_with(prefix) && obj != prefix {
                if next_level {
                    let tail = &obj[prefix.len()..];
                    if let Some(dot_pos) = tail.find('.') {
                        if dot_pos + 1 == tail.len() {
                            entries.insert(obj.clone(), true);
                        }
                    }
                } else {
                    entries.insert(obj.clone(), true);
                }
            }
        }
        for (k, v) in &self.params {
            if k.starts_with(prefix) {
                if next_level {
                    let tail = &k[prefix.len()..];
                    if !tail.contains('.') {
                        entries.insert(k.clone(), v.writable);
                    }
                } else {
                    entries.insert(k.clone(), v.writable);
                }
            }
        }
        Ok(entries.into_iter().collect())
    }

    pub fn set_parameter_values(
        &mut self,
        pairs: &[(String, String, Option<String>)],
        parameter_key: &str,
    ) -> Result<ManagementEffects, CwmpFault> {
        let mut param_faults = Vec::new();
        for (name, val, declared_type) in pairs {
            let Some(entry) = self.params.get(name) else {
                param_faults.push((name.clone(), 9005, "Invalid parameter name".to_owned()));
                continue;
            };
            if !entry.writable {
                param_faults.push((name.clone(), 9008, "Attempt to set a non-writable parameter".to_owned()));
                continue;
            }
            if let Some(dt) = declared_type {
                if !dt.is_empty() && dt != &entry.ptype && !(dt == "xsd:int" && entry.ptype == "xsd:unsignedInt") {
                    param_faults.push((name.clone(), 9006, "Invalid parameter type".to_owned()));
                    continue;
                }
            }
            if !validate_type_value(&entry.ptype, val) {
                param_faults.push((name.clone(), 9007, format!("Invalid value for {}", entry.ptype)));
                continue;
            }
        }
        if !param_faults.is_empty() {
            return Err(CwmpFault {
                code: 9003,
                message: "Invalid arguments".to_owned(),
                param_faults,
            });
        }
        let mut effects = ManagementEffects::default();
        for (name, val, _) in pairs {
            let normalized = normalize_value(
                self.params.get(name).map(|e| e.ptype.as_str()).unwrap_or("xsd:string"),
                val,
            );
            if let Some(entry) = self.params.get_mut(name) {
                entry.value = normalized.clone();
            }
            mirror_mgmt_side_effect(name, &normalized, &mut effects);
            mirror_tr098_tr181(&mut self.params, name, &normalized);
        }
        if let Some(pk) = self.params.get_mut("InternetGatewayDevice.ManagementServer.ParameterKey") {
            pk.value = parameter_key.to_owned();
        }
        if let Some(pk) = self.params.get_mut("Device.ManagementServer.ParameterKey") {
            pk.value = parameter_key.to_owned();
        }
        self.save_model()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))?;
        Ok(effects)
    }

    pub fn get_parameter_attributes(&self, names: &[String]) -> Result<Vec<(String, u8, Vec<String>)>, CwmpFault> {
        let mut out = Vec::new();
        for query in names {
            if query.ends_with('.') {
                let mut matched = false;
                for (k, v) in &self.params {
                    if k.starts_with(query) {
                        matched = true;
                        out.push((k.clone(), v.notification, v.access_list.clone()));
                    }
                }
                if !matched {
                    return Err(CwmpFault::simple(9005, format!("Invalid parameter name: {query}")));
                }
            } else if let Some(v) = self.params.get(query) {
                out.push((query.clone(), v.notification, v.access_list.clone()));
            } else {
                return Err(CwmpFault::simple(9005, format!("Invalid parameter name: {query}")));
            }
        }
        Ok(out)
    }

    pub fn set_parameter_attributes(
        &mut self,
        items: &[(String, Option<u8>, Option<Vec<String>>)],
    ) -> Result<(), CwmpFault> {
        for (name, notif, _) in items {
            if let Some(n) = notif {
                if *n > 2 {
                    return Err(CwmpFault::simple(9003, "Invalid notification value"));
                }
            }
            if name.ends_with('.') {
                if !self.params.keys().any(|k| k.starts_with(name)) {
                    return Err(CwmpFault::simple(9005, format!("Invalid parameter name: {name}")));
                }
            } else if !self.params.contains_key(name) {
                return Err(CwmpFault::simple(9005, format!("Invalid parameter name: {name}")));
            }
        }
        for (name, notif, acl) in items {
            for (k, entry) in &mut self.params {
                let hits = if name.ends_with('.') {
                    k.starts_with(name)
                } else {
                    k == name
                };
                if hits {
                    if let Some(n) = notif {
                        entry.notification = *n;
                    }
                    if let Some(a) = acl {
                        entry.access_list = a.clone();
                    }
                }
            }
        }
        self.save_model()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))?;
        Ok(())
    }

    pub fn add_object(&mut self, object_name: &str, parameter_key: &str) -> Result<u32, CwmpFault> {
        if !object_name.ends_with('.') {
            return Err(CwmpFault::simple(9003, "AddObject path must end with '.'"));
        }
        if !self.objects.contains(object_name) {
            return Err(CwmpFault::simple(9005, format!("Invalid object path: {object_name}")));
        }
        let mut max_inst = 0u32;
        for obj in &self.objects {
            if let Some(rest) = obj.strip_prefix(object_name) {
                if let Some(head) = rest.split('.').next() {
                    if let Ok(n) = head.parse::<u32>() {
                        max_inst = max_inst.max(n);
                    }
                }
            }
        }
        for k in self.params.keys() {
            if let Some(rest) = k.strip_prefix(object_name) {
                if let Some(head) = rest.split('.').next() {
                    if let Ok(n) = head.parse::<u32>() {
                        max_inst = max_inst.max(n);
                    }
                }
            }
        }
        let new_id = max_inst + 1;
        let prefix = format!("{object_name}{new_id}.");
        self.objects.insert(prefix.clone());
        self.params.insert(
            format!("{prefix}Enable"),
            ParamEntry {
                value: "true".to_owned(),
                ptype: "xsd:boolean".to_owned(),
                writable: true,
                notification: 0,
                access_list: vec!["Subscriber".to_owned()],
            },
        );
        self.params.insert(
            format!("{prefix}Name"),
            ParamEntry {
                value: format!("instance_{new_id}"),
                ptype: "xsd:string".to_owned(),
                writable: true,
                notification: 0,
                access_list: vec!["Subscriber".to_owned()],
            },
        );
        if let Some(pk) = self.params.get_mut("InternetGatewayDevice.ManagementServer.ParameterKey") {
            pk.value = parameter_key.to_owned();
        }
        if let Some(pk) = self.params.get_mut("Device.ManagementServer.ParameterKey") {
            pk.value = parameter_key.to_owned();
        }
        self.save_model()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))?;
        Ok(new_id)
    }

    pub fn delete_object(&mut self, object_name: &str, parameter_key: &str) -> Result<(), CwmpFault> {
        if !object_name.ends_with('.') {
            return Err(CwmpFault::simple(9003, "DeleteObject path must end with '.'"));
        }
        let has_obj = self.objects.contains(object_name)
            || self.params.keys().any(|k| k.starts_with(object_name));
        if !has_obj {
            return Err(CwmpFault::simple(9005, format!("Invalid object path: {object_name}")));
        }
        // Protect core root objects from accidental deletion
        if matches!(
            object_name,
            "InternetGatewayDevice."
                | "InternetGatewayDevice.DeviceInfo."
                | "InternetGatewayDevice.ManagementServer."
                | "Device."
                | "Device.DeviceInfo."
                | "Device.ManagementServer."
        ) {
            return Err(CwmpFault::simple(9003, "Protected object cannot be deleted"));
        }
        self.objects.retain(|o| !o.starts_with(object_name));
        self.params.retain(|k, _| !k.starts_with(object_name));
        if let Some(pk) = self.params.get_mut("InternetGatewayDevice.ManagementServer.ParameterKey") {
            pk.value = parameter_key.to_owned();
        }
        if let Some(pk) = self.params.get_mut("Device.ManagementServer.ParameterKey") {
            pk.value = parameter_key.to_owned();
        }
        self.save_model()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))?;
        Ok(())
    }

    pub fn handle_reboot(&mut self, command_key: &str) -> Result<(), CwmpFault> {
        self.pending.virtual_boot_epoch += 1;
        self.pending.events.push(PendingEvent {
            event_code: "M Reboot".to_owned(),
            command_key: command_key.to_owned(),
        });
        self.pending.events.push(PendingEvent {
            event_code: "1 BOOT".to_owned(),
            command_key: String::new(),
        });
        self.save_pending()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))
    }

    pub fn handle_factory_reset(&mut self) -> Result<(), CwmpFault> {
        self.reset_virtual()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))
    }

    pub fn handle_download(
        &mut self,
        command_key: &str,
        file_type: &str,
        url: &str,
        mappings: &[DownloadMapping],
    ) -> Result<PendingTransfer, CwmpFault> {
        let matched = mappings.iter().find(|m| {
            let url_ok = url.contains(&m.pattern);
            let type_ok = m.file_type.is_empty() || m.file_type == file_type;
            url_ok && type_ok
        });
        let Some(mapping) = matched else {
            return Err(CwmpFault::simple(
                9010,
                format!("Download rejected: no virtual firmware mapping matches url={url}"),
            ));
        };
        let ts = iso8601_now();
        for key in [
            "InternetGatewayDevice.DeviceInfo.SoftwareVersion",
            "Device.DeviceInfo.SoftwareVersion",
        ] {
            if let Some(entry) = self.params.get_mut(key) {
                entry.value = mapping.target_version.clone();
            }
        }
        self.save_model()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))?;

        let transfer = PendingTransfer {
            command_key: command_key.to_owned(),
            fault_code: 0,
            fault_string: String::new(),
            start_time: ts.clone(),
            complete_time: ts,
        };
        self.pending.transfers.push(transfer.clone());
        self.pending.events.push(PendingEvent {
            event_code: "7 TRANSFER COMPLETE".to_owned(),
            command_key: String::new(),
        });
        self.pending.events.push(PendingEvent {
            event_code: "M Download".to_owned(),
            command_key: command_key.to_owned(),
        });
        self.save_pending()
            .map_err(|e| CwmpFault::simple(9002, format!("Internal error: {e}")))?;
        Ok(transfer)
    }

    pub fn consume_pending_events(&mut self) -> Result<(), String> {
        self.pending.events.clear();
        self.save_pending()
    }

    pub fn consume_pending_transfer(&mut self) -> Result<(), String> {
        if !self.pending.transfers.is_empty() {
            self.pending.transfers.remove(0);
            self.save_pending()?;
        }
        Ok(())
    }

    pub fn save_template(&self) -> Result<(), String> {
        write_model_json(&self.template_path, &self.template)
    }

    pub fn save_model(&self) -> Result<(), String> {
        write_model_json(&self.model_path, &self.params)
    }

    pub fn save_pending(&self) -> Result<(), String> {
        let mut pretty = serde_json::to_string_pretty(&self.pending).map_err(|e| e.to_string())?;
        pretty.push('\n');
        atomic_write_string(&self.events_path, &pretty)
    }
}

fn build_initial_template(cfg: &FakeConfig) -> BTreeMap<String, ParamEntry> {
    let mut m = BTreeMap::new();
    let mut add = |k: &str, val: &str, ptype: &str, writable: bool| {
        m.insert(
            k.to_owned(),
            ParamEntry {
                value: val.to_owned(),
                ptype: ptype.to_owned(),
                writable,
                notification: 0,
                access_list: vec!["Subscriber".to_owned()],
            },
        );
    };

    let conn_req_url = if cfg.conn_req_enable {
        format!("http://127.0.0.1:{}{}", cfg.conn_req_port, cfg.conn_req_path)
    } else {
        String::new()
    };

    // TR-098 InternetGatewayDevice.*
    add("InternetGatewayDevice.DeviceSummary", "InternetGatewayDevice:1.4[](Baseline:1)", "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.Manufacturer", &cfg.manufacturer, "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.ManufacturerOUI", &cfg.oui, "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.ModelName", &cfg.product_class, "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.Description", "NNRRWrt Simulated PON CPE", "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.ProductClass", &cfg.product_class, "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.SerialNumber", &cfg.serial_number, "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.HardwareVersion", &cfg.hardware_version, "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.SoftwareVersion", &cfg.software_version, "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.SpecVersion", "1.0", "xsd:string", false);
    add("InternetGatewayDevice.DeviceInfo.ProvisioningCode", "", "xsd:string", true);
    add("InternetGatewayDevice.DeviceInfo.UpTime", "120", "xsd:unsignedInt", false);

    add("InternetGatewayDevice.ManagementServer.EnableCWMP", "true", "xsd:boolean", true);
    add("InternetGatewayDevice.ManagementServer.URL", &cfg.acs_url, "xsd:string", true);
    add("InternetGatewayDevice.ManagementServer.Username", &cfg.acs_username, "xsd:string", true);
    add("InternetGatewayDevice.ManagementServer.Password", &cfg.acs_password, "xsd:string", true);
    add(
        "InternetGatewayDevice.ManagementServer.PeriodicInformEnable",
        if cfg.periodic_inform_enable { "true" } else { "false" },
        "xsd:boolean",
        true,
    );
    add(
        "InternetGatewayDevice.ManagementServer.PeriodicInformInterval",
        &cfg.periodic_inform_interval.to_string(),
        "xsd:unsignedInt",
        true,
    );
    add("InternetGatewayDevice.ManagementServer.PeriodicInformTime", "0001-01-01T00:00:00Z", "xsd:dateTime", true);
    add("InternetGatewayDevice.ManagementServer.ParameterKey", "", "xsd:string", false);
    add("InternetGatewayDevice.ManagementServer.ConnectionRequestURL", &conn_req_url, "xsd:string", false);
    add("InternetGatewayDevice.ManagementServer.ConnectionRequestUsername", &cfg.conn_req_username, "xsd:string", true);
    add("InternetGatewayDevice.ManagementServer.ConnectionRequestPassword", &cfg.conn_req_password, "xsd:string", true);
    add("InternetGatewayDevice.ManagementServer.UpgradesManaged", "false", "xsd:boolean", true);

    add("InternetGatewayDevice.WANDevice.1.WANCommonInterfaceConfig.EnabledForInternet", "true", "xsd:boolean", true);
    add("InternetGatewayDevice.WANDevice.1.WANCommonInterfaceConfig.WANAccessType", "X_PON", "xsd:string", false);
    add("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.Enable", "true", "xsd:boolean", true);
    add("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ConnectionStatus", "Connected", "xsd:string", false);
    add("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.AddressingType", "DHCP", "xsd:string", true);
    add("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress", "0.0.0.0", "xsd:string", true);
    add("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.MACAddress", &cfg.macaddr, "xsd:string", false);
    add("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.Name", "TR069_WAN", "xsd:string", true);

    // TR-181 Device.* core mirror
    add("Device.DeviceInfo.Manufacturer", &cfg.manufacturer, "xsd:string", false);
    add("Device.DeviceInfo.ManufacturerOUI", &cfg.oui, "xsd:string", false);
    add("Device.DeviceInfo.ProductClass", &cfg.product_class, "xsd:string", false);
    add("Device.DeviceInfo.SerialNumber", &cfg.serial_number, "xsd:string", false);
    add("Device.DeviceInfo.HardwareVersion", &cfg.hardware_version, "xsd:string", false);
    add("Device.DeviceInfo.SoftwareVersion", &cfg.software_version, "xsd:string", false);
    add("Device.ManagementServer.EnableCWMP", "true", "xsd:boolean", true);
    add("Device.ManagementServer.URL", &cfg.acs_url, "xsd:string", true);
    add("Device.ManagementServer.Username", &cfg.acs_username, "xsd:string", true);
    add("Device.ManagementServer.Password", &cfg.acs_password, "xsd:string", true);
    add(
        "Device.ManagementServer.PeriodicInformEnable",
        if cfg.periodic_inform_enable { "true" } else { "false" },
        "xsd:boolean",
        true,
    );
    add(
        "Device.ManagementServer.PeriodicInformInterval",
        &cfg.periodic_inform_interval.to_string(),
        "xsd:unsignedInt",
        true,
    );
    add("Device.ManagementServer.ParameterKey", "", "xsd:string", false);
    add("Device.ManagementServer.ConnectionRequestURL", &conn_req_url, "xsd:string", false);
    add("Device.ManagementServer.ConnectionRequestUsername", &cfg.conn_req_username, "xsd:string", true);
    add("Device.ManagementServer.ConnectionRequestPassword", &cfg.conn_req_password, "xsd:string", true);

    for (k, v) in &cfg.custom_params {
        add(k, v, "xsd:string", true);
    }
    m
}

fn mirror_mgmt_side_effect(name: &str, val: &str, effects: &mut ManagementEffects) {
    match name {
        "InternetGatewayDevice.ManagementServer.URL" | "Device.ManagementServer.URL" => {
            effects.acs_url = Some(val.to_owned());
        }
        "InternetGatewayDevice.ManagementServer.Username" | "Device.ManagementServer.Username" => {
            effects.acs_username = Some(val.to_owned());
        }
        "InternetGatewayDevice.ManagementServer.Password" | "Device.ManagementServer.Password" => {
            effects.acs_password = Some(val.to_owned());
        }
        "InternetGatewayDevice.ManagementServer.PeriodicInformEnable"
        | "Device.ManagementServer.PeriodicInformEnable" => {
            effects.periodic_inform_enable = Some(val == "true" || val == "1");
        }
        "InternetGatewayDevice.ManagementServer.PeriodicInformInterval"
        | "Device.ManagementServer.PeriodicInformInterval" => {
            if let Ok(sec) = val.parse::<u64>() {
                effects.periodic_inform_interval = Some(sec.max(10));
            }
        }
        "InternetGatewayDevice.ManagementServer.ConnectionRequestUsername"
        | "Device.ManagementServer.ConnectionRequestUsername" => {
            effects.conn_req_username = Some(val.to_owned());
        }
        "InternetGatewayDevice.ManagementServer.ConnectionRequestPassword"
        | "Device.ManagementServer.ConnectionRequestPassword" => {
            effects.conn_req_password = Some(val.to_owned());
        }
        _ => {}
    }
}

fn mirror_tr098_tr181(params: &mut BTreeMap<String, ParamEntry>, name: &str, val: &str) {
    let sibling = if let Some(rest) = name.strip_prefix("InternetGatewayDevice.") {
        format!("Device.{rest}")
    } else if let Some(rest) = name.strip_prefix("Device.") {
        format!("InternetGatewayDevice.{rest}")
    } else {
        return;
    };
    if let Some(entry) = params.get_mut(&sibling) {
        entry.value = val.to_owned();
    }
}

fn validate_type_value(ptype: &str, val: &str) -> bool {
    match ptype {
        "xsd:boolean" => matches!(val, "0" | "1" | "true" | "false"),
        "xsd:unsignedInt" => val.parse::<u64>().is_ok(),
        "xsd:int" => val.parse::<i64>().is_ok(),
        _ => true,
    }
}

fn normalize_value(ptype: &str, val: &str) -> String {
    if ptype == "xsd:boolean" {
        return match val {
            "1" | "true" => "true".to_owned(),
            _ => "false".to_owned(),
        };
    }
    val.to_owned()
}

fn derive_objects(params: &BTreeMap<String, ParamEntry>) -> BTreeSet<String> {
    let mut objects = BTreeSet::new();
    for key in params.keys() {
        add_ancestor_objects(&mut objects, key);
    }
    objects
}

fn add_ancestor_objects(objects: &mut BTreeSet<String>, param_path: &str) {
    let mut pos = 0;
    while let Some(dot) = param_path[pos..].find('.') {
        let end = pos + dot + 1;
        objects.insert(param_path[..end].to_owned());
        pos = end;
    }
}

fn write_model_json(path: &Path, params: &BTreeMap<String, ParamEntry>) -> Result<(), String> {
    let mut pretty = serde_json::to_string_pretty(params).map_err(|e| e.to_string())?;
    pretty.push('\n');
    atomic_write_string(path, &pretty)
}

fn is_secret_param_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.contains("password") || lower.contains("secret")
}

fn sanitize_params_map(params: &BTreeMap<String, ParamEntry>) -> BTreeMap<String, ParamEntry> {
    let mut root = BTreeMap::new();
    for (k, v) in params {
        let mut cloned = v.clone();
        if is_secret_param_key(k) && !cloned.value.is_empty() {
            cloned.value = "***".to_owned();
        }
        root.insert(k.clone(), cloned);
    }
    root
}

/// Returns `{"template":...,"model":...}` with password/secret values redacted and zero
/// filesystem writes (safe under read-only LuCI ACLs even when TR-069 Fake is disabled).
pub fn dump_sanitized_model_json(cfg: &FakeConfig) -> Result<String, String> {
    let dir = PathBuf::from(&cfg.state_dir);
    let template_path = dir.join("template.json");
    let model_path = dir.join("model.json");
    let template = if template_path.exists() {
        load_model_file(&template_path)?.0
    } else {
        build_initial_template(cfg)
    };
    let mut params = if model_path.exists() {
        load_model_file(&model_path)?.0
    } else {
        template.clone()
    };
    for (k, v) in &cfg.custom_params {
        params.entry(k.clone()).or_insert_with(|| ParamEntry {
            value: v.clone(),
            ptype: "xsd:string".to_owned(),
            writable: true,
            notification: 0,
            access_list: vec!["Subscriber".to_owned()],
        });
    }
    serde_json::to_string(&json!({
        "model": sanitize_params_map(&params),
        "template": sanitize_params_map(&template),
    }))
    .map_err(|e| e.to_string())
}

fn load_model_file(path: &Path) -> Result<(BTreeMap<String, ParamEntry>, BTreeSet<String>), String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let params: BTreeMap<String, ParamEntry> =
        serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let objects = derive_objects(&params);
    Ok((params, objects))
}

fn load_pending_file(path: &Path) -> Result<PendingState, String> {
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let mut pending: PendingState = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    pending.events.retain(|e| !e.event_code.is_empty());
    Ok(pending)
}

pub fn atomic_write_string(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("failed to write {}: {e}", tmp.display()))?;
        f.write_all(content.as_bytes())
            .and_then(|_| f.sync_all())
            .map_err(|e| format!("failed to sync {}: {e}", tmp.display()))?;
    }
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("failed to chmod {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("failed to rename {}: {e}", path.display()))
}

pub fn iso8601_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format_unix_timestamp(secs)
}

pub fn format_unix_timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil-from-days algorithm (UTC proleptic Gregorian).
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };

    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

fn load_overlay_sig(path: &Path) -> Option<BTreeMap<String, String>> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn save_overlay_sig(path: &Path, sig: &BTreeMap<String, String>) -> Result<(), String> {
    let mut pretty = serde_json::to_string_pretty(sig).map_err(|e| e.to_string())?;
    pretty.push('\n');
    atomic_write_string(path, &pretty)
}
