// SPDX-License-Identifier: GPL-2.0-only

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use super::backend::BackendStatus;
use super::protocol::Request;
use super::provisioning::{DataPathGraph, ProvisioningSnapshot, Tr069ProvisioningSnapshot};

const CONTROL_PROTOCOL_VERSION: u8 = 1;
const EVENT_CAPACITY: usize = 256;

#[derive(Clone, Debug)]
struct Transaction {
    tci: u16,
    action: u8,
    class_id: u16,
    entity_id: u16,
    attribute_mask: u16,
    result: Option<u8>,
}

#[derive(Clone, Debug)]
struct Event {
    sequence: u64,
    timestamp_ms: u128,
    kind: &'static str,
    message: String,
}

#[derive(Debug)]
struct Inner {
    line: String,
    interface: String,
    loid_configured: bool,
    rx_messages: u64,
    tx_messages: u64,
    parse_errors: u64,
    authentication_status: Option<u8>,
    authentication_meaning: &'static str,
    provisioning: ProvisioningSnapshot,
    data_path_graph: DataPathGraph,
    backend: BackendStatus,
    tr069: Tr069ProvisioningSnapshot,
    tr069_updated_at_ms: u128,
    tr069_initialized: bool,
    tr069_snapshot_path: Option<PathBuf>,
    last_transaction: Option<Transaction>,
    event_sequence: u64,
    events: VecDeque<Event>,
}

#[derive(Clone, Debug)]
pub struct StatusHub {
    shared: Arc<Mutex<Inner>>,
}

impl StatusHub {
    pub fn new(
        line: &str,
        interface: &str,
        loid_configured: bool,
        tr069_snapshot_path: Option<PathBuf>,
    ) -> Self {
        let hub = Self {
            shared: Arc::new(Mutex::new(Inner {
                line: line.to_owned(),
                interface: interface.to_owned(),
                loid_configured,
                rx_messages: 0,
                tx_messages: 0,
                parse_errors: 0,
                authentication_status: None,
                authentication_meaning: "not-reported",
                provisioning: ProvisioningSnapshot::default(),
                data_path_graph: DataPathGraph::default(),
                backend: BackendStatus::default(),
                tr069: Tr069ProvisioningSnapshot::default(),
                tr069_updated_at_ms: 0,
                tr069_initialized: false,
                tr069_snapshot_path,
                last_transaction: None,
                event_sequence: 0,
                events: VecDeque::with_capacity(EVENT_CAPACITY),
            })),
        };
        hub.record_event("lifecycle", "OMCI daemon started".to_owned());
        hub
    }

    pub fn record_rx(&self, request: &Request<'_>) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.rx_messages += 1;
        inner.last_transaction = Some(Transaction {
            tci: request.tci,
            action: request.action,
            class_id: request.class_id,
            entity_id: request.entity_id,
            attribute_mask: request.attribute_mask,
            result: None,
        });
        drop(inner);
        self.record_event(
            "rx",
            format!(
                "tci=0x{:04x} action=0x{:02x} class={} entity={} {}=0x{:04x}",
                request.tci,
                request.action,
                request.class_id,
                request.entity_id,
                request.selector_name(),
                request.attribute_mask
            ),
        );
    }

    pub fn record_tx(&self, request: &Request<'_>, result: Option<u8>, retransmission: bool) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.tx_messages += 1;
        inner.last_transaction = Some(Transaction {
            tci: request.tci,
            action: request.action,
            class_id: request.class_id,
            entity_id: request.entity_id,
            attribute_mask: request.attribute_mask,
            result,
        });
        drop(inner);
        self.record_event(
            "tx",
            format!(
                "tci=0x{:04x} action=0x{:02x} class={} entity={} result={} retransmission={}",
                request.tci,
                request.action,
                request.class_id,
                request.entity_id,
                result
                    .map(|value| format!("0x{value:02x}"))
                    .unwrap_or_else(|| "none".to_owned()),
                retransmission
            ),
        );
    }

    pub fn record_parse_error(&self, error: &str) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.parse_errors += 1;
        drop(inner);
        self.record_event("parse-error", error.to_owned());
    }

    pub fn record_authentication_status(&self, status: u8, meaning: &'static str) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.authentication_status = Some(status);
        inner.authentication_meaning = meaning;
        drop(inner);
        self.record_event(
            "authentication",
            format!("status={status} meaning={meaning}"),
        );
    }

    pub fn record_transport_error(&self, error: &str) {
        self.record_event("transport-error", error.to_owned());
    }

    pub fn record_provisioning(
        &self,
        provisioning: ProvisioningSnapshot,
        data_path_graph: DataPathGraph,
        backend: BackendStatus,
        tr069: Tr069ProvisioningSnapshot,
    ) {
        let snapshot_to_write = {
            let mut inner = self.shared.lock().expect("status mutex poisoned");
            inner.provisioning = provisioning;
            inner.data_path_graph = data_path_graph;
            inner.backend = backend;
            if !inner.tr069_initialized || inner.tr069 != tr069 {
                inner.tr069 = tr069;
                inner.tr069_updated_at_ms = now_ms();
                inner.tr069_initialized = true;
                inner
                    .tr069_snapshot_path
                    .as_ref()
                    .map(|path| (path.clone(), tr069_json(&inner)))
            } else {
                None
            }
        };
        if let Some((path, json)) = snapshot_to_write {
            if let Err(error) = write_tr069_snapshot(&path, &json) {
                self.record_event(
                    "tr069-export-error",
                    format!("failed to write {}: {error}", path.display()),
                );
            }
        }
    }

    fn record_event(&self, kind: &'static str, message: String) {
        let mut inner = self.shared.lock().expect("status mutex poisoned");
        inner.event_sequence += 1;
        let sequence = inner.event_sequence;
        if inner.events.len() == EVENT_CAPACITY {
            inner.events.pop_front();
        }
        inner.events.push_back(Event {
            sequence,
            timestamp_ms: now_ms(),
            kind,
            message,
        });
    }
}

pub fn start_server(
    socket_path: &Path,
    status: StatusHub,
) -> io::Result<crate::control::ControlServer> {
    crate::control::ControlServer::start(socket_path, move |stream| handle_client(stream, &status))
}

fn handle_client(mut stream: UnixStream, status: &StatusHub) -> io::Result<()> {
    let mut request = String::new();
    {
        let mut reader = BufReader::new(&stream);
        reader.read_line(&mut request)?;
    }
    let fields: Vec<&str> = request.split_whitespace().collect();

    match fields.as_slice() {
        ["STATUS", "1"] => {
            let inner = status.shared.lock().expect("status mutex poisoned");
            writeln!(stream, "{}", status_json(&inner))
        }
        ["DATAPATH", "1"] => {
            let inner = status.shared.lock().expect("status mutex poisoned");
            writeln!(stream, "{}", data_path_json(&inner))
        }
        ["TR069", "1"] => {
            let inner = status.shared.lock().expect("status mutex poisoned");
            writeln!(stream, "{}", tr069_json(&inner))
        }
        ["EVENTS", "1", after] => {
            let after = after
                .parse::<u64>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid event cursor"))?;
            write_events(&mut stream, status, after)
        }
        _ => {
            writeln!(
                stream,
                "{{\"error\":\"unsupported control request\",\"protocol_version\":{CONTROL_PROTOCOL_VERSION}}}"
            )
        }
    }
}

fn write_events(stream: &mut UnixStream, status: &StatusHub, after: u64) -> io::Result<()> {
    let inner = status.shared.lock().expect("status mutex poisoned");
    for event in inner.events.iter().filter(|event| event.sequence > after) {
        writeln!(stream, "{}", event_json(event))?;
    }
    stream.flush()
}

fn status_json(inner: &Inner) -> String {
    let carrier = read_carrier(&inner.interface);
    let carrier_json = carrier
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let authentication_status = inner
        .authentication_status
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let last_transaction = inner
        .last_transaction
        .as_ref()
        .map(transaction_json)
        .unwrap_or_else(|| "null".to_owned());
    let vlan_ids = inner
        .provisioning
        .vlan_ids
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let multicast_vlan_ids = inner
        .provisioning
        .multicast_vlan_ids
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let igmp_upstream_vlan_ids = inner
        .provisioning
        .igmp_upstream_vlan_ids
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let igmp_upstream_tag_controls = inner
        .provisioning
        .igmp_upstream_tag_controls
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let broadcast_key_indexes = inner
        .provisioning
        .broadcast_key_indexes
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let data_path_active = carrier != Some(false);
    let active_alloc_id = data_path_active
        .then_some(inner.backend.active_alloc_id)
        .flatten()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let active_gem_id = data_path_active
        .then_some(inner.backend.active_gem_id)
        .flatten()
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    let backend_state = if data_path_active {
        inner.backend.state
    } else {
        "inactive"
    };
    let data_path_all_vlans = data_path_active && inner.backend.all_vlans;
    let backend_error = inner
        .backend
        .error
        .as_deref()
        .map(json_string)
        .unwrap_or_else(|| "null".to_owned());

    format!(
        concat!(
            "{{\"protocol_version\":{},\"interface\":{},",
            "\"channel_available\":{},\"loid_configured\":{},",
            "\"authentication_status\":{},\"authentication_meaning\":{},",
            "\"olt_vendor_id\":{},\"olt_equipment_id\":{},\"olt_version\":{},",
            "\"rx_messages\":{},\"tx_messages\":{},\"parse_errors\":{},",
            "\"tcont_count\":{},\"gem_port_count\":{},",
            "\"gem_iwtp_count\":{},\"vlan_rule_count\":{},",
            "\"vlan_ids\":[{}],\"multicast_vlan_ids\":[{}],",
            "\"igmp_upstream_vlan_ids\":[{}],",
            "\"igmp_upstream_tag_controls\":[{}],",
            "\"enhanced_security\":{},\"broadcast_key_indexes\":[{}],",
            "\"data_path_candidate_count\":{},",
            "\"data_path_all_vlans\":{},",
            "\"backend_state\":{},\"active_alloc_id\":{},",
            "\"active_gem_id\":{},\"backend_error\":{},",
            "\"event_sequence\":{},\"last_transaction\":{}}}"
        ),
        CONTROL_PROTOCOL_VERSION,
        json_string(&inner.interface),
        carrier_json,
        inner.loid_configured,
        authentication_status,
        json_string(inner.authentication_meaning),
        json_string(&inner.provisioning.olt_vendor_id),
        json_string(&inner.provisioning.olt_equipment_id),
        json_string(&inner.provisioning.olt_version),
        inner.rx_messages,
        inner.tx_messages,
        inner.parse_errors,
        inner.provisioning.configured_tconts,
        inner.provisioning.gem_ports,
        inner.provisioning.gem_interworking_tps,
        inner.provisioning.vlan_rules,
        vlan_ids,
        multicast_vlan_ids,
        igmp_upstream_vlan_ids,
        igmp_upstream_tag_controls,
        inner.provisioning.enhanced_security,
        broadcast_key_indexes,
        inner.provisioning.data_paths.len(),
        data_path_all_vlans,
        json_string(backend_state),
        active_alloc_id,
        active_gem_id,
        backend_error,
        inner.event_sequence,
        last_transaction
    )
}

fn transaction_json(transaction: &Transaction) -> String {
    let result = transaction
        .result
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_owned());
    format!(
        concat!(
            "{{\"tci\":{},\"action\":{},\"class_id\":{},\"entity_id\":{},",
            "\"attribute_mask\":{},\"result\":{}}}"
        ),
        transaction.tci,
        transaction.action,
        transaction.class_id,
        transaction.entity_id,
        transaction.attribute_mask,
        result
    )
}

fn data_path_json(inner: &Inner) -> String {
    let mut candidates = String::new();
    for (index, candidate) in inner.data_path_graph.candidates.iter().enumerate() {
        if index != 0 {
            candidates.push(',');
        }
        use std::fmt::Write as _;
        let _ = write!(
            candidates,
            concat!(
                "{{\"alloc_id\":{},\"gem_id\":{},\"vlan_id\":{},",
                "\"pbit_mask\":{},\"multicast\":{}}}"
            ),
            candidate.alloc_id,
            candidate.gem_id,
            candidate.vlan_id,
            candidate.pbit_mask,
            candidate.multicast
        );
    }

    let mut entities = String::new();
    for (entity_index, entity) in inner.data_path_graph.entities.iter().enumerate() {
        if entity_index != 0 {
            entities.push(',');
        }
        let mut attributes = String::new();
        for (attribute_index, attribute) in entity.attributes.iter().enumerate() {
            if attribute_index != 0 {
                attributes.push(',');
            }
            let mut rows = String::new();
            for (row_index, row) in attribute.table_rows.iter().enumerate() {
                if row_index != 0 {
                    rows.push(',');
                }
                rows.push_str("{\"key\":");
                rows.push_str(&json_string(&hex_bytes(&row.key)));
                rows.push_str(",\"value\":");
                rows.push_str(&json_string(&hex_bytes(&row.value)));
                rows.push('}');
            }
            use std::fmt::Write as _;
            let _ = write!(
                attributes,
                "{{\"index\":{},\"value\":{},\"table_rows\":[{}]}}",
                attribute.index,
                json_string(&hex_bytes(&attribute.value)),
                rows
            );
        }
        use std::fmt::Write as _;
        let _ = write!(
            entities,
            concat!(
                "{{\"class_id\":{},\"class_name\":{},",
                "\"entity_id\":{},\"attributes\":[{}]}}"
            ),
            entity.class_id,
            json_string(data_path_class_name(entity.class_id)),
            entity.entity_id,
            attributes
        );
    }

    let backend_error = inner
        .backend
        .error
        .as_deref()
        .map(json_string)
        .unwrap_or_else(|| "null".to_owned());
    format!(
        concat!(
            "{{\"protocol_version\":{},\"backend_state\":{},",
            "\"backend_error\":{},\"data_path_all_vlans\":{},",
            "\"candidates\":[{}],\"entities\":[{}]}}"
        ),
        CONTROL_PROTOCOL_VERSION,
        json_string(inner.backend.state),
        backend_error,
        inner.backend.all_vlans,
        candidates,
        entities
    )
}

fn data_path_class_name(class_id: u16) -> &'static str {
    match class_id {
        47 => "MAC Bridge Port Configuration Data",
        84 => "VLAN Tagging Filter Data",
        130 => "IEEE 802.1p Mapper Service Profile",
        171 => "Extended VLAN Tagging Operation Configuration Data",
        266 => "GEM Interworking Termination Point",
        268 => "GEM Port Network CTP",
        280 => "Traffic Descriptor",
        281 => "Multicast GEM Interworking Termination Point",
        309 => "Multicast Operations Profile",
        310 => "Multicast Subscriber Configuration Info",
        _ => "Unknown",
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn event_json(event: &Event) -> String {
    format!(
        "{{\"sequence\":{},\"timestamp_ms\":{},\"kind\":{},\"message\":{}}}",
        event.sequence,
        event.timestamp_ms,
        json_string(event.kind),
        json_string(&event.message)
    )
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn read_carrier(interface: &str) -> Option<bool> {
    let carrier = fs::read_to_string(format!("/sys/class/net/{interface}/carrier")).ok()?;
    match carrier.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::provisioning::{
        IpHostFamily, Ipv4HostSnapshot, Ipv6HostSnapshot, TcpUdpConfigSnapshot,
        Tr069ServerSnapshot,
    };

    #[test]
    fn tr069_socket_and_atomic_snapshot_file_match_contract() {
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("airoha-pond-test-{pid}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("airoha-pond.line0.sock");
        let snap_path = dir.join("airoha-pond-tr069.line0.json");

        let hub = StatusHub::new("line0", "omci0", false, Some(snap_path.clone()));
        let _server = start_server(&sock_path, hub.clone()).unwrap();

        let tr069 = Tr069ProvisioningSnapshot {
            management_vlan: Some(46),
            ipv4_hosts: vec![Ipv4HostSnapshot {
                entity_id: 1,
                mac_address: "02:11:22:33:44:55".to_owned(),
                ip_options: 1,
                ip_address: "0.0.0.0".to_owned(),
                mask: "0.0.0.0".to_owned(),
                gateway: "0.0.0.0".to_owned(),
                primary_dns: "0.0.0.0".to_owned(),
                secondary_dns: "0.0.0.0".to_owned(),
                current_address: "10.0.0.2".to_owned(),
                current_mask: "255.255.255.0".to_owned(),
                current_gateway: "10.0.0.1".to_owned(),
                current_primary_dns: "10.0.0.53".to_owned(),
                current_secondary_dns: "0.0.0.0".to_owned(),
                domain_name: "example.invalid".to_owned(),
                host_name: "cpe-test".to_owned(),
                relay_tag_mode: 0xffff,
            }],
            ipv6_hosts: vec![Ipv6HostSnapshot {
                entity_id: 2,
                mac_address: "02:11:22:33:44:55".to_owned(),
                ip_options: 7,
                ipv6_address: "2001:db8::10".to_owned(),
                prefix_length: 64,
                gateway: "fe80::1".to_owned(),
                primary_dns: "2001:db8::53".to_owned(),
                secondary_dns: "::".to_owned(),
                current_addresses: vec!["2001:db8::10".to_owned()],
                current_gateway: "fe80::1".to_owned(),
                current_primary_dns: "2001:db8::53".to_owned(),
                current_secondary_dns: "::".to_owned(),
                domain_name: "example.invalid".to_owned(),
                host_name: "cpe-test".to_owned(),
                relay_tag_mode: 0xffff,
            }],
            tcp_udp_configs: vec![TcpUdpConfigSnapshot {
                entity_id: 1,
                port: 7547,
                protocol: 6,
                tos_diffserv: 0,
                ip_host_pointer: 2,
                ip_host_family: IpHostFamily::Ipv6,
            }],
            tr069_servers: vec![Tr069ServerSnapshot {
                entity_id: 0,
                admin_state: true,
                acs_url: "https://acs.example.invalid:9443/cwmp".to_owned(),
                associated_tag: 1,
                tcp_udp_pointer: Some(1),
                ip_host_pointer: Some(2),
                ip_host_family: IpHostFamily::Ipv6,
                auth_method: 1,
                acs_username: "synthetic-user".to_owned(),
                acs_password: "synthetic-\"pass\"".to_owned(),
                acs_username_present: true,
                acs_password_present: true,
            }],
        };

        hub.record_provisioning(
            ProvisioningSnapshot::default(),
            DataPathGraph::default(),
            BackendStatus::default(),
            tr069,
        );

        let meta = fs::metadata(&snap_path).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let file_json = fs::read_to_string(&snap_path).unwrap();

        let mut stream = UnixStream::connect(&sock_path).unwrap();
        writeln!(stream, "TR069 1").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();
        let mut sock_json = String::new();
        std::io::Read::read_to_string(&mut stream, &mut sock_json).unwrap();

        assert_eq!(file_json.trim(), sock_json.trim());
        for expected in [
            "\"protocol_version\":1",
            "\"line\":\"line0\"",
            "\"management_vlan\":46",
            "\"ipv4_hosts\":[",
            "\"ipv6_hosts\":[",
            "\"tcp_udp_configs\":[",
            "\"tr069_servers\":[",
            "\"ip_host_family\":\"ipv6\"",
            "\"acs_url\":\"https://acs.example.invalid:9443/cwmp\"",
            "\"acs_password\":\"synthetic-\\\"pass\\\"\"",
        ] {
            assert!(sock_json.contains(expected), "missing {expected} in {sock_json}");
        }

        let _ = fs::remove_dir_all(&dir);
    }
}

pub fn write_tr069_snapshot(path: &Path, json: &str) -> io::Result<()> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("tr069-snapshot.json");
    let tmp_path = path.with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    file.write_all(json.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp_path, path)
}

fn tr069_json(inner: &Inner) -> String {
    use std::fmt::Write as _;

    let management_vlan = inner
        .tr069
        .management_vlan
        .map(|vid| vid.to_string())
        .unwrap_or_else(|| "null".to_owned());

    let mut ipv4_hosts = String::new();
    for (index, host) in inner.tr069.ipv4_hosts.iter().enumerate() {
        if index != 0 {
            ipv4_hosts.push(',');
        }
        let _ = write!(
            ipv4_hosts,
            concat!(
                "{{\"entity_id\":{},\"mac_address\":{},\"ip_options\":{},",
                "\"ip_address\":{},\"mask\":{},\"gateway\":{},",
                "\"primary_dns\":{},\"secondary_dns\":{},",
                "\"current_address\":{},\"current_mask\":{},\"current_gateway\":{},",
                "\"current_primary_dns\":{},\"current_secondary_dns\":{},",
                "\"domain_name\":{},\"host_name\":{},\"relay_tag_mode\":{}}}"
            ),
            host.entity_id,
            json_string(&host.mac_address),
            host.ip_options,
            json_string(&host.ip_address),
            json_string(&host.mask),
            json_string(&host.gateway),
            json_string(&host.primary_dns),
            json_string(&host.secondary_dns),
            json_string(&host.current_address),
            json_string(&host.current_mask),
            json_string(&host.current_gateway),
            json_string(&host.current_primary_dns),
            json_string(&host.current_secondary_dns),
            json_string(&host.domain_name),
            json_string(&host.host_name),
            host.relay_tag_mode
        );
    }

    let mut ipv6_hosts = String::new();
    for (index, host) in inner.tr069.ipv6_hosts.iter().enumerate() {
        if index != 0 {
            ipv6_hosts.push(',');
        }
        let current_addresses = host
            .current_addresses
            .iter()
            .map(|addr| json_string(addr))
            .collect::<Vec<_>>()
            .join(",");
        let _ = write!(
            ipv6_hosts,
            concat!(
                "{{\"entity_id\":{},\"mac_address\":{},\"ip_options\":{},",
                "\"ipv6_address\":{},\"prefix_length\":{},\"gateway\":{},",
                "\"primary_dns\":{},\"secondary_dns\":{},",
                "\"current_addresses\":[{}],\"current_gateway\":{},",
                "\"current_primary_dns\":{},\"current_secondary_dns\":{},",
                "\"domain_name\":{},\"host_name\":{},\"relay_tag_mode\":{}}}"
            ),
            host.entity_id,
            json_string(&host.mac_address),
            host.ip_options,
            json_string(&host.ipv6_address),
            host.prefix_length,
            json_string(&host.gateway),
            json_string(&host.primary_dns),
            json_string(&host.secondary_dns),
            current_addresses,
            json_string(&host.current_gateway),
            json_string(&host.current_primary_dns),
            json_string(&host.current_secondary_dns),
            json_string(&host.domain_name),
            json_string(&host.host_name),
            host.relay_tag_mode
        );
    }

    let mut tcp_udp_configs = String::new();
    for (index, cfg) in inner.tr069.tcp_udp_configs.iter().enumerate() {
        if index != 0 {
            tcp_udp_configs.push(',');
        }
        let _ = write!(
            tcp_udp_configs,
            concat!(
                "{{\"entity_id\":{},\"port\":{},\"protocol\":{},",
                "\"tos_diffserv\":{},\"ip_host_pointer\":{},\"ip_host_family\":{}}}"
            ),
            cfg.entity_id,
            cfg.port,
            cfg.protocol,
            cfg.tos_diffserv,
            cfg.ip_host_pointer,
            json_string(cfg.ip_host_family.as_str())
        );
    }

    let mut tr069_servers = String::new();
    for (index, server) in inner.tr069.tr069_servers.iter().enumerate() {
        if index != 0 {
            tr069_servers.push(',');
        }
        let tcp_udp_pointer = server
            .tcp_udp_pointer
            .map(|ptr| ptr.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let ip_host_pointer = server
            .ip_host_pointer
            .map(|ptr| ptr.to_string())
            .unwrap_or_else(|| "null".to_owned());
        let _ = write!(
            tr069_servers,
            concat!(
                "{{\"entity_id\":{},\"admin_state\":{},\"acs_url\":{},",
                "\"associated_tag\":{},\"tcp_udp_pointer\":{},",
                "\"ip_host_pointer\":{},\"ip_host_family\":{},",
                "\"auth_method\":{},\"acs_username\":{},\"acs_password\":{},",
                "\"acs_username_present\":{},\"acs_password_present\":{}}}"
            ),
            server.entity_id,
            server.admin_state,
            json_string(&server.acs_url),
            server.associated_tag,
            tcp_udp_pointer,
            ip_host_pointer,
            json_string(server.ip_host_family.as_str()),
            server.auth_method,
            json_string(&server.acs_username),
            json_string(&server.acs_password),
            server.acs_username_present,
            server.acs_password_present
        );
    }

    format!(
        concat!(
            "{{\"protocol_version\":{},\"line\":{},\"updated_at_ms\":{},",
            "\"management_vlan\":{},\"ipv4_hosts\":[{}],\"ipv6_hosts\":[{}],",
            "\"tcp_udp_configs\":[{}],\"tr069_servers\":[{}]}}"
        ),
        CONTROL_PROTOCOL_VERSION,
        json_string(&inner.line),
        inner.tr069_updated_at_ms,
        management_vlan,
        ipv4_hosts,
        ipv6_hosts,
        tcp_udp_configs,
        tr069_servers
    )
}
