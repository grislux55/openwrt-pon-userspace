// SPDX-License-Identifier: GPL-2.0-only

//! Service configuration model derived from the OMCI MIB.
//!
//! `mib` stores OLT-provisioned managed entities. This snapshot forms the
//! boundary between the MIB and the AN7581 kernel data path and is shared by
//! the control interface and kernel backend.

use std::collections::BTreeSet;

/// Match value for untagged upstream frames and tagged frames after concrete VID lookup.
pub const DATA_PATH_VLAN_ANY: u16 = u16::MAX;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DataPathCandidate {
    pub alloc_id: u16,
    pub gem_id: u16,
    pub vlan_id: u16,
    pub pbit_mask: u8,
    /// A Class 281 GEM carries downstream multicast traffic.
    pub multicast: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ProvisioningSnapshot {
    /// OLT-G text fields after fixed-width wire padding is removed.
    pub olt_vendor_id: String,
    pub olt_equipment_id: String,
    pub olt_version: String,
    pub configured_tconts: usize,
    pub gem_ports: usize,
    pub gem_interworking_tps: usize,
    pub vlan_rules: usize,
    /// VLANs used by unicast service data paths.
    pub vlan_ids: BTreeSet<u16>,
    /// VLANs mapped to Class 281 downstream multicast GEMs.
    pub multicast_vlan_ids: BTreeSet<u16>,
    /// IGMP upstream VLANs selected by Class 309 profiles referenced from Class 310.
    pub igmp_upstream_vlan_ids: BTreeSet<u16>,
    /// Class 309 attribute 5: 0 transparent, 1 add, 2 replace TCI, 3 replace VID.
    pub igmp_upstream_tag_controls: BTreeSet<u8>,
    /// Class 332 is present in the MIB.
    pub enhanced_security: bool,
    /// Key indexes with at least one Class 332 attribute 11 broadcast key fragment.
    pub broadcast_key_indexes: BTreeSet<u8>,
    pub data_paths: Vec<DataPathCandidate>,
}

#[derive(Clone, Debug)]
pub struct DataPathTableRow {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct DataPathAttribute {
    pub index: u8,
    pub value: Vec<u8>,
    pub table_rows: Vec<DataPathTableRow>,
}

#[derive(Clone, Debug)]
pub struct DataPathEntity {
    pub class_id: u16,
    pub entity_id: u16,
    pub attributes: Vec<DataPathAttribute>,
}

#[derive(Clone, Debug, Default)]
pub struct DataPathGraph {
    pub candidates: Vec<DataPathCandidate>,
    pub entities: Vec<DataPathEntity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpHostFamily {
    Ipv4,
    Ipv6,
    Unknown,
}

impl IpHostFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4HostSnapshot {
    pub entity_id: u16,
    pub mac_address: String,
    pub ip_options: u8,
    pub ip_address: String,
    pub mask: String,
    pub gateway: String,
    pub primary_dns: String,
    pub secondary_dns: String,
    pub current_address: String,
    pub current_mask: String,
    pub current_gateway: String,
    pub current_primary_dns: String,
    pub current_secondary_dns: String,
    pub domain_name: String,
    pub host_name: String,
    pub relay_tag_mode: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv6HostSnapshot {
    pub entity_id: u16,
    pub mac_address: String,
    pub ip_options: u8,
    pub ipv6_address: String,
    pub prefix_length: u8,
    pub gateway: String,
    pub primary_dns: String,
    pub secondary_dns: String,
    pub current_addresses: Vec<String>,
    pub current_gateway: String,
    pub current_primary_dns: String,
    pub current_secondary_dns: String,
    pub domain_name: String,
    pub host_name: String,
    pub relay_tag_mode: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TcpUdpConfigSnapshot {
    pub entity_id: u16,
    pub port: u16,
    pub protocol: u8,
    pub tos_diffserv: u8,
    pub ip_host_pointer: u16,
    pub ip_host_family: IpHostFamily,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tr069ServerSnapshot {
    pub entity_id: u16,
    pub admin_state: bool,
    pub acs_url: String,
    pub associated_tag: u16,
    pub tcp_udp_pointer: Option<u16>,
    pub ip_host_pointer: Option<u16>,
    pub ip_host_family: IpHostFamily,
    pub auth_method: u8,
    pub acs_username: String,
    pub acs_password: String,
    pub acs_username_present: bool,
    pub acs_password_present: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Tr069ProvisioningSnapshot {
    pub management_vlan: Option<u16>,
    pub ipv4_hosts: Vec<Ipv4HostSnapshot>,
    pub ipv6_hosts: Vec<Ipv6HostSnapshot>,
    pub tcp_udp_configs: Vec<TcpUdpConfigSnapshot>,
    pub tr069_servers: Vec<Tr069ServerSnapshot>,
}
