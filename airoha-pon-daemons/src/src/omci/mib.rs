// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};

use super::config::{fixed_width, IdentityConfig};
use super::protocol::{
    attribute_bit, Request, Response, ACTION_CREATE, ACTION_DELETE, ACTION_GET,
    ACTION_GET_ALL_ALARMS, ACTION_GET_ALL_ALARMS_NEXT, ACTION_GET_CURRENT_DATA, ACTION_GET_NEXT,
    ACTION_MIB_RESET, ACTION_MIB_UPLOAD, ACTION_MIB_UPLOAD_NEXT, ACTION_SET, ACTION_SET_TABLE,
    ACTION_SYNCHRONIZE_TIME, RESULT_ATTRIBUTE_FAILED, RESULT_COMMAND_NOT_SUPPORTED,
    RESULT_INSTANCE_EXISTS, RESULT_PARAMETER_ERROR, RESULT_SUCCESS, RESULT_UNKNOWN_INSTANCE,
    RESULT_UNKNOWN_ME,
};
use super::provisioning::{
    DataPathAttribute, DataPathCandidate, DataPathEntity, DataPathGraph, DataPathTableRow,
    IpHostFamily, Ipv4HostSnapshot, Ipv6HostSnapshot, ProvisioningSnapshot,
    TcpUdpConfigSnapshot, Tr069ProvisioningSnapshot, Tr069ServerSnapshot, DATA_PATH_VLAN_ANY,
};
use super::schema::{self, AttributeAccess, AttributeKind, CreateSource, ManagedEntityOrigin};
use super::security;

#[allow(unused_imports)]
pub use super::schema::{
    CLASS_ANI_G, CLASS_AUTHENTICATION_SECURITY_METHOD, CLASS_CARDHOLDER, CLASS_CIRCUIT_PACK,
    CLASS_CTC_LOID_AUTH, CLASS_ENHANCED_SECURITY_CONTROL, CLASS_ETHERNET_FRAME_EXTENDED_PM,
    CLASS_ETHERNET_PM_HISTORY_DATA, CLASS_ETHERNET_PM_HISTORY_DATA_2,
    CLASS_ETHERNET_PM_HISTORY_DATA_3, CLASS_EXTENDED_VLAN_TAGGING, CLASS_FEC_PM_HISTORY_DATA,
    CLASS_GAL_ETHERNET_PROFILE, CLASS_GEM_INTERWORKING_TP, CLASS_GEM_PORT_NETWORK_CTP,
    CLASS_GEM_PORT_PM_HISTORY_DATA, CLASS_IEEE_8021P_MAPPER, CLASS_IPV6_HOST_CONFIG_DATA,
    CLASS_IP_HOST_CONFIG_DATA, CLASS_LARGE_STRING, CLASS_MAC_BRIDGE_PORT_CONFIG_DATA,
    CLASS_MAC_BRIDGE_PORT_FILTER_PREASSIGN_DATA, CLASS_MAC_BRIDGE_PORT_PM_HISTORY_DATA,
    CLASS_MAC_BRIDGE_SERVICE_PROFILE, CLASS_MULTICAST_GEM_INTERWORKING_TP,
    CLASS_MULTICAST_OPERATIONS_PROFILE, CLASS_MULTICAST_SUBSCRIBER_CONFIG,
    CLASS_MULTICAST_SUBSCRIBER_MONITOR, CLASS_NETWORK_ADDRESS, CLASS_OLT_G, CLASS_OMCI,
    CLASS_ONU2_G, CLASS_ONU_DATA, CLASS_ONU_G, CLASS_ONU_POWER_SHEDDING,
    CLASS_PPTP_ETHERNET_UNI, CLASS_PRIORITY_QUEUE, CLASS_SOFTWARE_IMAGE, CLASS_TCONT,
    CLASS_TCP_UDP_CONFIG_DATA, CLASS_THRESHOLD_DATA_1, CLASS_THRESHOLD_DATA_2,
    CLASS_TR069_MANAGEMENT_SERVER, CLASS_TRAFFIC_DESCRIPTOR, CLASS_TRAFFIC_SCHEDULER,
    CLASS_UNI_G, CLASS_VEIP, CLASS_VENDOR_247, CLASS_VENDOR_351, CLASS_VLAN_TAGGING_FILTER,
};

const TCONT_COUNT: u16 = 16;
const TCONT_FIRST_ENTITY: u16 = 0x8000;
const ETHERNET_UNI_COUNT: u16 = 4;
const QUEUES_PER_TCONT: u16 = 8;
const QUEUES_PER_UNI: u16 = 8;
const UPSTREAM_PRIORITY_QUEUE_COUNT: u16 = TCONT_COUNT * QUEUES_PER_TCONT;
const DOWNSTREAM_PRIORITY_QUEUE_COUNT: u16 = ETHERNET_UNI_COUNT * QUEUES_PER_UNI;
const TOTAL_PRIORITY_QUEUE_COUNT: u16 =
    UPSTREAM_PRIORITY_QUEUE_COUNT + DOWNSTREAM_PRIORITY_QUEUE_COUNT;
const TOTAL_GEM_PORT_COUNT: u16 = 256;
const VEIP_ENTITY: u16 = 0x0a01;
pub const IP_HOST_DEFAULT_ENTITY: u16 = 1;
pub const IPV6_HOST_DEFAULT_ENTITY: u16 = 2;
pub const TR069_SERVER_DEFAULT_ENTITY: u16 = 0;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttributeValueChange {
    pub class_id: u16,
    pub entity_id: u16,
    pub attribute_mask: u16,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Attribute {
    value: Vec<u8>,
    writable: bool,
    table_row_len: Option<usize>,
    table_rows: BTreeMap<Vec<u8>, Vec<u8>>,
    upload: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct ManagedEntity {
    attributes: BTreeMap<u8, Attribute>,
}

impl ManagedEntity {
    fn read_only(mut self, index: u8, value: Vec<u8>) -> Self {
        self.attributes.insert(
            index,
            Attribute {
                value,
                writable: false,
                table_row_len: None,
                table_rows: BTreeMap::new(),
                upload: true,
            },
        );
        self
    }

    fn read_write(mut self, index: u8, value: Vec<u8>) -> Self {
        self.attributes.insert(
            index,
            Attribute {
                value,
                writable: true,
                table_row_len: None,
                table_rows: BTreeMap::new(),
                upload: true,
            },
        );
        self
    }

    fn table(mut self, index: u8, row_len: usize) -> Self {
        self.attributes.insert(
            index,
            Attribute {
                value: Vec::new(),
                writable: true,
                table_row_len: Some(row_len),
                table_rows: BTreeMap::new(),
                upload: false,
            },
        );
        self
    }

    fn read_only_table(mut self, index: u8, row_len: usize) -> Self {
        self.attributes.insert(
            index,
            Attribute {
                value: Vec::new(),
                writable: false,
                table_row_len: Some(row_len),
                table_rows: BTreeMap::new(),
                upload: false,
            },
        );
        self
    }
}

fn entity_from_definition(class_id: u16, payload: Option<&[u8]>) -> Option<ManagedEntity> {
    let definition = schema::managed_entity(class_id)?;
    let mut entity = ManagedEntity::default();

    for attribute in definition.attributes {
        let table_row_len = match attribute.kind {
            AttributeKind::Scalar { .. } => None,
            AttributeKind::Table { row_length } => Some(row_length),
        };
        let value = match attribute.kind {
            AttributeKind::Table { .. } => Vec::new(),
            AttributeKind::Scalar { length } => {
                let configured = match (payload, attribute.create) {
                    (Some(payload), CreateSource::Required { offset }) => {
                        Some(payload.get(offset..offset + length)?.to_vec())
                    }
                    (Some(payload), CreateSource::Optional { offset }) => {
                        payload.get(offset..offset + length).map(ToOwned::to_owned)
                    }
                    _ => None,
                };
                configured.unwrap_or_else(|| {
                    if attribute.default.is_empty() {
                        vec![0; length]
                    } else {
                        attribute.default.to_vec()
                    }
                })
            }
        };
        entity.attributes.insert(
            attribute.index,
            Attribute {
                value,
                writable: attribute.access == AttributeAccess::ReadWrite,
                table_row_len,
                table_rows: BTreeMap::new(),
                upload: attribute.upload,
            },
        );
    }
    Some(entity)
}

fn priority_queue_entity(related_port: u16, priority: u16) -> ManagedEntity {
    let mut related = Vec::with_capacity(4);
    related.extend_from_slice(&related_port.to_be_bytes());
    related.extend_from_slice(&priority.to_be_bytes());

    ManagedEntity::default()
        .read_only(1, vec![1])
        .read_only(2, 0xffffu16.to_be_bytes().to_vec())
        .read_write(3, 4u16.to_be_bytes().to_vec())
        .read_write(6, related)
        .read_write(7, 0u16.to_be_bytes().to_vec())
        .read_write(8, vec![1])
        .read_write(9, 0u16.to_be_bytes().to_vec())
        .read_write(10, 0u32.to_be_bytes().to_vec())
        .read_write(11, 0xffffu16.to_be_bytes().to_vec())
        .read_write(12, 0u16.to_be_bytes().to_vec())
}

fn mac_bridge_port_filter_preassign_entity() -> ManagedEntity {
    entity_from_definition(CLASS_MAC_BRIDGE_PORT_FILTER_PREASSIGN_DATA, None)
        .expect("filter preassign schema is registered")
}

fn omci_capability_entity(enhanced_security: bool) -> ManagedEntity {
    let mut entity = entity_from_definition(CLASS_OMCI, None).expect("OMCI schema is registered");
    let class_table = entity.attributes.get_mut(&1).expect("OMCI class table");
    /*
     * Class 351 lies in the vendor-specific range 350..399. Huawei OLTs create it without
     * checking this table; advertising it could invite another vendor's layout.
     */
    for definition in schema::MANAGED_ENTITIES.iter().filter(|definition| {
        (enhanced_security || definition.class_id != CLASS_ENHANCED_SECURITY_CONTROL)
            && definition.class_id != CLASS_VENDOR_351
    }) {
        let row = definition.class_id.to_be_bytes().to_vec();
        class_table.table_rows.insert(row.clone(), row);
    }

    let message_table = entity.attributes.get_mut(&2).expect("OMCI message table");
    for action in 0..32u8 {
        if schema::MANAGED_ENTITIES
            .iter()
            .any(|definition| definition.supports_action(action))
        {
            message_table.table_rows.insert(vec![action], vec![action]);
        }
    }
    entity
}

#[derive(Clone, Debug)]
pub struct Mib {
    entities: BTreeMap<(u16, u16), ManagedEntity>,
    autonomous_defaults: BTreeMap<(u16, u16), ManagedEntity>,
    known_classes: BTreeSet<u16>,
    olt_created: BTreeSet<(u16, u16)>,
    dynamic_classes: BTreeSet<u16>,
    table_snapshot: Option<TableSnapshot>,
    upload_snapshot: Vec<UploadRecord>,
    onu_serial: [u8; 8],
    pending_master_session_key: Option<[u8; 16]>,
    attribute_value_changes: Vec<AttributeValueChange>,
    enhanced_security: bool,
}

#[derive(Clone, Debug)]
struct TableSnapshot {
    class_id: u16,
    entity_id: u16,
    attribute_mask: u16,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct UploadRecord {
    class_id: u16,
    entity_id: u16,
    attribute_mask: u16,
    values: Vec<u8>,
}

impl Mib {
    #[cfg(test)]
    pub fn from_identity(identity: &IdentityConfig) -> Self {
        Self::from_identity_with_mac(identity, None)
    }

    pub fn from_identity_with_mac(identity: &IdentityConfig, host_mac: Option<[u8; 6]>) -> Self {
        let onu_serial: [u8; 8] = identity
            .onu_g_serial()
            .try_into()
            .expect("onu_g_serial always returns eight bytes");
        let mut mib = Self {
            entities: BTreeMap::new(),
            autonomous_defaults: BTreeMap::new(),
            known_classes: BTreeSet::new(),
            olt_created: BTreeSet::new(),
            dynamic_classes: BTreeSet::new(),
            table_snapshot: None,
            upload_snapshot: Vec::new(),
            onu_serial,
            pending_master_session_key: None,
            attribute_value_changes: Vec::new(),
            enhanced_security: !identity.disable_enhanced_security,
        };

        let onu_data = ManagedEntity::default().read_write(1, vec![0]);
        mib.insert(CLASS_ONU_DATA, 0, onu_data);

        // Software image 0 is active; image 1 is the valid standby slot.
        let image_version = fixed_width(&identity.software_version, 14);
        mib.insert(
            CLASS_SOFTWARE_IMAGE,
            0,
            ManagedEntity::default()
                .read_only(1, image_version.clone())
                .read_only(2, vec![1])
                .read_only(3, vec![1])
                .read_only(4, vec![1]),
        );
        mib.insert(
            CLASS_SOFTWARE_IMAGE,
            1,
            ManagedEntity::default()
                .read_only(1, image_version)
                .read_only(2, vec![0])
                .read_only(3, vec![0])
                .read_only(4, vec![1]),
        );

        let onu_g = ManagedEntity::default()
            .read_only(1, fixed_width(&identity.vendor_id, 4))
            .read_only(2, fixed_width(&identity.hardware_version, 14))
            .read_only(3, onu_serial.to_vec())
            // Option 2 advertises priority-controlled scheduling with rate-controlled shaping.
            .read_only(4, vec![0x02])
            .read_only(5, vec![0])
            .read_write(6, vec![0])
            .read_write(7, vec![0])
            .read_only(8, vec![0])
            .read_only(9, vec![0])
            .read_only(10, fixed_width(&identity.loid, 24))
            .read_only(11, fixed_width(&identity.loid_password, 12))
            .read_write(12, vec![0])
            .read_only(13, vec![0]);
        mib.insert(CLASS_ONU_G, 0, onu_g);

        // ONU2-G capabilities mirror the autonomous T-CONT, queue, and GEM capacity below.
        let onu2_g = ManagedEntity::default()
            .read_only(1, fixed_width(&identity.equipment_id, 20))
            .read_only(2, vec![identity.omcc_version])
            .read_only(3, vec![0, 0])
            .read_only(4, vec![1])
            .read_write(5, vec![1])
            .read_only(6, TOTAL_PRIORITY_QUEUE_COUNT.to_be_bytes().to_vec())
            .read_only(7, vec![TCONT_COUNT as u8])
            .read_only(8, vec![1])
            .read_only(9, TOTAL_GEM_PORT_COUNT.to_be_bytes().to_vec())
            .read_only(10, vec![0; 4])
            .read_only(11, vec![0, 0])
            .read_write(12, vec![0])
            // Airoha traffic management options occupy the low six bits.
            .read_only(13, 0x003fu16.to_be_bytes().to_vec())
            .read_write(14, 1u16.to_be_bytes().to_vec());
        mib.insert(CLASS_ONU2_G, 0, onu2_g);

        // Class 11 entity IDs 1 through 4 represent the four Ethernet UNIs.
        for entity_id in 1..=ETHERNET_UNI_COUNT {
            mib.insert(
                CLASS_PPTP_ETHERNET_UNI,
                entity_id,
                ManagedEntity::default()
                    .read_write(1, vec![0x2f])
                    .read_only(2, vec![0x2f])
                    .read_write(3, vec![0])
                    .read_write(4, vec![0])
                    .read_write(5, vec![0])
                    .read_only(6, vec![1])
                    .read_only(7, vec![0])
                    .read_write(8, 0x05eeu16.to_be_bytes().to_vec())
                    .read_write(9, vec![0])
                    .read_write(10, 0u16.to_be_bytes().to_vec())
                    .read_write(11, vec![0])
                    .read_write(12, vec![0])
                    .read_write(13, vec![0])
                    .read_write(14, vec![0])
                    .read_write(15, vec![0]),
            );
        }

        // ONU power shedding is an autonomous singleton with zeroed timers.
        mib.insert(
            CLASS_ONU_POWER_SHEDDING,
            0,
            ManagedEntity::default()
                .read_write(1, 0u16.to_be_bytes().to_vec())
                .read_write(2, 0u16.to_be_bytes().to_vec())
                .read_write(4, 0u16.to_be_bytes().to_vec())
                .read_write(5, 0u16.to_be_bytes().to_vec())
                .read_write(6, 0u16.to_be_bytes().to_vec())
                .read_write(7, 0u16.to_be_bytes().to_vec())
                .read_write(8, 0u16.to_be_bytes().to_vec())
                .read_write(9, 0u16.to_be_bytes().to_vec())
                .read_write(10, 0u16.to_be_bytes().to_vec())
                .read_write(11, 0u16.to_be_bytes().to_vec())
                .read_only(12, vec![0]),
        );

        let ctc_auth = ManagedEntity::default()
            .read_only(1, fixed_width(&identity.operator_id, 4))
            .read_only(2, fixed_width(&identity.loid, 24))
            .read_only(3, fixed_width(&identity.loid_password, 12))
            .read_write(4, vec![0]);
        mib.insert(CLASS_CTC_LOID_AUTH, 0, ctc_auth);

        if !identity.disable_enhanced_security {
            /* Class 332 negotiates cryptographic capabilities and key length for each O5 epoch. */
            mib.insert(
                CLASS_ENHANCED_SECURITY_CONTROL,
                0,
                ManagedEntity::default()
                    .read_write(1, vec![0; 16])
                    .table(2, 17)
                    .read_write(3, vec![0])
                    .read_only(4, vec![1])
                    .read_only_table(5, 16)
                    .read_only_table(6, 16)
                    .table(7, 17)
                    .read_write(8, vec![0])
                    .read_only(9, vec![0])
                    .read_only(10, vec![0; 16])
                    .table(11, 18)
                    .read_only(12, 128u16.to_be_bytes().to_vec()),
            );
        }

        // Airoha OMCI maps the 16 onboard T-CONTs to entity IDs 0x8000..0x800f.
        // XG-PON represents an unassigned Alloc-ID as 0xffff.
        for offset in 0..TCONT_COUNT {
            mib.insert(
                CLASS_TCONT,
                TCONT_FIRST_ENTITY + offset,
                ManagedEntity::default()
                    .read_write(1, 0xffffu16.to_be_bytes().to_vec())
                    .read_only(2, vec![1])
                    .read_write(3, vec![0]),
            );
        }

        // Each T-CONT and Ethernet UNI owns eight priority queues.
        for offset in 0..UPSTREAM_PRIORITY_QUEUE_COUNT {
            let entity_id = TCONT_FIRST_ENTITY + offset;
            let tcont_id = TCONT_FIRST_ENTITY + offset / QUEUES_PER_TCONT;
            let priority = 7 - (offset % QUEUES_PER_TCONT);
            mib.insert(
                CLASS_PRIORITY_QUEUE,
                entity_id,
                priority_queue_entity(tcont_id, priority),
            );
        }
        for offset in 0..DOWNSTREAM_PRIORITY_QUEUE_COUNT {
            let entity_id = offset;
            let uni_id = 1 + offset / QUEUES_PER_UNI;
            let priority = offset % QUEUES_PER_UNI;
            mib.insert(
                CLASS_PRIORITY_QUEUE,
                entity_id,
                priority_queue_entity(0x0100 + uni_id, priority),
            );
        }
        for offset in 0..TCONT_COUNT {
            let entity_id = TCONT_FIRST_ENTITY + offset;
            mib.insert(
                CLASS_TRAFFIC_SCHEDULER,
                entity_id,
                ManagedEntity::default()
                    .read_write(1, entity_id.to_be_bytes().to_vec())
                    .read_only(2, 0u16.to_be_bytes().to_vec())
                    .read_write(3, vec![1])
                    .read_write(4, vec![0]),
            );
        }

        // Airoha VEIP_SLOT and VEIP_INST_ID combine into entity ID 0x0a01.
        mib.insert(
            CLASS_VEIP,
            VEIP_ENTITY,
            ManagedEntity::default()
                .read_write(1, vec![0])
                .read_only(2, vec![0])
                .read_write(3, vec![0; 25])
                .read_write(4, 0xffffu16.to_be_bytes().to_vec())
                .read_only(5, vec![0, 0]),
        );

        mib.insert(
            CLASS_OLT_G,
            0,
            entity_from_definition(CLASS_OLT_G, None).expect("OLT-G schema is registered"),
        );

        for entity_id in 1..=ETHERNET_UNI_COUNT {
            mib.insert(
                CLASS_UNI_G,
                entity_id,
                entity_from_definition(CLASS_UNI_G, None).expect("UNI-G schema is registered"),
            );
        }

        mib.insert(
            CLASS_OMCI,
            0,
            omci_capability_entity(!identity.disable_enhanced_security),
        );

        let mac = host_mac.unwrap_or([
            0x02,
            onu_serial[4],
            onu_serial[5],
            onu_serial[6],
            onu_serial[7],
            0x01,
        ]);
        let mut ip_host = entity_from_definition(CLASS_IP_HOST_CONFIG_DATA, None)
            .expect("IP host config schema is registered");
        if let Some(attr) = ip_host.attributes.get_mut(&2) {
            attr.value = mac.to_vec();
        }
        mib.insert(CLASS_IP_HOST_CONFIG_DATA, IP_HOST_DEFAULT_ENTITY, ip_host);

        let mut ipv6_host = entity_from_definition(CLASS_IPV6_HOST_CONFIG_DATA, None)
            .expect("IPv6 host config schema is registered");
        if let Some(attr) = ipv6_host.attributes.get_mut(&2) {
            attr.value = mac.to_vec();
        }
        if let Some(attr) = ipv6_host.attributes.get_mut(&4) {
            attr.value = eui64_link_local(&mac).to_vec();
        }
        mib.insert(
            CLASS_IPV6_HOST_CONFIG_DATA,
            IPV6_HOST_DEFAULT_ENTITY,
            ipv6_host,
        );

        mib.insert(
            CLASS_TR069_MANAGEMENT_SERVER,
            TR069_SERVER_DEFAULT_ENTITY,
            entity_from_definition(CLASS_TR069_MANAGEMENT_SERVER, None)
                .expect("TR-069 management server schema is registered"),
        );

        for definition in schema::MANAGED_ENTITIES {
            mib.known_classes.insert(definition.class_id);
            if definition.origin == ManagedEntityOrigin::Olt {
                mib.dynamic_classes.insert(definition.class_id);
            }
        }

        // The MIB Reset template preserves initial attributes of autonomous entities.
        mib.autonomous_defaults = mib.entities.clone();
        mib
    }

    fn insert(&mut self, class_id: u16, entity_id: u16, entity: ManagedEntity) {
        self.known_classes.insert(class_id);
        self.entities.insert((class_id, entity_id), entity);
    }

    pub fn dispatch(&mut self, request: &Request<'_>) -> Response {
        if request.class_id == CLASS_ENHANCED_SECURITY_CONTROL && !self.enhanced_security {
            /* The disabled class is absent from the MIB and the OMCI class table, so it is an unknown ME. */
            return Response::new(request, RESULT_UNKNOWN_ME);
        }
        let Some(definition) = schema::managed_entity(request.class_id) else {
            return Response::new(request, RESULT_UNKNOWN_ME);
        };
        debug_assert!(!definition.name.is_empty());
        if !definition.supports_action(request.action) {
            return Response::new(request, RESULT_COMMAND_NOT_SUPPORTED);
        }

        match request.action {
            ACTION_CREATE => self.handle_create(request),
            ACTION_DELETE => self.handle_delete(request),
            ACTION_GET | ACTION_GET_CURRENT_DATA => self.handle_get(request),
            ACTION_GET_ALL_ALARMS => self.handle_get_all_alarms(request),
            ACTION_GET_ALL_ALARMS_NEXT => self.handle_get_all_alarms_next(request),
            ACTION_GET_NEXT => self.handle_get_next(request),
            ACTION_SET => self.handle_set(request),
            ACTION_SET_TABLE => self.handle_set_table(request),
            ACTION_MIB_UPLOAD => self.handle_mib_upload(request),
            ACTION_MIB_UPLOAD_NEXT => self.handle_mib_upload_next(request),
            ACTION_MIB_RESET => self.handle_mib_reset(request),
            ACTION_SYNCHRONIZE_TIME => self.handle_synchronize_time(request),
            _ => Response::new(request, RESULT_COMMAND_NOT_SUPPORTED),
        }
    }

    fn entity_error(&self, request: &Request<'_>) -> Response {
        let result = if self.known_classes.contains(&request.class_id) {
            RESULT_UNKNOWN_INSTANCE
        } else {
            RESULT_UNKNOWN_ME
        };
        Response::new(request, result)
    }

    fn handle_create(&mut self, request: &Request<'_>) -> Response {
        if !self.dynamic_classes.contains(&request.class_id) {
            return if self.known_classes.contains(&request.class_id) {
                Response::new(request, RESULT_COMMAND_NOT_SUPPORTED)
            } else {
                Response::new(request, RESULT_UNKNOWN_ME)
            };
        }
        let Some(entity) = Self::dynamic_entity(request.class_id, request.payload) else {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        };
        if let Some(existing) = self.entities.get(&(request.class_id, request.entity_id)) {
            /* Repeated Create requests recover a lost response; identical content reuses the instance and MIB Data Sync value. */
            let result = if existing == &entity {
                RESULT_SUCCESS
            } else {
                RESULT_INSTANCE_EXISTS
            };
            return Response::new(request, result);
        }
        self.insert(request.class_id, request.entity_id, entity);
        if request.class_id == CLASS_MAC_BRIDGE_PORT_CONFIG_DATA {
            /* Creating Class 47 also creates the same Class 79 entity used by the following filter policy Set. */
            self.insert(
                CLASS_MAC_BRIDGE_PORT_FILTER_PREASSIGN_DATA,
                request.entity_id,
                mac_bridge_port_filter_preassign_entity(),
            );
        }
        self.olt_created
            .insert((request.class_id, request.entity_id));
        self.increment_mib_sync();
        Response::new(request, RESULT_SUCCESS)
    }

    fn handle_delete(&mut self, request: &Request<'_>) -> Response {
        let key = (request.class_id, request.entity_id);
        if !self.entities.contains_key(&key) {
            return self.entity_error(request);
        }
        if !self.olt_created.remove(&key) {
            return Response::new(request, RESULT_COMMAND_NOT_SUPPORTED);
        }
        self.entities.remove(&key);
        if request.class_id == CLASS_MAC_BRIDGE_PORT_CONFIG_DATA {
            self.entities.remove(&(
                CLASS_MAC_BRIDGE_PORT_FILTER_PREASSIGN_DATA,
                request.entity_id,
            ));
        }
        self.increment_mib_sync();
        Response::new(request, RESULT_SUCCESS)
    }

    fn dynamic_entity(class_id: u16, payload: &[u8]) -> Option<ManagedEntity> {
        let definition = schema::managed_entity(class_id)?;
        (definition.origin == ManagedEntityOrigin::Olt)
            .then(|| entity_from_definition(class_id, Some(payload)))?
    }

    fn handle_get_next(&self, request: &Request<'_>) -> Response {
        let Some(snapshot) = self.table_snapshot.as_ref() else {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        };
        if snapshot.class_id != request.class_id
            || snapshot.entity_id != request.entity_id
            || snapshot.attribute_mask != request.attribute_mask
        {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        }

        let sequence = u16::from_be_bytes([request.content[0], request.content[1]]) as usize;
        let capacity = request.get_next_value_capacity();
        let start = sequence * capacity;
        if start >= snapshot.bytes.len() && !snapshot.bytes.is_empty() {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        }
        let end = (start + capacity).min(snapshot.bytes.len());
        Response::get_next_success(
            request,
            snapshot.attribute_mask,
            &snapshot.bytes[start..end],
        )
        .expect("table chunk is bounded by baseline capacity")
    }

    fn handle_mib_upload(&mut self, request: &Request<'_>) -> Response {
        if request.class_id != CLASS_ONU_DATA || request.entity_id != 0 {
            return self.entity_error(request);
        }
        self.rebuild_upload_snapshot();
        Response::mib_upload(request, self.upload_snapshot.len() as u16)
    }

    fn handle_get_all_alarms(&self, request: &Request<'_>) -> Response {
        Response::get_all_alarms(request, 0)
    }

    fn handle_get_all_alarms_next(&self, request: &Request<'_>) -> Response {
        Response::get_all_alarms_next_empty(request)
    }

    fn handle_mib_upload_next(&self, request: &Request<'_>) -> Response {
        if request.class_id != CLASS_ONU_DATA || request.entity_id != 0 {
            return self.entity_error(request);
        }
        let sequence = request.attribute_mask as usize;
        let Some(record) = self.upload_snapshot.get(sequence) else {
            return Response::mib_upload_next(request, 0, 0, 0, &[])
                .expect("empty upload record always fits");
        };
        Response::mib_upload_next(
            request,
            record.class_id,
            record.entity_id,
            record.attribute_mask,
            &record.values,
        )
        .expect("upload records are split to baseline capacity")
    }

    fn rebuild_upload_snapshot(&mut self) {
        let mut records = Vec::new();
        for (&(class_id, entity_id), entity) in &self.entities {
            // CTC requires LOID authentication attributes to be read with GET, not MIB Upload.
            if class_id == CLASS_CTC_LOID_AUTH {
                continue;
            }
            let mut mask = 0u16;
            let mut values = Vec::new();
            for (&index, attribute) in &entity.attributes {
                // MIB Upload carries persistent scalar state; PM counters and tables use GET.
                if !attribute.upload || attribute.table_row_len.is_some() {
                    continue;
                }
                let bit = attribute_bit(index).expect("stored attribute index is valid");
                if !values.is_empty() && values.len() + attribute.value.len() > 26 {
                    records.push(UploadRecord {
                        class_id,
                        entity_id,
                        attribute_mask: mask,
                        values,
                    });
                    mask = 0;
                    values = Vec::new();
                }
                if attribute.value.len() <= 26 {
                    mask |= bit;
                    values.extend_from_slice(&attribute.value);
                }
            }
            if mask != 0 {
                records.push(UploadRecord {
                    class_id,
                    entity_id,
                    attribute_mask: mask,
                    values,
                });
            }
        }
        self.upload_snapshot = records;
    }

    fn handle_get(&mut self, request: &Request<'_>) -> Response {
        let Some(entity) = self.entities.get(&(request.class_id, request.entity_id)) else {
            return self.entity_error(request);
        };
        if request.attribute_mask == 0 {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        }

        let mut returned_mask = 0u16;
        let mut values = Vec::new();
        let mut table = None;
        for index in 1..=16 {
            let bit = attribute_bit(index).expect("1..=16 always has an attribute bit");
            if request.attribute_mask & bit == 0 {
                continue;
            }
            let Some(attribute) = entity.attributes.get(&index) else {
                return Response::new(request, RESULT_ATTRIBUTE_FAILED);
            };
            if attribute.table_row_len.is_some() {
                if request.attribute_mask.count_ones() != 1 {
                    return Response::new(request, RESULT_PARAMETER_ERROR);
                }
                let bytes = attribute
                    .table_rows
                    .values()
                    .flat_map(|row| row.iter().copied())
                    .collect::<Vec<_>>();
                values.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                table = Some(TableSnapshot {
                    class_id: request.class_id,
                    entity_id: request.entity_id,
                    attribute_mask: bit,
                    bytes,
                });
                returned_mask |= bit;
                continue;
            }
            if values.len() + attribute.value.len() > request.get_value_capacity() {
                return Response::new(request, RESULT_PARAMETER_ERROR);
            }
            returned_mask |= bit;
            values.extend_from_slice(&attribute.value);
        }

        self.table_snapshot = table;
        Response::get_success(request, returned_mask, &values)
            .expect("capacity was checked before response construction")
    }

    fn handle_set(&mut self, request: &Request<'_>) -> Response {
        let class_known = self.known_classes.contains(&request.class_id);
        let Some(entity) = self
            .entities
            .get_mut(&(request.class_id, request.entity_id))
        else {
            return Response::new(
                request,
                if class_known {
                    RESULT_UNKNOWN_INSTANCE
                } else {
                    RESULT_UNKNOWN_ME
                },
            );
        };
        if request.attribute_mask == 0 {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        }

        // Validate every attribute and length before applying the Set atomically.
        let mut cursor = 0usize;
        let mut updates = Vec::<(u8, Vec<u8>, bool)>::new();
        for index in 1..=16 {
            let bit = attribute_bit(index).expect("1..=16 always has an attribute bit");
            if request.attribute_mask & bit == 0 {
                continue;
            }
            let Some(attribute) = entity.attributes.get(&index) else {
                return Response::new(request, RESULT_ATTRIBUTE_FAILED);
            };
            if !attribute.writable {
                return Response::new(request, RESULT_ATTRIBUTE_FAILED);
            }
            let length = attribute.table_row_len.unwrap_or(attribute.value.len());
            if attribute.table_row_len.is_some() && request.attribute_mask.count_ones() != 1 {
                return Response::new(request, RESULT_PARAMETER_ERROR);
            }
            let end = cursor + length;
            if end > request.content.len() {
                return Response::new(request, RESULT_PARAMETER_ERROR);
            }
            updates.push((
                index,
                request.content[cursor..end].to_vec(),
                attribute.table_row_len.is_some(),
            ));
            cursor = end;
        }

        if request.class_id == CLASS_ENHANCED_SECURITY_CONTROL && request.entity_id == 0 {
            if self.apply_enhanced_security_updates(&updates).is_err() {
                return Response::new(request, RESULT_ATTRIBUTE_FAILED);
            }
            self.increment_mib_sync();
            return Response::set_success(request);
        }

        for (index, value, is_table) in updates {
            let attribute = entity
                .attributes
                .get_mut(&index)
                .expect("attribute was validated above");
            if is_table {
                let key = value[..8].to_vec();
                if value[8..].iter().all(|byte| *byte == 0xff) {
                    attribute.table_rows.remove(&key);
                } else {
                    attribute.table_rows.insert(key, value);
                }
            } else {
                attribute.value = value;
            }
        }
        self.increment_mib_sync();
        Response::set_success(request)
    }

    fn apply_enhanced_security_updates(
        &mut self,
        updates: &[(u8, Vec<u8>, bool)],
    ) -> Result<(), ()> {
        let mut run_step1 = false;
        let mut run_step2 = false;
        let entity = self
            .entities
            .get_mut(&(CLASS_ENHANCED_SECURITY_CONTROL, 0))
            .ok_or(())?;

        for (index, value, is_table) in updates {
            match (*index, *is_table) {
                (2 | 7, true) => {
                    /*
                     * Class 332 challenge rows use the first byte as their key, and
                     * row zero clears the table. Rewriting a key replaces its row.
                     */
                    let attribute = entity.attributes.get_mut(index).ok_or(())?;
                    if value[0] == 0 {
                        attribute.table_rows.clear();
                    } else {
                        attribute.table_rows.insert(vec![value[0]], value.clone());
                    }
                    let status_index = if *index == 2 { 3 } else { 8 };
                    entity.attributes.get_mut(&status_index).ok_or(())?.value[0] = 0;
                }
                (1, false) => {
                    entity.attributes.get_mut(index).ok_or(())?.value = value.clone();
                    entity.attributes.get_mut(&3).ok_or(())?.value[0] = 0;
                }
                (11, true) => {
                    /*
                     * Broadcast key rows are keyed by the row identifier (key index
                     * and fragment number). Row control bits 2..1 select set row,
                     * clear row, or clear table.
                     */
                    let attribute = entity.attributes.get_mut(index).ok_or(())?;
                    match value[0] & 0x03 {
                        0 => {
                            attribute.table_rows.insert(vec![value[1]], value.clone());
                        }
                        1 => {
                            attribute.table_rows.remove(&[value[1]][..]);
                        }
                        2 => attribute.table_rows.clear(),
                        _ => return Err(()),
                    }
                }
                (3 | 8, false) if value[0] <= 1 => {
                    let attribute = entity.attributes.get_mut(index).ok_or(())?;
                    let rising_edge = attribute.value[0] == 0 && value[0] == 1;
                    attribute.value[0] = value[0];
                    run_step1 |= *index == 3 && rising_edge;
                    run_step2 |= *index == 8 && rising_edge;
                }
                _ => return Err(()),
            }
        }

        if run_step1 {
            self.enhanced_security_step1()?;
        }
        if run_step2 {
            self.enhanced_security_step2()?;
        }
        Ok(())
    }

    fn enhanced_security_step1(&mut self) -> Result<(), ()> {
        let olt_challenges = self.enhanced_security_challenges(2, true)?;
        let mut onu_challenges = Vec::with_capacity(olt_challenges.len());

        for olt_challenge in &olt_challenges {
            let mut random = [0u8; 16];
            security::fill_random(&mut random).map_err(|_| ())?;
            onu_challenges.push(security::onu_random_challenge(olt_challenge, &random));
        }
        let authentication_result =
            security::authentication_result(&olt_challenges, &onu_challenges, &[0; 8], true)
                .ok_or(())?;

        let entity = self
            .entities
            .get_mut(&(CLASS_ENHANCED_SECURITY_CONTROL, 0))
            .ok_or(())?;
        let onu_table = entity.attributes.get_mut(&5).ok_or(())?;
        onu_table.table_rows.clear();
        for (index, challenge) in onu_challenges.iter().enumerate() {
            onu_table
                .table_rows
                .insert(vec![(index + 1) as u8], challenge.to_vec());
        }
        let result_table = entity.attributes.get_mut(&6).ok_or(())?;
        result_table.table_rows.clear();
        result_table
            .table_rows
            .insert(vec![1], authentication_result.to_vec());

        self.queue_table_avc(5, onu_challenges.len() * 16);
        self.queue_table_avc(6, 16);
        Ok(())
    }

    fn enhanced_security_step2(&mut self) -> Result<(), ()> {
        let olt_challenges = self.enhanced_security_challenges(2, true)?;
        let onu_challenges = self.enhanced_security_challenges(5, false)?;
        let expected = security::authentication_result(
            &olt_challenges,
            &onu_challenges,
            &self.onu_serial,
            false,
        )
        .ok_or(())?;
        let received = self
            .entities
            .get(&(CLASS_ENHANCED_SECURITY_CONTROL, 0))
            .and_then(|entity| entity.attributes.get(&7))
            .and_then(|attribute| attribute.table_rows.values().next())
            .and_then(|row| row.get(1..17));

        if received != Some(expected.as_slice()) {
            self.set_enhanced_authentication_state(4);
            return Ok(());
        }

        let name = security::master_session_key_name(&olt_challenges, &onu_challenges).ok_or(())?;
        let msk = security::master_session_key(&olt_challenges, &onu_challenges).ok_or(())?;
        self.entities
            .get_mut(&(CLASS_ENHANCED_SECURITY_CONTROL, 0))
            .and_then(|entity| entity.attributes.get_mut(&10))
            .ok_or(())?
            .value = name.to_vec();
        /* State 3 is published after the driver installs the OIK. */
        self.pending_master_session_key = Some(msk);
        Ok(())
    }

    fn enhanced_security_challenges(
        &self,
        attribute_index: u8,
        indexed: bool,
    ) -> Result<Vec<[u8; 16]>, ()> {
        let attribute = self
            .entities
            .get(&(CLASS_ENHANCED_SECURITY_CONTROL, 0))
            .and_then(|entity| entity.attributes.get(&attribute_index))
            .ok_or(())?;
        let mut challenges = Vec::with_capacity(attribute.table_rows.len());
        for row in attribute.table_rows.values() {
            let bytes = if indexed {
                row.get(1..17)
            } else {
                row.get(0..16)
            }
            .ok_or(())?;
            challenges.push(bytes.try_into().map_err(|_| ())?);
        }
        if challenges.is_empty() {
            return Err(());
        }
        Ok(challenges)
    }

    fn queue_table_avc(&mut self, attribute_index: u8, byte_length: usize) {
        self.queue_avc(attribute_index, (byte_length as u32).to_be_bytes().to_vec());
    }

    fn queue_avc(&mut self, attribute_index: u8, value: Vec<u8>) {
        self.attribute_value_changes.push(AttributeValueChange {
            class_id: CLASS_ENHANCED_SECURITY_CONTROL,
            entity_id: 0,
            attribute_mask: attribute_bit(attribute_index)
                .expect("Class 332 attribute index is valid"),
            value,
        });
    }

    fn set_enhanced_authentication_state(&mut self, state: u8) {
        if let Some(attribute) = self
            .entities
            .get_mut(&(CLASS_ENHANCED_SECURITY_CONTROL, 0))
            .and_then(|entity| entity.attributes.get_mut(&9))
        {
            attribute.value[0] = state;
        }
        self.queue_avc(9, vec![state]);
    }

    pub fn take_pending_master_session_key(&mut self) -> Option<[u8; 16]> {
        self.pending_master_session_key.take()
    }

    pub fn set_onu_serial(&mut self, serial: [u8; 8]) {
        self.onu_serial = serial;
        /* ONU-G attribute 3 and Class 332 use the same active PLOAM serial number. */
        for entities in [&mut self.entities, &mut self.autonomous_defaults] {
            if let Some(attribute) = entities
                .get_mut(&(CLASS_ONU_G, 0))
                .and_then(|entity| entity.attributes.get_mut(&3))
            {
                attribute.value = serial.to_vec();
            }
        }
    }

    pub fn complete_master_session_key_install(&mut self, installed: bool) {
        self.set_enhanced_authentication_state(if installed { 3 } else { 4 });
    }

    pub fn take_attribute_value_changes(&mut self) -> Vec<AttributeValueChange> {
        std::mem::take(&mut self.attribute_value_changes)
    }

    fn handle_set_table(&mut self, request: &Request<'_>) -> Response {
        let class_known = self.known_classes.contains(&request.class_id);
        let Some(entity) = self
            .entities
            .get_mut(&(request.class_id, request.entity_id))
        else {
            return Response::new(
                request,
                if class_known {
                    RESULT_UNKNOWN_INSTANCE
                } else {
                    RESULT_UNKNOWN_ME
                },
            );
        };
        if request.attribute_mask.count_ones() != 1 {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        }

        let index = request.attribute_mask.leading_zeros() as u8 + 1;
        let Some(attribute) = entity.attributes.get_mut(&index) else {
            return Response::new(request, RESULT_ATTRIBUTE_FAILED);
        };
        let Some(row_len) = attribute.table_row_len else {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        };
        if !attribute.writable
            || row_len < 8
            || request.content.is_empty()
            || request.content.len() % row_len != 0
        {
            return Response::new(request, RESULT_PARAMETER_ERROR);
        }

        // Set-table applies rows in wire order using each table's add/delete control field.
        for row in request.content.chunks_exact(row_len) {
            let key = row[..8].to_vec();
            if row[8..].iter().all(|byte| *byte == 0xff) {
                attribute.table_rows.remove(&key);
            } else {
                attribute.table_rows.insert(key, row.to_vec());
            }
        }
        self.increment_mib_sync();
        Response::set_success(request)
    }

    fn handle_mib_reset(&mut self, request: &Request<'_>) -> Response {
        if request.class_id != CLASS_ONU_DATA || request.entity_id != 0 {
            return self.entity_error(request);
        }
        let loid_authentication = self.entities.get(&(CLASS_CTC_LOID_AUTH, 0)).cloned();
        self.entities = self.autonomous_defaults.clone();
        // The CTC LOID Authentication ME survives MIB Reset with every attribute unchanged.
        if let Some(entity) = loid_authentication {
            self.entities.insert((CLASS_CTC_LOID_AUTH, 0), entity);
        }
        self.olt_created.clear();
        self.table_snapshot = None;
        self.upload_snapshot.clear();
        self.pending_master_session_key = None;
        self.attribute_value_changes.clear();
        Response::new(request, 0)
    }

    fn handle_synchronize_time(&self, request: &Request<'_>) -> Response {
        if request.class_id != CLASS_ONU_G || request.entity_id != 0 {
            return self.entity_error(request);
        }
        Response::synchronize_time_success(request)
    }

    fn increment_mib_sync(&mut self) {
        if let Some(sync) = self
            .entities
            .get_mut(&(CLASS_ONU_DATA, 0))
            .and_then(|entity| entity.attributes.get_mut(&1))
        {
            // G.988 MIB Data Sync cycles through 1..255; zero represents reset state.
            sync.value[0] = if sync.value[0] == 255 {
                1
            } else {
                sync.value[0] + 1
            };
        }
    }

    pub fn provisioning_snapshot(&self) -> ProvisioningSnapshot {
        let mut snapshot = ProvisioningSnapshot::default();
        let mut tcont_alloc = BTreeMap::<u16, u16>::new();
        let mut gem_id_by_entity = BTreeMap::<u16, u16>::new();
        let mut unicast_by_entity = BTreeMap::<u16, DataPathCandidate>::new();
        let mut multicast_by_iwtp = BTreeMap::<u16, DataPathCandidate>::new();
        let mut mapper_paths = BTreeMap::<(u16, u16), DataPathCandidate>::new();
        let mut bridge_paths = BTreeMap::<u16, Vec<DataPathCandidate>>::new();

        if let Some(olt) = self.entities.get(&(CLASS_OLT_G, 0)) {
            snapshot.olt_vendor_id = olt
                .attributes
                .get(&1)
                .map(|attribute| omci_text(&attribute.value))
                .unwrap_or_default();
            snapshot.olt_equipment_id = olt
                .attributes
                .get(&2)
                .map(|attribute| omci_text(&attribute.value))
                .unwrap_or_default();
            snapshot.olt_version = olt
                .attributes
                .get(&3)
                .map(|attribute| omci_text(&attribute.value))
                .unwrap_or_default();
        }

        if let Some(security) = self.entities.get(&(CLASS_ENHANCED_SECURITY_CONTROL, 0)) {
            snapshot.enhanced_security = true;
            /* Row identifier bits 7..6 carry the key index; bits 3..0 the fragment number. */
            snapshot.broadcast_key_indexes = security
                .attributes
                .get(&11)
                .map(|table| table.table_rows.keys().map(|row| row[0] >> 6).collect())
                .unwrap_or_default();
        }

        for (&(class_id, entity_id), entity) in &self.entities {
            if class_id != CLASS_TCONT {
                continue;
            }
            let Some(alloc) = entity
                .attributes
                .get(&1)
                .and_then(|attr| be_u16(&attr.value))
            else {
                continue;
            };
            if alloc != 0xffff {
                tcont_alloc.insert(entity_id, alloc);
            }
        }
        snapshot.configured_tconts = tcont_alloc.len();

        /* The GEM CTP entity ID is the pointer stored by 802.1p mapper and GEM IWTP entities. */
        for (&(class_id, entity_id), entity) in &self.entities {
            if class_id != CLASS_GEM_PORT_NETWORK_CTP {
                continue;
            }
            let gem_id = entity
                .attributes
                .get(&1)
                .and_then(|attr| be_u16(&attr.value));
            let tcont = entity
                .attributes
                .get(&2)
                .and_then(|attr| be_u16(&attr.value));
            let direction = entity
                .attributes
                .get(&3)
                .and_then(|attr| attr.value.first())
                .copied();
            if let Some(gem_id) = gem_id {
                gem_id_by_entity.insert(entity_id, gem_id);
            }
            if let (Some(gem_id), Some(tcont), Some(3)) = (gem_id, tcont, direction) {
                if let Some(&alloc_id) = tcont_alloc.get(&tcont) {
                    unicast_by_entity.insert(
                        entity_id,
                        DataPathCandidate {
                            alloc_id,
                            gem_id,
                            vlan_id: DATA_PATH_VLAN_ANY,
                            pbit_mask: 0,
                            multicast: false,
                        },
                    );
                }
            }
        }

        /*
         * Class 281 attribute 1 points to a GEM Port Network CTP. That GEM uses
         * multicast type and the downstream channel, deriving membership directly
         * from the CTP.
         */
        for (&(class_id, iwtp_id), iwtp) in &self.entities {
            if class_id != CLASS_MULTICAST_GEM_INTERWORKING_TP {
                continue;
            }
            let Some(ctp_entity) = iwtp.attributes.get(&1).and_then(|attr| be_u16(&attr.value))
            else {
                continue;
            };
            let Some(&gem_id) = gem_id_by_entity.get(&ctp_entity) else {
                continue;
            };
            multicast_by_iwtp.insert(
                iwtp_id,
                DataPathCandidate {
                    alloc_id: u16::MAX,
                    gem_id,
                    vlan_id: DATA_PATH_VLAN_ANY,
                    pbit_mask: u8::MAX,
                    multicast: true,
                },
            );
        }

        /*
         * 802.1p mapper attributes 2..9 point to GEM IWTPs for P-bits 0..7.
         * A direct GEM CTP entity ID is also a valid mapping form.
         */
        for (&(class_id, mapper_id), mapper) in &self.entities {
            if class_id != CLASS_IEEE_8021P_MAPPER {
                continue;
            }
            for pbit in 0..8u8 {
                let Some(pointer) = mapper
                    .attributes
                    .get(&(pbit + 2))
                    .and_then(|attr| be_u16(&attr.value))
                else {
                    continue;
                };
                if pointer == 0xffff {
                    continue;
                }
                let ctp_entity = self
                    .entities
                    .get(&(CLASS_GEM_INTERWORKING_TP, pointer))
                    .and_then(|entity| entity.attributes.get(&1))
                    .and_then(|attr| be_u16(&attr.value))
                    .unwrap_or(pointer);
                if let Some(path) = unicast_by_entity.get(&ctp_entity) {
                    let mapped = mapper_paths
                        .entry((mapper_id, path.gem_id))
                        .or_insert_with(|| path.clone());
                    mapped.pbit_mask |= 1 << pbit;
                }
            }
        }

        /*
         * MAC bridge TP type 3 resolves through an 802.1p mapper, type 5 through
         * GEM IWTP, and type 6 through Multicast GEM IWTP. Each path ends at a GEM CTP.
         */
        for (&(class_id, entity_id), bridge) in &self.entities {
            if class_id != CLASS_MAC_BRIDGE_PORT_CONFIG_DATA {
                continue;
            }
            let tp_type = bridge
                .attributes
                .get(&3)
                .and_then(|attr| attr.value.first())
                .copied();
            let pointer = bridge
                .attributes
                .get(&4)
                .and_then(|attr| be_u16(&attr.value));
            let Some(pointer) = pointer else {
                continue;
            };

            let paths = match tp_type {
                Some(3) => mapper_paths
                    .iter()
                    .filter(|((mapper_id, _), _)| *mapper_id == pointer)
                    .map(|(_, path)| path.clone())
                    .collect::<Vec<_>>(),
                Some(5) => self
                    .entities
                    .get(&(CLASS_GEM_INTERWORKING_TP, pointer))
                    .and_then(|entity| entity.attributes.get(&1))
                    .and_then(|attr| be_u16(&attr.value))
                    .and_then(|ctp_entity| unicast_by_entity.get(&ctp_entity))
                    .cloned()
                    .into_iter()
                    .collect::<Vec<_>>(),
                Some(6) => multicast_by_iwtp
                    .get(&pointer)
                    .cloned()
                    .into_iter()
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            };
            if !paths.is_empty() {
                bridge_paths.insert(entity_id, paths);
            }
        }

        /* A VLAN filter and the same-entity ANI bridge port select the GEM path together. */
        for (entity_id, paths) in bridge_paths {
            let Some(filter) = self.entities.get(&(CLASS_VLAN_TAGGING_FILTER, entity_id)) else {
                if let Some(mgmt_vid) = self.bridge_host_vlan_for_ani_port(entity_id) {
                    for path in &paths {
                        let mut path = path.clone();
                        path.vlan_id = mgmt_vid;
                        if path.pbit_mask == 0 {
                            path.pbit_mask = u8::MAX;
                        }
                        snapshot.data_paths.push(path);
                    }
                } else {
                    snapshot.data_paths.extend(paths);
                }
                continue;
            };
            let operation = filter
                .attributes
                .get(&2)
                .and_then(|attr| attr.value.first())
                .copied()
                .unwrap_or(0);
            let count = filter
                .attributes
                .get(&3)
                .and_then(|attr| attr.value.first())
                .copied()
                .unwrap_or(0)
                .min(12) as usize;
            let Some(list) = filter.attributes.get(&1) else {
                snapshot.data_paths.extend(paths);
                continue;
            };
            let before = snapshot.data_paths.len();
            for entry in list.value.chunks_exact(2).take(count) {
                let tci = u16::from_be_bytes([entry[0], entry[1]]);
                match operation {
                    0x03 | 0x04 | 0x0f | 0x10 | 0x16 => {
                        let vlan_id = tci & 0x0fff;
                        if !(1..=4094).contains(&vlan_id) {
                            continue;
                        }
                        for path in &paths {
                            let mut path = path.clone();
                            path.vlan_id = vlan_id;
                            if path.pbit_mask == 0 {
                                path.pbit_mask = u8::MAX;
                            }
                            snapshot.data_paths.push(path);
                        }
                    }
                    0x07 | 0x08 | 0x11 | 0x12 => {
                        let pbit = ((tci >> 13) & 7) as u8;
                        for path in &paths {
                            if path.pbit_mask == 0 || path.pbit_mask & (1 << pbit) != 0 {
                                let mut path = path.clone();
                                path.pbit_mask = 1 << pbit;
                                snapshot.data_paths.push(path);
                            }
                        }
                    }
                    _ => {}
                }
            }
            if snapshot.data_paths.len() == before {
                snapshot.data_paths.extend(paths);
            }
        }

        if !snapshot.data_paths.iter().any(|path| !path.multicast) {
            snapshot.data_paths.extend(mapper_paths.into_values());
        }
        /*
         * Class 281 activates its downstream GEM at creation time. Existing bridge
         * paths preserve concrete VIDs; DATA_PATH_VLAN_ANY represents GEM-wide delivery.
         */
        for path in multicast_by_iwtp.into_values() {
            if !snapshot
                .data_paths
                .iter()
                .any(|current| current.multicast && current.gem_id == path.gem_id)
            {
                snapshot.data_paths.push(path);
            }
        }

        for (&(class_id, _), entity) in &self.entities {
            match class_id {
                CLASS_GEM_PORT_NETWORK_CTP => {
                    snapshot.gem_ports += 1;
                }
                CLASS_GEM_INTERWORKING_TP | CLASS_MULTICAST_GEM_INTERWORKING_TP => {
                    snapshot.gem_interworking_tps += 1;
                }
                CLASS_EXTENDED_VLAN_TAGGING => {
                    if let Some(table) = entity.attributes.get(&6) {
                        snapshot.vlan_rules += table.table_rows.len();
                        for row in table.table_rows.values() {
                            collect_extended_vlan_ids(row, &mut snapshot.vlan_ids);
                        }
                    }
                }
                CLASS_VLAN_TAGGING_FILTER => {
                    let count = entity
                        .attributes
                        .get(&3)
                        .and_then(|attr| attr.value.first())
                        .copied()
                        .unwrap_or(0)
                        .min(12) as usize;
                    snapshot.vlan_rules += count;
                }
                _ => {}
            }
        }
        snapshot.data_paths.sort_by_key(|path| {
            (
                path.multicast,
                path.vlan_id,
                path.alloc_id,
                path.gem_id,
                path.pbit_mask,
            )
        });
        snapshot.data_paths.dedup();
        /*
         * A VLAN Tagging Filter gains its role from the associated MAC bridge port.
         * The resolved GEM or Class 281 reference classifies unicast and multicast VLANs.
         */
        for path in &snapshot.data_paths {
            if !(1..=4094).contains(&path.vlan_id) {
                continue;
            }
            if path.multicast {
                snapshot.multicast_vlan_ids.insert(path.vlan_id);
            } else {
                snapshot.vlan_ids.insert(path.vlan_id);
            }
        }

        /*
         * Class 309 becomes active for a UNI through a Class 310 reference. ACL rows
         * describe downstream GEM, VLAN, and group ranges; upstream TCI and tag control
         * describe Report/Leave tagging on the unicast GEM.
         */
        for (&(class_id, _), subscriber) in &self.entities {
            if class_id != CLASS_MULTICAST_SUBSCRIBER_CONFIG {
                continue;
            }
            let Some(profile_id) = subscriber
                .attributes
                .get(&2)
                .and_then(|attr| be_u16(&attr.value))
            else {
                continue;
            };
            let Some(profile) = self
                .entities
                .get(&(CLASS_MULTICAST_OPERATIONS_PROFILE, profile_id))
            else {
                continue;
            };
            for index in [7u8, 8] {
                let Some(table) = profile.attributes.get(&index) else {
                    continue;
                };
                for row in table.table_rows.values() {
                    collect_multicast_acl_vlan_id(row, &mut snapshot.multicast_vlan_ids);
                }
            }
            let Some(tag_control) = profile
                .attributes
                .get(&5)
                .and_then(|attr| attr.value.first())
                .copied()
            else {
                continue;
            };
            if tag_control > 3 {
                continue;
            }
            snapshot.igmp_upstream_tag_controls.insert(tag_control);
            if tag_control == 0 {
                continue;
            }
            let Some(tci) = profile
                .attributes
                .get(&4)
                .and_then(|attr| be_u16(&attr.value))
            else {
                continue;
            };
            let vlan_id = tci & 0x0fff;
            if (1..=4094).contains(&vlan_id) {
                snapshot.igmp_upstream_vlan_ids.insert(vlan_id);
            }
        }
        snapshot
    }

    /// Export OMCI entities that determine GEM classification in MIB wire byte order.
    pub fn data_path_graph(&self) -> DataPathGraph {
        const GRAPH_CLASSES: [u16; 10] = [
            CLASS_MAC_BRIDGE_PORT_CONFIG_DATA,
            CLASS_VLAN_TAGGING_FILTER,
            CLASS_IEEE_8021P_MAPPER,
            CLASS_EXTENDED_VLAN_TAGGING,
            CLASS_GEM_INTERWORKING_TP,
            CLASS_MULTICAST_GEM_INTERWORKING_TP,
            CLASS_MULTICAST_OPERATIONS_PROFILE,
            CLASS_MULTICAST_SUBSCRIBER_CONFIG,
            CLASS_GEM_PORT_NETWORK_CTP,
            CLASS_TRAFFIC_DESCRIPTOR,
        ];

        let mut graph = DataPathGraph {
            candidates: self.provisioning_snapshot().data_paths,
            entities: Vec::new(),
        };
        for (&(class_id, entity_id), entity) in &self.entities {
            if !GRAPH_CLASSES.contains(&class_id) {
                continue;
            }
            let mut attributes = Vec::with_capacity(entity.attributes.len());
            for (&index, attribute) in &entity.attributes {
                let table_rows = attribute
                    .table_rows
                    .iter()
                    .map(|(key, value)| DataPathTableRow {
                        key: key.clone(),
                        value: value.clone(),
                    })
                    .collect();
                attributes.push(DataPathAttribute {
                    index,
                    value: attribute.value.clone(),
                    table_rows,
                });
            }
            graph.entities.push(DataPathEntity {
                class_id,
                entity_id,
                attributes,
            });
        }
        graph
    }

    pub fn tr069_snapshot(&self) -> Tr069ProvisioningSnapshot {
        let mut ipv4_hosts = Vec::new();
        for (&(class_id, entity_id), entity) in &self.entities {
            if class_id != CLASS_IP_HOST_CONFIG_DATA {
                continue;
            }
            ipv4_hosts.push(Ipv4HostSnapshot {
                entity_id,
                mac_address: attr_mac(entity, 2),
                ip_options: attr_u8(entity, 1),
                ip_address: attr_ipv4(entity, 4),
                mask: attr_ipv4(entity, 5),
                gateway: attr_ipv4(entity, 6),
                primary_dns: attr_ipv4(entity, 7),
                secondary_dns: attr_ipv4(entity, 8),
                current_address: attr_ipv4(entity, 9),
                current_mask: attr_ipv4(entity, 10),
                current_gateway: attr_ipv4(entity, 11),
                current_primary_dns: attr_ipv4(entity, 12),
                current_secondary_dns: attr_ipv4(entity, 13),
                domain_name: attr_text(entity, 14),
                host_name: attr_text(entity, 15),
                relay_tag_mode: attr_u16(entity, 16).unwrap_or(0xffff),
            });
        }

        let mut ipv6_hosts = Vec::new();
        for (&(class_id, entity_id), entity) in &self.entities {
            if class_id != CLASS_IPV6_HOST_CONFIG_DATA {
                continue;
            }
            let ipv6_address = attr_ipv6(entity, 5);
            let prefix_length = if ipv6_address == "::" { 0 } else { 64 };
            let current_addresses = entity
                .attributes
                .get(&9)
                .map(|attr| {
                    attr.table_rows
                        .values()
                        .filter_map(|row| row.get(0..16).map(format_ipv6))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let current_gateway = entity
                .attributes
                .get(&10)
                .and_then(|attr| attr.table_rows.values().next())
                .and_then(|row| row.get(0..16))
                .map(format_ipv6)
                .unwrap_or_else(|| "::".to_owned());
            let dns_rows = entity
                .attributes
                .get(&11)
                .map(|attr| {
                    attr.table_rows
                        .values()
                        .filter_map(|row| row.get(0..16).map(format_ipv6))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let current_primary_dns = dns_rows.first().cloned().unwrap_or_else(|| "::".to_owned());
            let current_secondary_dns = dns_rows.get(1).cloned().unwrap_or_else(|| "::".to_owned());

            ipv6_hosts.push(Ipv6HostSnapshot {
                entity_id,
                mac_address: attr_mac(entity, 2),
                ip_options: attr_u8(entity, 1),
                ipv6_address,
                prefix_length,
                gateway: attr_ipv6(entity, 6),
                primary_dns: attr_ipv6(entity, 7),
                secondary_dns: attr_ipv6(entity, 8),
                current_addresses,
                current_gateway,
                current_primary_dns,
                current_secondary_dns,
                domain_name: attr_text(entity, 12),
                host_name: attr_text(entity, 13),
                relay_tag_mode: attr_u16(entity, 14).unwrap_or(0xffff),
            });
        }

        let mut tcp_udp_configs = Vec::new();
        for (&(class_id, entity_id), entity) in &self.entities {
            if class_id != CLASS_TCP_UDP_CONFIG_DATA {
                continue;
            }
            let ip_host_pointer = attr_u16(entity, 4).unwrap_or(0xffff);
            tcp_udp_configs.push(TcpUdpConfigSnapshot {
                entity_id,
                port: attr_u16(entity, 1).unwrap_or(0),
                protocol: attr_u8(entity, 2),
                tos_diffserv: attr_u8(entity, 3),
                ip_host_pointer,
                ip_host_family: self.resolve_ip_host_family(ip_host_pointer),
            });
        }

        let mut tr069_servers = Vec::new();
        for (&(class_id, entity_id), entity) in &self.entities {
            if class_id != CLASS_TR069_MANAGEMENT_SERVER {
                continue;
            }
            let admin_state = attr_u8(entity, 1) == 0;
            let acs_ptr = attr_u16(entity, 2).unwrap_or(0xffff);
            let associated_tag = attr_u16(entity, 3).unwrap_or(0xffff);
            let tcp_udp_pointer = (associated_tag != 0xffff).then_some(associated_tag);
            let (ip_host_pointer, ip_host_family) = tcp_udp_pointer
                .and_then(|ptr| tcp_udp_configs.iter().find(|cfg| cfg.entity_id == ptr))
                .map(|cfg| {
                    (Some(cfg.ip_host_pointer).filter(|&p| p != 0xffff), cfg.ip_host_family)
                })
                .unwrap_or((None, IpHostFamily::Unknown));
            let (acs_url, auth_method, acs_username, acs_password) = self.resolve_acs_target(acs_ptr);
            let acs_username_present = !acs_username.is_empty();
            let acs_password_present = !acs_password.is_empty();
            tr069_servers.push(Tr069ServerSnapshot {
                entity_id,
                admin_state,
                acs_url,
                associated_tag,
                tcp_udp_pointer,
                ip_host_pointer,
                ip_host_family,
                auth_method,
                acs_username,
                acs_password,
                acs_username_present,
                acs_password_present,
            });
        }

        let management_vlan = self.resolve_management_vlan(&tr069_servers);

        Tr069ProvisioningSnapshot {
            management_vlan,
            ipv4_hosts,
            ipv6_hosts,
            tcp_udp_configs,
            tr069_servers,
        }
    }

    fn resolve_ip_host_family(&self, pointer: u16) -> IpHostFamily {
        if pointer == 0xffff {
            return IpHostFamily::Unknown;
        }
        let has_v4 = self
            .entities
            .contains_key(&(CLASS_IP_HOST_CONFIG_DATA, pointer));
        let has_v6 = self
            .entities
            .contains_key(&(CLASS_IPV6_HOST_CONFIG_DATA, pointer));
        match (has_v4, has_v6) {
            (true, false) => IpHostFamily::Ipv4,
            (false, true) => IpHostFamily::Ipv6,
            _ => IpHostFamily::Unknown,
        }
    }

    fn resolve_acs_target(&self, ptr: u16) -> (String, u8, String, String) {
        if ptr == 0xffff {
            return (String::new(), 0, String::new(), String::new());
        }
        if let Some(net_addr) = self.entities.get(&(CLASS_NETWORK_ADDRESS, ptr)) {
            let sec_ptr = attr_u16(net_addr, 1).unwrap_or(0xffff);
            let addr_ptr = attr_u16(net_addr, 2).unwrap_or(0xffff);
            let acs_url = self.read_large_string(addr_ptr);
            let (auth_method, username, password) = self.read_auth_method(sec_ptr);
            return (acs_url, auth_method, username, password);
        }
        let acs_url = self.read_large_string(ptr);
        (acs_url, 0, String::new(), String::new())
    }

    fn read_large_string(&self, entity_id: u16) -> String {
        if entity_id == 0xffff {
            return String::new();
        }
        let Some(entity) = self.entities.get(&(CLASS_LARGE_STRING, entity_id)) else {
            return String::new();
        };
        let num_parts = attr_u8(entity, 1).min(15) as usize;
        let mut raw = Vec::with_capacity(num_parts * 25);
        for part in 0..num_parts {
            let attr_idx = (part + 2) as u8;
            if let Some(attr) = entity.attributes.get(&attr_idx) {
                raw.extend_from_slice(&attr.value);
            }
        }
        omci_text(&raw)
    }

    fn read_auth_method(&self, entity_id: u16) -> (u8, String, String) {
        if entity_id == 0xffff {
            return (0, String::new(), String::new());
        }
        let Some(entity) = self
            .entities
            .get(&(CLASS_AUTHENTICATION_SECURITY_METHOD, entity_id))
        else {
            return (0, String::new(), String::new());
        };
        let scheme = attr_u8(entity, 1);
        let user1 = entity
            .attributes
            .get(&2)
            .map(|a| a.value.as_slice())
            .unwrap_or(&[]);
        let user2 = entity
            .attributes
            .get(&5)
            .map(|a| a.value.as_slice())
            .unwrap_or(&[]);
        let username = if user1.iter().any(|&b| b == 0 || b == 0xff) {
            omci_text(user1)
        } else {
            let mut combined = Vec::with_capacity(user1.len() + user2.len());
            combined.extend_from_slice(user1);
            combined.extend_from_slice(user2);
            omci_text(&combined)
        };
        let password = attr_text(entity, 3);
        (scheme, username, password)
    }

    fn resolve_management_vlan(&self, servers: &[Tr069ServerSnapshot]) -> Option<u16> {
        let mut candidates: Vec<(u16, u16)> = Vec::new();
        for server in servers {
            if let Some(host_id) = server.ip_host_pointer {
                match server.ip_host_family {
                    IpHostFamily::Ipv4 => candidates.push((CLASS_IP_HOST_CONFIG_DATA, host_id)),
                    IpHostFamily::Ipv6 => candidates.push((CLASS_IPV6_HOST_CONFIG_DATA, host_id)),
                    IpHostFamily::Unknown => {}
                }
            }
        }
        for &(class_id, entity_id) in self.entities.keys() {
            if matches!(
                class_id,
                CLASS_IP_HOST_CONFIG_DATA | CLASS_IPV6_HOST_CONFIG_DATA
            ) && !candidates.contains(&(class_id, entity_id))
            {
                candidates.push((class_id, entity_id));
            }
        }

        for (host_class, host_id) in candidates {
            if let Some(vid) = self.vlan_for_ip_host(host_class, host_id) {
                return Some(vid);
            }
        }
        None
    }

    fn vlan_for_ip_host(&self, host_class: u16, host_id: u16) -> Option<u16> {
        let assoc_type = match host_class {
            CLASS_IP_HOST_CONFIG_DATA => 4u8,
            CLASS_IPV6_HOST_CONFIG_DATA => 9u8,
            _ => return None,
        };
        if let Some(vid) = self.extended_vlan_for_target(assoc_type, host_id) {
            return Some(vid);
        }
        for (&(class_id, port_id), port) in &self.entities {
            if class_id != CLASS_MAC_BRIDGE_PORT_CONFIG_DATA {
                continue;
            }
            let tp_type = attr_u8(port, 3);
            let tp_pointer = attr_u16(port, 4);
            let matches_host = match host_class {
                CLASS_IP_HOST_CONFIG_DATA => tp_type == 4 && tp_pointer == Some(host_id),
                CLASS_IPV6_HOST_CONFIG_DATA => {
                    (tp_type == 13 || tp_type == 4) && tp_pointer == Some(host_id)
                }
                _ => false,
            };
            if !matches_host {
                continue;
            }
            if let Some(vid) = self.vlan_for_bridge_port(port_id, tp_type, tp_pointer) {
                return Some(vid);
            }
            let Some(bridge_id) = attr_u16(port, 1) else {
                continue;
            };
            for (&(other_class, ani_id), ani_port) in &self.entities {
                if other_class != CLASS_MAC_BRIDGE_PORT_CONFIG_DATA || ani_id == port_id {
                    continue;
                }
                if attr_u16(ani_port, 1) != Some(bridge_id) {
                    continue;
                }
                let ani_tp_type = attr_u8(ani_port, 3);
                if !matches!(ani_tp_type, 3 | 5) {
                    continue;
                }
                if let Some(vid) = self.vlan_for_bridge_port(
                    ani_id,
                    ani_tp_type,
                    attr_u16(ani_port, 4),
                ) {
                    return Some(vid);
                }
            }
        }
        None
    }

    fn bridge_host_vlan_for_ani_port(&self, ani_port_id: u16) -> Option<u16> {
        let ani_port = self
            .entities
            .get(&(CLASS_MAC_BRIDGE_PORT_CONFIG_DATA, ani_port_id))?;
        let bridge_id = attr_u16(ani_port, 1)?;
        for (&(class_id, port_id), port) in &self.entities {
            if class_id != CLASS_MAC_BRIDGE_PORT_CONFIG_DATA || port_id == ani_port_id {
                continue;
            }
            if attr_u16(port, 1) != Some(bridge_id) {
                continue;
            }
            let tp_type = attr_u8(port, 3);
            let Some(tp_pointer) = attr_u16(port, 4) else {
                continue;
            };
            let host_class = match (tp_type, self.resolve_ip_host_family(tp_pointer)) {
                (4, IpHostFamily::Ipv4) => CLASS_IP_HOST_CONFIG_DATA,
                (4, IpHostFamily::Ipv6) | (13, _) => CLASS_IPV6_HOST_CONFIG_DATA,
                (4, IpHostFamily::Unknown) => CLASS_IP_HOST_CONFIG_DATA,
                _ => continue,
            };
            if let Some(vid) = self.vlan_for_bridge_port(port_id, tp_type, Some(tp_pointer)) {
                return Some(vid);
            }
            let assoc_type = if host_class == CLASS_IPV6_HOST_CONFIG_DATA { 9 } else { 4 };
            if let Some(vid) = self.extended_vlan_for_target(assoc_type, tp_pointer) {
                return Some(vid);
            }
        }
        None
    }

    fn vlan_for_bridge_port(
        &self,
        port_id: u16,
        tp_type: u8,
        tp_pointer: Option<u16>,
    ) -> Option<u16> {
        if let Some(filter) = self.entities.get(&(CLASS_VLAN_TAGGING_FILTER, port_id)) {
            if let Some(vid) = first_filter_vlan(filter) {
                return Some(vid);
            }
        }
        if let Some(vid) = self.extended_vlan_for_target(0, port_id) {
            return Some(vid);
        }
        if tp_type == 3 {
            if let Some(mapper_id) = tp_pointer {
                if let Some(vid) = self.extended_vlan_for_target(1, mapper_id) {
                    return Some(vid);
                }
            }
        }
        None
    }

    fn extended_vlan_for_target(&self, assoc_type: u8, target_id: u16) -> Option<u16> {
        for (&(class_id, _), entity) in &self.entities {
            if class_id != CLASS_EXTENDED_VLAN_TAGGING {
                continue;
            }
            if attr_u8(entity, 1) != assoc_type || attr_u16(entity, 7) != Some(target_id) {
                continue;
            }
            if let Some(table) = entity.attributes.get(&6) {
                for row in table.table_rows.values() {
                    if let Some(vid) = collect_extended_vlan_primary_vid(row) {
                        return Some(vid);
                    }
                }
            }
        }
        None
    }
}

fn be_u16(value: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*value.first()?, *value.get(1)?]))
}

fn attr_u8(entity: &ManagedEntity, index: u8) -> u8 {
    entity
        .attributes
        .get(&index)
        .and_then(|attr| attr.value.first())
        .copied()
        .unwrap_or(0)
}

fn attr_u16(entity: &ManagedEntity, index: u8) -> Option<u16> {
    entity
        .attributes
        .get(&index)
        .and_then(|attr| be_u16(&attr.value))
}

fn attr_text(entity: &ManagedEntity, index: u8) -> String {
    entity
        .attributes
        .get(&index)
        .map(|attr| omci_text(&attr.value))
        .unwrap_or_default()
}

fn attr_mac(entity: &ManagedEntity, index: u8) -> String {
    let bytes = entity
        .attributes
        .get(&index)
        .map(|attr| attr.value.as_slice())
        .unwrap_or(&[]);
    if bytes.len() == 6 {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
        )
    } else {
        "00:00:00:00:00:00".to_owned()
    }
}

fn attr_ipv4(entity: &ManagedEntity, index: u8) -> String {
    let bytes = entity
        .attributes
        .get(&index)
        .map(|attr| attr.value.as_slice())
        .unwrap_or(&[]);
    if bytes.len() == 4 {
        std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string()
    } else {
        "0.0.0.0".to_owned()
    }
}

fn format_ipv6(bytes: &[u8]) -> String {
    if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        std::net::Ipv6Addr::from(octets).to_string()
    } else {
        "::".to_owned()
    }
}

fn attr_ipv6(entity: &ManagedEntity, index: u8) -> String {
    let bytes = entity
        .attributes
        .get(&index)
        .map(|attr| attr.value.as_slice())
        .unwrap_or(&[]);
    format_ipv6(bytes)
}

fn eui64_link_local(mac: &[u8; 6]) -> [u8; 16] {
    [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0,
        mac[0] ^ 0x02, mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5],
    ]
}

fn first_filter_vlan(filter: &ManagedEntity) -> Option<u16> {
    let operation = attr_u8(filter, 2);
    if !matches!(operation, 0x03 | 0x04 | 0x0f | 0x10 | 0x16) {
        return None;
    }
    let count = attr_u8(filter, 3).min(12) as usize;
    let list = filter.attributes.get(&1)?;
    for entry in list.value.chunks_exact(2).take(count) {
        let vid = u16::from_be_bytes([entry[0], entry[1]]) & 0x0fff;
        if (1..=4094).contains(&vid) {
            return Some(vid);
        }
    }
    None
}

fn collect_extended_vlan_primary_vid(row: &[u8]) -> Option<u16> {
    if row.len() != 16 {
        return None;
    }
    for offset in [8usize, 12] {
        let word = u32::from_be_bytes([
            row[offset],
            row[offset + 1],
            row[offset + 2],
            row[offset + 3],
        ]);
        let vid = ((word >> 3) & 0x1fff) as u16;
        if (1..=4094).contains(&vid) {
            return Some(vid);
        }
    }
    for offset in [0usize, 4] {
        let word = u32::from_be_bytes([
            row[offset],
            row[offset + 1],
            row[offset + 2],
            row[offset + 3],
        ]);
        let vid = ((word >> 15) & 0x1fff) as u16;
        if (1..=4094).contains(&vid) {
            return Some(vid);
        }
    }
    None
}

fn omci_text(value: &[u8]) -> String {
    let end = value
        .iter()
        .position(|byte| *byte == 0 || *byte == 0xff)
        .unwrap_or(value.len());
    String::from_utf8_lossy(&value[..end]).trim_end().to_owned()
}

fn collect_extended_vlan_ids(row: &[u8], output: &mut BTreeSet<u16>) {
    if row.len() != 16 {
        return;
    }
    for offset in [0usize, 4, 8, 12] {
        let word = u32::from_be_bytes([
            row[offset],
            row[offset + 1],
            row[offset + 2],
            row[offset + 3],
        ]);
        let vid = ((word >> 3) & 0x1fff) as u16;
        // Filter fields place VID in bits 27..15; treatment fields use bits 15..3.
        // Values 4096 and 4097 encode copy and don't-care operations.
        let vid = if offset < 8 {
            ((word >> 15) & 0x1fff) as u16
        } else {
            vid
        };
        if (1..=4094).contains(&vid) {
            output.insert(vid);
        }
    }
}

fn collect_multicast_acl_vlan_id(row: &[u8], output: &mut BTreeSet<u16>) {
    if row.len() != 24 {
        return;
    }
    /*
     * G.988 Class 309 static and dynamic ACL rows carry the two-byte VLAN TCI
     * at offset 4. The low 12 bits contain VID, with 0 and 4095 as reserved values.
     */
    let vlan_id = u16::from_be_bytes([row[4], row[5]]) & 0x0fff;
    if (1..=4094).contains(&vlan_id) {
        output.insert(vlan_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_mib() -> Mib {
        Mib {
            entities: BTreeMap::new(),
            autonomous_defaults: BTreeMap::new(),
            known_classes: BTreeSet::new(),
            olt_created: BTreeSet::new(),
            dynamic_classes: BTreeSet::new(),
            table_snapshot: None,
            upload_snapshot: Vec::new(),
            onu_serial: [0; 8],
            pending_master_session_key: None,
            attribute_value_changes: Vec::new(),
            enhanced_security: true,
        }
    }

    #[test]
    fn create_schema_preserves_wire_offsets_and_access() {
        let payload = (0u8..32).collect::<Vec<_>>();
        let bridge = Mib::dynamic_entity(CLASS_MAC_BRIDGE_SERVICE_PROFILE, &payload).unwrap();
        assert_eq!(bridge.attributes[&4].value, payload[3..5]);
        assert!(bridge.attributes[&4].writable);

        let gem = Mib::dynamic_entity(CLASS_GEM_PORT_NETWORK_CTP, &payload).unwrap();
        assert_eq!(gem.attributes[&9].value, payload[11..13]);
        assert!(!gem.attributes[&8].writable);

        let descriptor = Mib::dynamic_entity(CLASS_TRAFFIC_DESCRIPTOR, &payload).unwrap();
        assert_eq!(descriptor.attributes[&8].value, payload[19..20]);
        assert!(!descriptor.attributes[&8].writable);
    }

    #[test]
    fn create_schema_requires_its_complete_payload() {
        for definition in schema::MANAGED_ENTITIES
            .iter()
            .filter(|definition| definition.origin == ManagedEntityOrigin::Olt)
        {
            let length = definition
                .attributes
                .iter()
                .filter_map(|attribute| match (attribute.create, attribute.kind) {
                    (CreateSource::Required { offset }, AttributeKind::Scalar { length }) => {
                        Some(offset + length)
                    }
                    _ => None,
                })
                .max();
            match length {
                Some(length) => {
                    assert!(Mib::dynamic_entity(definition.class_id, &vec![0; length]).is_some());
                    assert!(
                        Mib::dynamic_entity(definition.class_id, &vec![0; length - 1]).is_none()
                    );
                }
                None => {
                    assert!(Mib::dynamic_entity(definition.class_id, &[]).is_some());
                }
            }
        }
    }

    #[test]
    fn pm_schema_keeps_threshold_state_and_runtime_counters_separate() {
        let mut mib = Mib::from_identity(&IdentityConfig::default());
        let payload = 0x1234u16.to_be_bytes();
        let create = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 1,
            message_type: 0x44,
            action: ACTION_CREATE,
            class_id: CLASS_ETHERNET_PM_HISTORY_DATA,
            entity_id: 1,
            attribute_mask: 0,
            payload: &payload,
            content: &payload,
        };

        assert_eq!(mib.dispatch(&create).result(), Some(RESULT_SUCCESS));
        let entity = &mib.entities[&(CLASS_ETHERNET_PM_HISTORY_DATA, 1)];
        assert_eq!(entity.attributes[&2].value, payload);
        assert_eq!(entity.attributes[&3].value, vec![0; 4]);
        assert!(!entity.attributes[&3].writable);
        assert!(!entity.attributes[&3].upload);
    }

    #[test]
    fn duplicate_create_is_idempotent_when_the_instance_matches() {
        let mut mib = Mib::from_identity(&IdentityConfig::default());
        let payload = 0x1234u16.to_be_bytes();
        let create = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 1,
            message_type: 0x44,
            action: ACTION_CREATE,
            class_id: CLASS_ETHERNET_PM_HISTORY_DATA,
            entity_id: 1,
            attribute_mask: 0,
            payload: &payload,
            content: &payload,
        };

        assert_eq!(mib.dispatch(&create).result(), Some(RESULT_SUCCESS));
        assert_eq!(mib.dispatch(&create).result(), Some(RESULT_SUCCESS));

        let changed_payload = 0x5678u16.to_be_bytes();
        let changed = Request {
            payload: &changed_payload,
            content: &changed_payload,
            ..create
        };
        assert_eq!(
            mib.dispatch(&changed).result(),
            Some(RESULT_INSTANCE_EXISTS)
        );
        assert_eq!(
            mib.entities[&(CLASS_ETHERNET_PM_HISTORY_DATA, 1)].attributes[&2].value,
            payload
        );
    }

    #[test]
    fn compatibility_profile_disables_enhanced_security() {
        let identity = IdentityConfig {
            omcc_version: 0x86,
            disable_enhanced_security: true,
            ..IdentityConfig::default()
        };
        let mut mib = Mib::from_identity(&identity);

        assert_eq!(
            mib.entities[&(CLASS_ONU2_G, 0)].attributes[&2].value,
            [0x86]
        );
        assert!(!mib
            .entities
            .contains_key(&(CLASS_ENHANCED_SECURITY_CONTROL, 0)));
        assert!(!mib.entities[&(CLASS_OMCI, 0)].attributes[&1]
            .table_rows
            .contains_key(&CLASS_ENHANCED_SECURITY_CONTROL.to_be_bytes().to_vec()));

        let content = [1u8];
        let set = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 1,
            message_type: 0x48,
            action: ACTION_SET,
            class_id: CLASS_ENHANCED_SECURITY_CONTROL,
            entity_id: 0,
            attribute_mask: 0x8000,
            payload: &content,
            content: &content,
        };
        assert_eq!(mib.dispatch(&set).result(), Some(RESULT_UNKNOWN_ME));
    }

    #[test]
    fn huawei_pm_creates_are_accepted() {
        let mut mib = Mib::from_identity(&IdentityConfig::default());
        /* Payloads captured from a Huawei XGS-PON OLT: PPTP 1 downstream control block and threshold data 4. */
        let mut control_block = [0u8; 32];
        control_block[..12].copy_from_slice(&[0, 0x0b, 0, 0x0b, 0, 0x01, 0, 0, 0, 0, 0, 0x02]);
        let mut threshold = [0u8; 32];
        threshold[1] = 0x04;

        let class_rows = &mib.entities[&(CLASS_OMCI, 0)].attributes[&1].table_rows;
        assert!(
            class_rows.contains_key(&CLASS_MAC_BRIDGE_PORT_PM_HISTORY_DATA.to_be_bytes().to_vec())
        );
        assert!(class_rows.contains_key(&CLASS_ETHERNET_FRAME_EXTENDED_PM.to_be_bytes().to_vec()));
        assert!(!class_rows.contains_key(&CLASS_VENDOR_351.to_be_bytes().to_vec()));

        for (class_id, payload) in [
            (CLASS_ETHERNET_FRAME_EXTENDED_PM, &control_block),
            (CLASS_MAC_BRIDGE_PORT_PM_HISTORY_DATA, &threshold),
            (CLASS_VENDOR_351, &threshold),
        ] {
            let create = Request {
                encoding: super::super::protocol::Encoding::Baseline,
                tci: 1,
                message_type: 0x44,
                action: ACTION_CREATE,
                class_id,
                entity_id: 2,
                attribute_mask: 0,
                payload,
                content: payload,
            };
            assert_eq!(mib.dispatch(&create).result(), Some(RESULT_SUCCESS));
            let get = Request {
                message_type: 0x49,
                action: ACTION_GET,
                attribute_mask: 0xc000,
                ..create
            };
            assert_eq!(mib.dispatch(&get).result(), Some(RESULT_SUCCESS));
            let delete = Request {
                message_type: 0x46,
                action: ACTION_DELETE,
                ..create
            };
            assert_eq!(mib.dispatch(&delete).result(), Some(RESULT_SUCCESS));
        }

        let entity = entity_from_definition(CLASS_ETHERNET_FRAME_EXTENDED_PM, Some(&control_block))
            .expect("extended PM schema is registered");
        assert_eq!(entity.attributes[&2].value, control_block[..16]);
        assert!(!entity.attributes[&16].upload);
    }

    #[test]
    fn enhanced_security_accepts_broadcast_key_rows() {
        let mut mib = Mib::from_identity(&IdentityConfig::default());
        let set = |mib: &mut Mib, row: &[u8]| {
            mib.dispatch(&Request {
                encoding: super::super::protocol::Encoding::Baseline,
                tci: 1,
                message_type: 0x48,
                action: ACTION_SET,
                class_id: CLASS_ENHANCED_SECURITY_CONTROL,
                entity_id: 0,
                attribute_mask: 0x0020,
                payload: row,
                content: row,
            })
            .result()
        };
        let rows = |mib: &Mib| {
            mib.entities[&(CLASS_ENHANCED_SECURITY_CONTROL, 0)].attributes[&11]
                .table_rows
                .len()
        };

        /* Key indexes 1 and 2, fragment 0, as distributed by a Huawei XGS-PON OLT. */
        let mut key1 = vec![0x00, 0x40];
        key1.extend_from_slice(&[0x50; 16]);
        let mut key2 = vec![0x00, 0x80];
        key2.extend_from_slice(&[0xf5; 16]);
        assert_eq!(set(&mut mib, &key1), Some(RESULT_SUCCESS));
        assert_eq!(set(&mut mib, &key2), Some(RESULT_SUCCESS));
        assert_eq!(rows(&mib), 2);
        let snapshot = mib.provisioning_snapshot();
        assert!(snapshot.enhanced_security);
        assert_eq!(
            snapshot
                .broadcast_key_indexes
                .into_iter()
                .collect::<Vec<_>>(),
            [1, 2]
        );

        let mut clear_row = vec![0x01, 0x40];
        clear_row.extend_from_slice(&[0; 16]);
        assert_eq!(set(&mut mib, &clear_row), Some(RESULT_SUCCESS));
        assert_eq!(rows(&mib), 1);

        let mut clear_table = vec![0x02, 0x00];
        clear_table.extend_from_slice(&[0; 16]);
        assert_eq!(set(&mut mib, &clear_table), Some(RESULT_SUCCESS));
        assert_eq!(rows(&mib), 0);

        let mut reserved = vec![0x03, 0x40];
        reserved.extend_from_slice(&[0; 16]);
        assert_eq!(set(&mut mib, &reserved), Some(RESULT_ATTRIBUTE_FAILED));
    }

    #[test]
    fn omci_capability_table_tracks_the_registered_schema() {
        let mib = Mib::from_identity(&IdentityConfig::default());
        let entity = &mib.entities[&(CLASS_OMCI, 0)];
        let class_rows = &entity.attributes[&1].table_rows;
        let message_rows = &entity.attributes[&2].table_rows;

        for class_id in [
            CLASS_ETHERNET_PM_HISTORY_DATA,
            CLASS_GEM_PORT_PM_HISTORY_DATA,
            CLASS_FEC_PM_HISTORY_DATA,
            CLASS_THRESHOLD_DATA_1,
            CLASS_THRESHOLD_DATA_2,
        ] {
            assert!(class_rows.contains_key(&class_id.to_be_bytes().to_vec()));
        }
        assert!(message_rows.contains_key(&vec![ACTION_GET_CURRENT_DATA]));
    }

    #[test]
    fn multicast_iwtp_uses_downstream_gem_and_bridge_vlan() {
        let mut mib = empty_mib();

        /* The Class 281 reference assigns multicast type to its downstream GEM. */
        mib.insert(
            CLASS_GEM_PORT_NETWORK_CTP,
            0x120,
            ManagedEntity::default()
                .read_write(1, 4000u16.to_be_bytes().to_vec())
                .read_write(2, 0xffffu16.to_be_bytes().to_vec())
                .read_write(3, vec![2]),
        );
        mib.insert(
            CLASS_MULTICAST_GEM_INTERWORKING_TP,
            0x220,
            ManagedEntity::default().read_write(1, 0x120u16.to_be_bytes().to_vec()),
        );
        mib.insert(
            CLASS_MAC_BRIDGE_PORT_CONFIG_DATA,
            0x320,
            ManagedEntity::default()
                .read_write(3, vec![6])
                .read_write(4, 0x220u16.to_be_bytes().to_vec()),
        );
        let mut vlan_list = vec![0; 24];
        vlan_list[..2].copy_from_slice(&85u16.to_be_bytes());
        mib.insert(
            CLASS_VLAN_TAGGING_FILTER,
            0x320,
            ManagedEntity::default()
                .read_write(1, vlan_list)
                .read_write(2, vec![0x03])
                .read_write(3, vec![1]),
        );

        assert_eq!(
            mib.provisioning_snapshot().data_paths,
            vec![DataPathCandidate {
                alloc_id: u16::MAX,
                gem_id: 4000,
                vlan_id: 85,
                pbit_mask: u8::MAX,
                multicast: true,
            }]
        );
        let snapshot = mib.provisioning_snapshot();
        assert!(snapshot.vlan_ids.is_empty());
        assert_eq!(snapshot.multicast_vlan_ids, BTreeSet::from([85]));
    }

    #[test]
    fn subscriber_profile_reports_igmp_upstream_vlan() {
        let mut mib = empty_mib();
        let mut profile_payload = vec![0; 26];

        /* Class 309 attribute 4 starts at offset 3 and attribute 5 follows it. */
        profile_payload[3..5].copy_from_slice(&85u16.to_be_bytes());
        profile_payload[5] = 1; // add TCI
        mib.insert(
            CLASS_MULTICAST_OPERATIONS_PROFILE,
            0x400,
            Mib::dynamic_entity(CLASS_MULTICAST_OPERATIONS_PROFILE, &profile_payload)
                .expect("valid multicast profile"),
        );

        let mut subscriber_payload = vec![0; 10];
        subscriber_payload[1..3].copy_from_slice(&0x400u16.to_be_bytes());
        mib.insert(
            CLASS_MULTICAST_SUBSCRIBER_CONFIG,
            0x100,
            Mib::dynamic_entity(CLASS_MULTICAST_SUBSCRIBER_CONFIG, &subscriber_payload)
                .expect("valid subscriber config"),
        );

        let snapshot = mib.provisioning_snapshot();
        assert_eq!(snapshot.igmp_upstream_vlan_ids, BTreeSet::from([85]));
        assert_eq!(snapshot.igmp_upstream_tag_controls, BTreeSet::from([1]));
    }

    #[test]
    fn subscriber_profile_reports_multicast_acl_vlan() {
        let mut mib = empty_mib();
        let profile_payload = vec![0; 26];
        let mut profile = Mib::dynamic_entity(CLASS_MULTICAST_OPERATIONS_PROFILE, &profile_payload)
            .expect("valid multicast profile");
        let mut acl = vec![0; 24];

        /* Class 309 attribute 7 carries GEM 0xfffe, VLAN 80, and the multicast address range. */
        acl[0..2].copy_from_slice(&0x5388u16.to_be_bytes());
        acl[2..4].copy_from_slice(&0xfffeu16.to_be_bytes());
        acl[4..6].copy_from_slice(&80u16.to_be_bytes());
        acl[10..14].copy_from_slice(&[224, 0, 1, 0]);
        acl[14..18].copy_from_slice(&[239, 255, 255, 255]);
        profile
            .attributes
            .get_mut(&7)
            .expect("static ACL table")
            .table_rows
            .insert(acl[..8].to_vec(), acl);
        mib.insert(CLASS_MULTICAST_OPERATIONS_PROFILE, 5, profile);

        let mut subscriber_payload = vec![0; 10];
        subscriber_payload[1..3].copy_from_slice(&5u16.to_be_bytes());
        mib.insert(
            CLASS_MULTICAST_SUBSCRIBER_CONFIG,
            5,
            Mib::dynamic_entity(CLASS_MULTICAST_SUBSCRIBER_CONFIG, &subscriber_payload)
                .expect("valid subscriber config"),
        );

        assert_eq!(
            mib.provisioning_snapshot().multicast_vlan_ids,
            BTreeSet::from([80])
        );
    }

    #[test]
    fn bridge_port_create_provides_filter_preassign_instance() {
        let mut mib = Mib::from_identity(&IdentityConfig::default());
        let bridge_port_payload = [0u8; 14];
        let create = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 1,
            message_type: 0x44,
            action: ACTION_CREATE,
            class_id: CLASS_MAC_BRIDGE_PORT_CONFIG_DATA,
            entity_id: 1,
            attribute_mask: 0,
            payload: &bridge_port_payload,
            content: &bridge_port_payload,
        };

        assert_eq!(mib.dispatch(&create).result(), Some(RESULT_SUCCESS));
        let filter = (CLASS_MAC_BRIDGE_PORT_FILTER_PREASSIGN_DATA, 1);
        assert!(mib.entities.contains_key(&filter));

        let value = [1u8];
        let set = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 2,
            message_type: 0x48,
            action: ACTION_SET,
            class_id: filter.0,
            entity_id: filter.1,
            attribute_mask: 0x8000,
            payload: &value,
            content: &value,
        };

        assert_eq!(mib.dispatch(&set).result(), Some(RESULT_SUCCESS));
        assert_eq!(mib.entities[&filter].attributes[&1].value, value);
    }

    #[test]
    fn me134_ip_host_config_supports_set_get_upload_and_reset() {
        let identity = IdentityConfig {
            serial_number: b"EXMP01020304".to_vec(),
            ..IdentityConfig::default()
        };
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut mib = Mib::from_identity_with_mac(&identity, Some(mac));

        let initial = mib.tr069_snapshot();
        assert_eq!(initial.ipv4_hosts.len(), 1);
        assert_eq!(initial.ipv4_hosts[0].entity_id, IP_HOST_DEFAULT_ENTITY);
        assert_eq!(initial.ipv4_hosts[0].mac_address, "02:11:22:33:44:55");

        // Set Attr 1 (IP options = 0x09), Attr 4 (IP = 10.10.0.2), Attr 5 (Mask = 255.255.255.0),
        // Attr 6 (GW = 10.10.0.1), Attr 7 (DNS1 = 10.10.0.53) via Extended OMCI.
        let mut set_content = vec![0x09];
        set_content.extend_from_slice(&[10, 10, 0, 2]);
        set_content.extend_from_slice(&[255, 255, 255, 0]);
        set_content.extend_from_slice(&[10, 10, 0, 1]);
        set_content.extend_from_slice(&[10, 10, 0, 53]);
        let set = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 10,
            message_type: 0x48,
            action: ACTION_SET,
            class_id: CLASS_IP_HOST_CONFIG_DATA,
            entity_id: IP_HOST_DEFAULT_ENTITY,
            attribute_mask: 0x9e00,
            payload: &set_content,
            content: &set_content,
        };
        assert_eq!(mib.dispatch(&set).result(), Some(RESULT_SUCCESS));

        let snapshot = mib.tr069_snapshot();
        let host = &snapshot.ipv4_hosts[0];
        assert_eq!(host.ip_options, 0x09);
        assert_eq!(host.ip_address, "10.10.0.2");
        assert_eq!(host.mask, "255.255.255.0");
        assert_eq!(host.gateway, "10.10.0.1");
        assert_eq!(host.primary_dns, "10.10.0.53");

        // MIB Upload includes ME 134, ME 340, and ME 347.
        mib.rebuild_upload_snapshot();
        for class_id in [
            CLASS_IP_HOST_CONFIG_DATA,
            CLASS_TR069_MANAGEMENT_SERVER,
            CLASS_IPV6_HOST_CONFIG_DATA,
        ] {
            assert!(mib
                .upload_snapshot
                .iter()
                .any(|rec| rec.class_id == class_id));
        }

        // MIB Reset restores ME 134 back to zeroed IP config while preserving MAC.
        let reset = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 11,
            message_type: 0x4f,
            action: ACTION_MIB_RESET,
            class_id: CLASS_ONU_DATA,
            entity_id: 0,
            attribute_mask: 0,
            payload: &[],
            content: &[],
        };
        assert_eq!(mib.dispatch(&reset).result(), Some(RESULT_SUCCESS));
        let after_reset = mib.tr069_snapshot();
        assert_eq!(after_reset.ipv4_hosts[0].ip_address, "0.0.0.0");
        assert_eq!(after_reset.ipv4_hosts[0].mac_address, "02:11:22:33:44:55");
    }

    #[test]
    fn me347_ipv6_host_config_supports_tables_and_get_next() {
        let mac = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];
        let mut mib = Mib::from_identity_with_mac(&IdentityConfig::default(), Some(mac));

        let v6_entity = mib
            .entities
            .get_mut(&(CLASS_IPV6_HOST_CONFIG_DATA, IPV6_HOST_DEFAULT_ENTITY))
            .expect("autonomous ME 347 present");
        // Verify EUI-64 link-local initialization: fe80::aa:bbff:fecc:ddee (bit 1 inverted -> 0x00).
        assert_eq!(
            attr_ipv6(v6_entity, 4),
            "fe80::aa:bbff:fecc:ddee"
        );
        let mut addr_row = vec![0u8; 24];
        addr_row[0..16].copy_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ]);
        v6_entity
            .attributes
            .get_mut(&9)
            .unwrap()
            .table_rows
            .insert(vec![0, 1], addr_row);
        v6_entity
            .attributes
            .get_mut(&10)
            .unwrap()
            .table_rows
            .insert(
                vec![0, 1],
                vec![0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            );
        v6_entity
            .attributes
            .get_mut(&11)
            .unwrap()
            .table_rows
            .insert(
                vec![0, 1],
                vec![0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53],
            );

        // Set static IPv6 options (0x07: DHCPv6 + SLAAC + RS) and static IPv6 address.
        let mut set_content = vec![0x07];
        set_content.extend_from_slice(&[
            0x20, 0x01, 0x0d, 0xb8, 0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20,
        ]);
        let set = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 20,
            message_type: 0x48,
            action: ACTION_SET,
            class_id: CLASS_IPV6_HOST_CONFIG_DATA,
            entity_id: IPV6_HOST_DEFAULT_ENTITY,
            attribute_mask: 0x8800,
            payload: &set_content,
            content: &set_content,
        };
        assert_eq!(mib.dispatch(&set).result(), Some(RESULT_SUCCESS));

        // Exercise Get + Get-next on Attr 9 (Current address table, mask 0x0080).
        let get = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 21,
            message_type: 0x49,
            action: ACTION_GET,
            class_id: CLASS_IPV6_HOST_CONFIG_DATA,
            entity_id: IPV6_HOST_DEFAULT_ENTITY,
            attribute_mask: 0x0080,
            payload: &[],
            content: &[],
        };
        assert_eq!(mib.dispatch(&get).result(), Some(RESULT_SUCCESS));
        let seq0 = [0u8, 0u8];
        let get_next = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 22,
            message_type: 0x5a,
            action: ACTION_GET_NEXT,
            class_id: CLASS_IPV6_HOST_CONFIG_DATA,
            entity_id: IPV6_HOST_DEFAULT_ENTITY,
            attribute_mask: 0x0080,
            payload: &seq0,
            content: &seq0,
        };
        let next_resp = mib.dispatch(&get_next);
        assert_eq!(next_resp.result(), Some(RESULT_SUCCESS));
        assert_eq!(&next_resp.as_bytes()[11..15], &[0x20, 0x01, 0x0d, 0xb8]);

        let snapshot = mib.tr069_snapshot();
        let host = &snapshot.ipv6_hosts[0];
        assert_eq!(host.ip_options, 0x07);
        assert_eq!(host.ipv6_address, "2001:db8:2::20");
        assert_eq!(host.prefix_length, 64);
        assert_eq!(host.current_addresses, vec!["2001:db8:1::10"]);
        assert_eq!(host.current_gateway, "fe80::1");
        assert_eq!(host.current_primary_dns, "2001:db8::53");
    }

    #[test]
    fn me136_and_me340_resolve_multipart_acs_and_host_family() {
        let mut mib = Mib::from_identity(&IdentityConfig::default());

        // Create ME 157 (Large string, id=10) with >25-byte ACS URL.
        let create_str = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 30,
            message_type: 0x44,
            action: ACTION_CREATE,
            class_id: CLASS_LARGE_STRING,
            entity_id: 10,
            attribute_mask: 0,
            payload: &[],
            content: &[],
        };
        assert_eq!(mib.dispatch(&create_str).result(), Some(RESULT_SUCCESS));
        let url = b"https://acs.example.invalid:9443/tr069/cwmp";
        let mut str_set = vec![2u8]; // num_parts = 2
        str_set.extend_from_slice(&url[..25]);
        let mut part2 = vec![0u8; 25];
        part2[..url.len() - 25].copy_from_slice(&url[25..]);
        str_set.extend_from_slice(&part2);
        let set_str = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 31,
            message_type: 0x48,
            action: ACTION_SET,
            class_id: CLASS_LARGE_STRING,
            entity_id: 10,
            attribute_mask: 0xe000, // Attr 1, 2, 3
            payload: &str_set,
            content: &str_set,
        };
        assert_eq!(mib.dispatch(&set_str).result(), Some(RESULT_SUCCESS));

        // Create ME 138 (Authentication security method, id=11) with Digest auth.
        let create_auth = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 32,
            message_type: 0x44,
            action: ACTION_CREATE,
            class_id: CLASS_AUTHENTICATION_SECURITY_METHOD,
            entity_id: 11,
            attribute_mask: 0,
            payload: &[],
            content: &[],
        };
        assert_eq!(mib.dispatch(&create_auth).result(), Some(RESULT_SUCCESS));
        let mut auth_set = vec![1u8]; // MD5 Digest
        auth_set.extend_from_slice(&fixed_width(b"synthetic-acs-user", 25));
        auth_set.extend_from_slice(&fixed_width(b"synthetic-acs-secret", 25));
        let set_auth = Request {
            encoding: super::super::protocol::Encoding::Extended,
            tci: 33,
            message_type: 0x48,
            action: ACTION_SET,
            class_id: CLASS_AUTHENTICATION_SECURITY_METHOD,
            entity_id: 11,
            attribute_mask: 0xe000, // Attr 1, 2, 3
            payload: &auth_set,
            content: &auth_set,
        };
        assert_eq!(mib.dispatch(&set_auth).result(), Some(RESULT_SUCCESS));

        // Create ME 137 (Network address, id=12) -> auth 11, str 10.
        let mut net_payload = Vec::new();
        net_payload.extend_from_slice(&11u16.to_be_bytes());
        net_payload.extend_from_slice(&10u16.to_be_bytes());
        let create_net = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 34,
            message_type: 0x44,
            action: ACTION_CREATE,
            class_id: CLASS_NETWORK_ADDRESS,
            entity_id: 12,
            attribute_mask: 0,
            payload: &net_payload,
            content: &net_payload,
        };
        assert_eq!(mib.dispatch(&create_net).result(), Some(RESULT_SUCCESS));

        // Create ME 136 (TCP/UDP, id=20) pointing to ME 347 (entity 2, IPv6).
        let mut tcp_payload = Vec::new();
        tcp_payload.extend_from_slice(&7547u16.to_be_bytes());
        tcp_payload.push(6); // TCP
        tcp_payload.push(0);
        tcp_payload.extend_from_slice(&IPV6_HOST_DEFAULT_ENTITY.to_be_bytes());
        let create_tcp = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 35,
            message_type: 0x44,
            action: ACTION_CREATE,
            class_id: CLASS_TCP_UDP_CONFIG_DATA,
            entity_id: 20,
            attribute_mask: 0,
            payload: &tcp_payload,
            content: &tcp_payload,
        };
        assert_eq!(mib.dispatch(&create_tcp).result(), Some(RESULT_SUCCESS));

        // Unlock ME 340 and point to ME 137 (12) + ME 136 (20).
        let mut srv_set = vec![0u8]; // admin_state unlocked
        srv_set.extend_from_slice(&12u16.to_be_bytes());
        srv_set.extend_from_slice(&20u16.to_be_bytes());
        let set_srv = Request {
            encoding: super::super::protocol::Encoding::Baseline,
            tci: 36,
            message_type: 0x48,
            action: ACTION_SET,
            class_id: CLASS_TR069_MANAGEMENT_SERVER,
            entity_id: TR069_SERVER_DEFAULT_ENTITY,
            attribute_mask: 0xe000,
            payload: &srv_set,
            content: &srv_set,
        };
        assert_eq!(mib.dispatch(&set_srv).result(), Some(RESULT_SUCCESS));

        let snapshot = mib.tr069_snapshot();
        assert_eq!(snapshot.tcp_udp_configs.len(), 1);
        assert_eq!(snapshot.tcp_udp_configs[0].ip_host_family, IpHostFamily::Ipv6);
        assert_eq!(snapshot.tr069_servers.len(), 1);
        let server = &snapshot.tr069_servers[0];
        assert!(server.admin_state);
        assert_eq!(server.acs_url, "https://acs.example.invalid:9443/tr069/cwmp");
        assert_eq!(server.tcp_udp_pointer, Some(20));
        assert_eq!(server.ip_host_pointer, Some(IPV6_HOST_DEFAULT_ENTITY));
        assert_eq!(server.ip_host_family, IpHostFamily::Ipv6);
        assert_eq!(server.auth_method, 1);
        assert_eq!(server.acs_username, "synthetic-acs-user");
        assert_eq!(server.acs_password, "synthetic-acs-secret");
        assert!(server.acs_username_present);
        assert!(server.acs_password_present);
    }

    #[test]
    fn management_vlan_resolves_via_bridge_and_extended_vlan() {
        let mut mib = Mib::from_identity(&IdentityConfig::default());

        // Bridge 1 (Internet VLAN 41) + Bridge 2 (TR-069 VLAN 46).
        mib.insert(
            CLASS_TCONT,
            0x8000,
            ManagedEntity::default().read_write(1, 100u16.to_be_bytes().to_vec()),
        );
        mib.insert(
            CLASS_GEM_PORT_NETWORK_CTP,
            0x101,
            ManagedEntity::default()
                .read_write(1, 1001u16.to_be_bytes().to_vec())
                .read_write(2, 0x8000u16.to_be_bytes().to_vec())
                .read_write(3, vec![3]),
        );
        mib.insert(
            CLASS_GEM_PORT_NETWORK_CTP,
            0x102,
            ManagedEntity::default()
                .read_write(1, 1002u16.to_be_bytes().to_vec())
                .read_write(2, 0x8000u16.to_be_bytes().to_vec())
                .read_write(3, vec![3]),
        );
        mib.insert(
            CLASS_GEM_INTERWORKING_TP,
            0x201,
            ManagedEntity::default().read_write(1, 0x101u16.to_be_bytes().to_vec()),
        );
        mib.insert(
            CLASS_GEM_INTERWORKING_TP,
            0x202,
            ManagedEntity::default().read_write(1, 0x102u16.to_be_bytes().to_vec()),
        );
        mib.insert(
            CLASS_MAC_BRIDGE_PORT_CONFIG_DATA,
            0x301,
            ManagedEntity::default()
                .read_write(1, 1u16.to_be_bytes().to_vec())
                .read_write(3, vec![5])
                .read_write(4, 0x201u16.to_be_bytes().to_vec()),
        );
        let mut vlan41 = vec![0; 24];
        vlan41[..2].copy_from_slice(&41u16.to_be_bytes());
        mib.insert(
            CLASS_VLAN_TAGGING_FILTER,
            0x301,
            ManagedEntity::default()
                .read_write(1, vlan41)
                .read_write(2, vec![0x03])
                .read_write(3, vec![1]),
        );

        mib.insert(
            CLASS_MAC_BRIDGE_PORT_CONFIG_DATA,
            0x302,
            ManagedEntity::default()
                .read_write(1, 2u16.to_be_bytes().to_vec())
                .read_write(3, vec![5])
                .read_write(4, 0x202u16.to_be_bytes().to_vec()),
        );
        mib.insert(
            CLASS_MAC_BRIDGE_PORT_CONFIG_DATA,
            0x303,
            ManagedEntity::default()
                .read_write(1, 2u16.to_be_bytes().to_vec())
                .read_write(3, vec![4])
                .read_write(4, IP_HOST_DEFAULT_ENTITY.to_be_bytes().to_vec()),
        );
        let mut vlan46 = vec![0; 24];
        vlan46[..2].copy_from_slice(&46u16.to_be_bytes());
        mib.insert(
            CLASS_VLAN_TAGGING_FILTER,
            0x303,
            ManagedEntity::default()
                .read_write(1, vlan46)
                .read_write(2, vec![0x03])
                .read_write(3, vec![1]),
        );

        let prov = mib.provisioning_snapshot();
        assert!(prov.data_paths.iter().any(|p| p.vlan_id == 41 && p.gem_id == 1001));
        assert!(prov.data_paths.iter().any(|p| p.vlan_id == 46 && p.gem_id == 1002));
        assert_eq!(mib.tr069_snapshot().management_vlan, Some(46));

        // Also test direct Extended VLAN (ME 171 assoc_type=9) on ME 347.
        let mut ext_mib = Mib::from_identity(&IdentityConfig::default());
        let mut ext = entity_from_definition(CLASS_EXTENDED_VLAN_TAGGING, None).unwrap();
        ext.attributes.get_mut(&1).unwrap().value = vec![9];
        ext.attributes.get_mut(&7).unwrap().value = IPV6_HOST_DEFAULT_ENTITY.to_be_bytes().to_vec();
        let mut row = [0u8; 16];
        row[8..12].copy_from_slice(&((47u32 << 3) | 0x0000_0000).to_be_bytes());
        ext.attributes
            .get_mut(&6)
            .unwrap()
            .table_rows
            .insert(row[..8].to_vec(), row.to_vec());
        ext_mib.insert(CLASS_EXTENDED_VLAN_TAGGING, 0x401, ext);
        assert_eq!(ext_mib.tr069_snapshot().management_vlan, Some(47));
    }
}
