// SPDX-License-Identifier: GPL-2.0-only

use quick_xml::escape::{escape as qxml_escape, unescape as qxml_unescape};
use quick_xml::events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use roxmltree::{Document, Node, ParsingOptions};

use crate::config::FakeConfig;
use crate::model::{
    iso8601_now, CwmpFault, ManagementEffects, PendingEvent, PendingTransfer, VirtualModel,
};

const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CwmpMessage {
    InformResponse {
        max_envelopes: u32,
    },
    TransferCompleteResponse,
    GetRPCMethods,
    GetParameterNames {
        parameter_path: String,
        next_level: bool,
    },
    GetParameterValues {
        parameter_names: Vec<String>,
    },
    SetParameterValues {
        params: Vec<(String, String, Option<String>)>,
        parameter_key: String,
    },
    GetParameterAttributes {
        parameter_names: Vec<String>,
    },
    SetParameterAttributes {
        items: Vec<(String, Option<u8>, Option<Vec<String>>)>,
    },
    AddObject {
        object_name: String,
        parameter_key: String,
    },
    DeleteObject {
        object_name: String,
        parameter_key: String,
    },
    Reboot {
        command_key: String,
    },
    FactoryReset,
    Download {
        command_key: String,
        file_type: String,
        url: String,
    },
    Fault {
        code: String,
        message: String,
    },
}

#[derive(Clone, Debug)]
pub struct ParsedEnvelope {
    pub cwmp_id: Option<String>,
    pub message: CwmpMessage,
}

pub fn xml_escape(input: &str) -> String {
    qxml_escape(input).into_owned()
}

pub fn xml_unescape(input: &str) -> String {
    let normalized: std::borrow::Cow<'_, str> = if input.contains("&#X") {
        std::borrow::Cow::Owned(input.replace("&#X", "&#x"))
    } else {
        std::borrow::Cow::Borrowed(input)
    };
    qxml_unescape(normalized.as_ref())
        .map(|cow| cow.into_owned())
        .unwrap_or_else(|_| input.to_owned())
}

fn write_text_elem<W: std::io::Write>(
    w: &mut Writer<W>,
    tag: &str,
    attrs: &[(&str, &str)],
    text_val: &str,
) {
    let mut start = BytesStart::new(tag);
    for (k, v) in attrs {
        start.push_attribute((*k, *v));
    }
    let _ = w.write_event(Event::Start(start));
    let _ = w.write_event(Event::Text(BytesText::new(text_val)));
    let _ = w.write_event(Event::End(BytesEnd::new(tag)));
}

fn soap_wrap_with<F>(cwmp_id: Option<&str>, build_body: F) -> String
where
    F: FnOnce(&mut Writer<&mut Vec<u8>>),
{
    let mut buf = Vec::with_capacity(512);
    {
        let mut w = Writer::new(&mut buf);
        let _ = w.write_event(Event::Decl(BytesDecl::new("1.0", Some("UTF-8"), None)));
        let mut env = BytesStart::new("SOAP-ENV:Envelope");
        env.push_attribute(("xmlns:SOAP-ENV", "http://schemas.xmlsoap.org/soap/envelope/"));
        env.push_attribute(("xmlns:SOAP-ENC", "http://schemas.xmlsoap.org/soap/encoding/"));
        env.push_attribute(("xmlns:xsd", "http://www.w3.org/2001/XMLSchema"));
        env.push_attribute(("xmlns:xsi", XSI_NS));
        env.push_attribute(("xmlns:cwmp", "urn:dslforum-org:cwmp-1-0"));
        let _ = w.write_event(Event::Start(env));

        if let Some(id) = cwmp_id {
            let _ = w.write_event(Event::Start(BytesStart::new("SOAP-ENV:Header")));
            write_text_elem(&mut w, "cwmp:ID", &[("SOAP-ENV:mustUnderstand", "1")], id);
            let _ = w.write_event(Event::End(BytesEnd::new("SOAP-ENV:Header")));
        } else {
            let _ = w.write_event(Event::Empty(BytesStart::new("SOAP-ENV:Header")));
        }

        let _ = w.write_event(Event::Start(BytesStart::new("SOAP-ENV:Body")));
        build_body(&mut w);
        let _ = w.write_event(Event::End(BytesEnd::new("SOAP-ENV:Body")));
        let _ = w.write_event(Event::End(BytesEnd::new("SOAP-ENV:Envelope")));
    }
    String::from_utf8(buf).unwrap_or_default()
}

pub fn build_inform(
    cwmp_id: &str,
    model: &VirtualModel,
    events: &[PendingEvent],
    conn_req_url: &str,
    retry_count: u32,
) -> String {
    let manufacturer = model
        .get_value("InternetGatewayDevice.DeviceInfo.Manufacturer")
        .unwrap_or("NNRRWrt");
    let oui = model
        .get_value("InternetGatewayDevice.DeviceInfo.ManufacturerOUI")
        .unwrap_or("000000");
    let product_class = model
        .get_value("InternetGatewayDevice.DeviceInfo.ProductClass")
        .unwrap_or("XG-040G-MD");
    let serial_number = model
        .get_value("InternetGatewayDevice.DeviceInfo.SerialNumber")
        .unwrap_or("FAKE00000000");
    let hw_ver = model
        .get_value("InternetGatewayDevice.DeviceInfo.HardwareVersion")
        .unwrap_or("AN7581-1.0");
    let sw_ver = model
        .get_value("InternetGatewayDevice.DeviceInfo.SoftwareVersion")
        .unwrap_or("NNRRWrt-1.0.0");
    let param_key = model
        .get_value("InternetGatewayDevice.ManagementServer.ParameterKey")
        .unwrap_or("");
    let summary = model
        .get_value("InternetGatewayDevice.DeviceSummary")
        .unwrap_or("InternetGatewayDevice:1.4[](Baseline:1)");
    let ext_ip = model
        .get_value("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress")
        .unwrap_or("0.0.0.0");
    let effective_conn_url = if !conn_req_url.is_empty() {
        conn_req_url
    } else {
        model
            .get_value("InternetGatewayDevice.ManagementServer.ConnectionRequestURL")
            .unwrap_or("")
    };
    let prov_code = model
        .get_value("InternetGatewayDevice.DeviceInfo.ProvisioningCode")
        .unwrap_or("");

    let inform_params = [
        ("InternetGatewayDevice.DeviceSummary", summary, "xsd:string"),
        ("InternetGatewayDevice.DeviceInfo.SpecVersion", "1.0", "xsd:string"),
        ("InternetGatewayDevice.DeviceInfo.HardwareVersion", hw_ver, "xsd:string"),
        ("InternetGatewayDevice.DeviceInfo.SoftwareVersion", sw_ver, "xsd:string"),
        ("InternetGatewayDevice.DeviceInfo.ProvisioningCode", prov_code, "xsd:string"),
        ("InternetGatewayDevice.ManagementServer.ConnectionRequestURL", effective_conn_url, "xsd:string"),
        ("InternetGatewayDevice.ManagementServer.ParameterKey", param_key, "xsd:string"),
        ("InternetGatewayDevice.WANDevice.1.WANConnectionDevice.1.WANIPConnection.1.ExternalIPAddress", ext_ip, "xsd:string"),
    ];
    let now = iso8601_now();
    let retry_str = retry_count.to_string();
    let ev_arr_type = format!("cwmp:EventStruct[{}]", events.len());
    let param_arr_type = format!("cwmp:ParameterValueStruct[{}]", inform_params.len());

    soap_wrap_with(Some(cwmp_id), |w| {
        let _ = w.write_event(Event::Start(BytesStart::new("cwmp:Inform")));
        let _ = w.write_event(Event::Start(BytesStart::new("DeviceId")));
        write_text_elem(w, "Manufacturer", &[], manufacturer);
        write_text_elem(w, "OUI", &[], oui);
        write_text_elem(w, "ProductClass", &[], product_class);
        write_text_elem(w, "SerialNumber", &[], serial_number);
        let _ = w.write_event(Event::End(BytesEnd::new("DeviceId")));

        let mut ev_tag = BytesStart::new("Event");
        ev_tag.push_attribute(("SOAP-ENC:arrayType", ev_arr_type.as_str()));
        let _ = w.write_event(Event::Start(ev_tag));
        for ev in events {
            let _ = w.write_event(Event::Start(BytesStart::new("EventStruct")));
            write_text_elem(w, "EventCode", &[], &ev.event_code);
            write_text_elem(w, "CommandKey", &[], &ev.command_key);
            let _ = w.write_event(Event::End(BytesEnd::new("EventStruct")));
        }
        let _ = w.write_event(Event::End(BytesEnd::new("Event")));

        write_text_elem(w, "MaxEnvelopes", &[], "1");
        write_text_elem(w, "CurrentTime", &[], &now);
        write_text_elem(w, "RetryCount", &[], &retry_str);

        let mut plist = BytesStart::new("ParameterList");
        plist.push_attribute(("SOAP-ENC:arrayType", param_arr_type.as_str()));
        let _ = w.write_event(Event::Start(plist));
        for (name, val, ptype) in &inform_params {
            let _ = w.write_event(Event::Start(BytesStart::new("ParameterValueStruct")));
            write_text_elem(w, "Name", &[], name);
            write_text_elem(w, "Value", &[("xsi:type", *ptype)], val);
            let _ = w.write_event(Event::End(BytesEnd::new("ParameterValueStruct")));
        }
        let _ = w.write_event(Event::End(BytesEnd::new("ParameterList")));
        let _ = w.write_event(Event::End(BytesEnd::new("cwmp:Inform")));
    })
}

pub fn build_transfer_complete(cwmp_id: &str, tr: &PendingTransfer) -> String {
    let fc = tr.fault_code.to_string();
    soap_wrap_with(Some(cwmp_id), |w| {
        let _ = w.write_event(Event::Start(BytesStart::new("cwmp:TransferComplete")));
        write_text_elem(w, "CommandKey", &[], &tr.command_key);
        let _ = w.write_event(Event::Start(BytesStart::new("FaultStruct")));
        write_text_elem(w, "FaultCode", &[], &fc);
        write_text_elem(w, "FaultString", &[], &tr.fault_string);
        let _ = w.write_event(Event::End(BytesEnd::new("FaultStruct")));
        write_text_elem(w, "StartTime", &[], &tr.start_time);
        write_text_elem(w, "CompleteTime", &[], &tr.complete_time);
        let _ = w.write_event(Event::End(BytesEnd::new("cwmp:TransferComplete")));
    })
}

pub fn build_fault(cwmp_id: Option<&str>, fault: &CwmpFault) -> String {
    let fc = fault.code.to_string();
    soap_wrap_with(cwmp_id, |w| {
        let _ = w.write_event(Event::Start(BytesStart::new("SOAP-ENV:Fault")));
        write_text_elem(w, "faultcode", &[], "Client");
        write_text_elem(w, "faultstring", &[], "CWMP fault");
        let _ = w.write_event(Event::Start(BytesStart::new("detail")));
        let _ = w.write_event(Event::Start(BytesStart::new("cwmp:Fault")));
        write_text_elem(w, "FaultCode", &[], &fc);
        write_text_elem(w, "FaultString", &[], &fault.message);
        for (name, code, msg) in &fault.param_faults {
            let pc = code.to_string();
            let _ = w.write_event(Event::Start(BytesStart::new("SetParameterValuesFault")));
            write_text_elem(w, "ParameterName", &[], name);
            write_text_elem(w, "FaultCode", &[], &pc);
            write_text_elem(w, "FaultString", &[], msg);
            let _ = w.write_event(Event::End(BytesEnd::new("SetParameterValuesFault")));
        }
        let _ = w.write_event(Event::End(BytesEnd::new("cwmp:Fault")));
        let _ = w.write_event(Event::End(BytesEnd::new("detail")));
        let _ = w.write_event(Event::End(BytesEnd::new("SOAP-ENV:Fault")));
    })
}

pub fn dispatch_rpc(
    env: &ParsedEnvelope,
    model: &mut VirtualModel,
    cfg: &FakeConfig,
) -> (Option<String>, ManagementEffects, bool) {
    let id = env.cwmp_id.as_deref();
    let mut effects = ManagementEffects::default();
    let mut virtual_reboot = false;
    let xml = match &env.message {
        CwmpMessage::InformResponse { .. } | CwmpMessage::TransferCompleteResponse => {
            return (None, effects, false);
        }
        CwmpMessage::GetRPCMethods => {
            let methods = [
                "Inform",
                "GetRPCMethods",
                "GetParameterNames",
                "GetParameterValues",
                "SetParameterValues",
                "GetParameterAttributes",
                "SetParameterAttributes",
                "AddObject",
                "DeleteObject",
                "Reboot",
                "FactoryReset",
                "Download",
                "TransferComplete",
            ];
            let arr_type = format!("xsd:string[{}]", methods.len());
            soap_wrap_with(id, |w| {
                let _ = w.write_event(Event::Start(BytesStart::new("cwmp:GetRPCMethodsResponse")));
                let mut ml = BytesStart::new("MethodList");
                ml.push_attribute(("SOAP-ENC:arrayType", arr_type.as_str()));
                let _ = w.write_event(Event::Start(ml));
                for m in &methods {
                    write_text_elem(w, "string", &[], m);
                }
                let _ = w.write_event(Event::End(BytesEnd::new("MethodList")));
                let _ = w.write_event(Event::End(BytesEnd::new("cwmp:GetRPCMethodsResponse")));
            })
        }
        CwmpMessage::GetParameterNames {
            parameter_path,
            next_level,
        } => match model.get_parameter_names(parameter_path, *next_level) {
            Ok(items) => {
                let arr_type = format!("cwmp:ParameterInfoStruct[{}]", items.len());
                soap_wrap_with(id, |w| {
                    let _ = w.write_event(Event::Start(BytesStart::new("cwmp:GetParameterNamesResponse")));
                    let mut pl = BytesStart::new("ParameterList");
                    pl.push_attribute(("SOAP-ENC:arrayType", arr_type.as_str()));
                    let _ = w.write_event(Event::Start(pl));
                    for (name, writable) in &items {
                        let _ = w.write_event(Event::Start(BytesStart::new("ParameterInfoStruct")));
                        write_text_elem(w, "Name", &[], name);
                        write_text_elem(w, "Writable", &[], if *writable { "1" } else { "0" });
                        let _ = w.write_event(Event::End(BytesEnd::new("ParameterInfoStruct")));
                    }
                    let _ = w.write_event(Event::End(BytesEnd::new("ParameterList")));
                    let _ = w.write_event(Event::End(BytesEnd::new("cwmp:GetParameterNamesResponse")));
                })
            }
            Err(f) => build_fault(id, &f),
        },
        CwmpMessage::GetParameterValues { parameter_names } => {
            match model.get_parameter_values(parameter_names) {
                Ok(items) => {
                    let arr_type = format!("cwmp:ParameterValueStruct[{}]", items.len());
                    soap_wrap_with(id, |w| {
                        let _ = w.write_event(Event::Start(BytesStart::new("cwmp:GetParameterValuesResponse")));
                        let mut pl = BytesStart::new("ParameterList");
                        pl.push_attribute(("SOAP-ENC:arrayType", arr_type.as_str()));
                        let _ = w.write_event(Event::Start(pl));
                        for (name, val, ptype) in &items {
                            let _ = w.write_event(Event::Start(BytesStart::new("ParameterValueStruct")));
                            write_text_elem(w, "Name", &[], name);
                            write_text_elem(w, "Value", &[("xsi:type", ptype.as_str())], val);
                            let _ = w.write_event(Event::End(BytesEnd::new("ParameterValueStruct")));
                        }
                        let _ = w.write_event(Event::End(BytesEnd::new("ParameterList")));
                        let _ = w.write_event(Event::End(BytesEnd::new("cwmp:GetParameterValuesResponse")));
                    })
                }
                Err(f) => build_fault(id, &f),
            }
        }
        CwmpMessage::SetParameterValues {
            params,
            parameter_key,
        } => match model.set_parameter_values(params, parameter_key) {
            Ok(eff) => {
                effects = eff;
                soap_wrap_with(id, |w| {
                    let _ = w.write_event(Event::Start(BytesStart::new("cwmp:SetParameterValuesResponse")));
                    write_text_elem(w, "Status", &[], "0");
                    let _ = w.write_event(Event::End(BytesEnd::new("cwmp:SetParameterValuesResponse")));
                })
            }
            Err(f) => build_fault(id, &f),
        },
        CwmpMessage::GetParameterAttributes { parameter_names } => {
            match model.get_parameter_attributes(parameter_names) {
                Ok(items) => {
                    let arr_type = format!("cwmp:ParameterAttributeStruct[{}]", items.len());
                    soap_wrap_with(id, |w| {
                        let _ = w.write_event(Event::Start(BytesStart::new("cwmp:GetParameterAttributesResponse")));
                        let mut pl = BytesStart::new("ParameterList");
                        pl.push_attribute(("SOAP-ENC:arrayType", arr_type.as_str()));
                        let _ = w.write_event(Event::Start(pl));
                        for (name, notif, acl) in &items {
                            let notif_str = notif.to_string();
                            let acl_type = format!("xsd:string[{}]", acl.len());
                            let _ = w.write_event(Event::Start(BytesStart::new("ParameterAttributeStruct")));
                            write_text_elem(w, "Name", &[], name);
                            write_text_elem(w, "Notification", &[], &notif_str);
                            let mut al = BytesStart::new("AccessList");
                            al.push_attribute(("SOAP-ENC:arrayType", acl_type.as_str()));
                            let _ = w.write_event(Event::Start(al));
                            for s in acl {
                                write_text_elem(w, "string", &[], s);
                            }
                            let _ = w.write_event(Event::End(BytesEnd::new("AccessList")));
                            let _ = w.write_event(Event::End(BytesEnd::new("ParameterAttributeStruct")));
                        }
                        let _ = w.write_event(Event::End(BytesEnd::new("ParameterList")));
                        let _ = w.write_event(Event::End(BytesEnd::new("cwmp:GetParameterAttributesResponse")));
                    })
                }
                Err(f) => build_fault(id, &f),
            }
        }
        CwmpMessage::SetParameterAttributes { items } => {
            match model.set_parameter_attributes(items) {
                Ok(()) => soap_wrap_with(id, |w| {
                    let _ = w.write_event(Event::Empty(BytesStart::new("cwmp:SetParameterAttributesResponse")));
                }),
                Err(f) => build_fault(id, &f),
            }
        }
        CwmpMessage::AddObject {
            object_name,
            parameter_key,
        } => match model.add_object(object_name, parameter_key) {
            Ok(inst) => {
                let inst_str = inst.to_string();
                soap_wrap_with(id, |w| {
                    let _ = w.write_event(Event::Start(BytesStart::new("cwmp:AddObjectResponse")));
                    write_text_elem(w, "InstanceNumber", &[], &inst_str);
                    write_text_elem(w, "Status", &[], "0");
                    let _ = w.write_event(Event::End(BytesEnd::new("cwmp:AddObjectResponse")));
                })
            }
            Err(f) => build_fault(id, &f),
        },
        CwmpMessage::DeleteObject {
            object_name,
            parameter_key,
        } => match model.delete_object(object_name, parameter_key) {
            Ok(()) => soap_wrap_with(id, |w| {
                let _ = w.write_event(Event::Start(BytesStart::new("cwmp:DeleteObjectResponse")));
                write_text_elem(w, "Status", &[], "0");
                let _ = w.write_event(Event::End(BytesEnd::new("cwmp:DeleteObjectResponse")));
            }),
            Err(f) => build_fault(id, &f),
        },
        CwmpMessage::Reboot { command_key } => match model.handle_reboot(command_key) {
            Ok(()) => {
                virtual_reboot = true;
                soap_wrap_with(id, |w| {
                    let _ = w.write_event(Event::Empty(BytesStart::new("cwmp:RebootResponse")));
                })
            }
            Err(f) => build_fault(id, &f),
        },
        CwmpMessage::FactoryReset => match model.handle_factory_reset() {
            Ok(()) => {
                virtual_reboot = true;
                soap_wrap_with(id, |w| {
                    let _ = w.write_event(Event::Empty(BytesStart::new("cwmp:FactoryResetResponse")));
                })
            }
            Err(f) => build_fault(id, &f),
        },
        CwmpMessage::Download {
            command_key,
            file_type,
            url,
        } => match model.handle_download(command_key, file_type, url, &cfg.download_mappings) {
            Ok(tr) => soap_wrap_with(id, |w| {
                let _ = w.write_event(Event::Start(BytesStart::new("cwmp:DownloadResponse")));
                write_text_elem(w, "Status", &[], "1");
                write_text_elem(w, "StartTime", &[], &tr.start_time);
                write_text_elem(w, "CompleteTime", &[], &tr.complete_time);
                let _ = w.write_event(Event::End(BytesEnd::new("cwmp:DownloadResponse")));
            }),
            Err(f) => build_fault(id, &f),
        },
        CwmpMessage::Fault { .. } => return (None, effects, false),
    };
    (Some(xml), effects, virtual_reboot)
}

// ---------- CWMP SOAP XML Parser (roxmltree) ----------

fn std_soap_namespace_uri(prefix: &str) -> Option<&'static str> {
    match prefix {
        "xsi" => Some(XSI_NS),
        "xsd" => Some("http://www.w3.org/2001/XMLSchema"),
        "SOAP-ENC" | "soap-enc" | "soapenc" => Some("http://schemas.xmlsoap.org/soap/encoding/"),
        "SOAP-ENV" | "soap-env" | "soapenv" => Some("http://schemas.xmlsoap.org/soap/envelope/"),
        "cwmp" => Some("urn:dslforum-org:cwmp-1-0"),
        _ => None,
    }
}

fn inject_root_xmlns(xml: &str, prefix: &str, uri: &str) -> Option<String> {
    let bytes = xml.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let lt = xml[pos..].find('<')? + pos;
        if xml[lt..].starts_with("<?") {
            pos = xml[lt + 2..].find("?>")? + lt + 4;
            continue;
        }
        if xml[lt..].starts_with("<!--") {
            pos = xml[lt + 4..].find("-->")? + lt + 7;
            continue;
        }
        if matches!(bytes.get(lt + 1), Some(b'!' | b'/')) {
            return None;
        }
        let gt = xml[lt + 1..].find('>')? + lt + 1;
        let insert_at = if gt > lt + 1 && bytes[gt - 1] == b'/' {
            gt - 1
        } else {
            gt
        };
        let mut out = String::with_capacity(xml.len() + prefix.len() + uri.len() + 12);
        out.push_str(&xml[..insert_at]);
        out.push_str(&format!(" xmlns:{prefix}=\"{uri}\""));
        out.push_str(&xml[insert_at..]);
        return Some(out);
    }
    None
}

fn find_child_elem<'a, 'input>(node: Node<'a, 'input>, local: &str) -> Option<Node<'a, 'input>> {
    node.children()
        .find(|c| c.is_element() && c.tag_name().name() == local)
}

fn node_text_raw(node: Node<'_, '_>) -> String {
    let mut out = String::new();
    for c in node.children() {
        if c.is_text() {
            if let Some(t) = c.text() {
                out.push_str(t);
            }
        }
    }
    out
}

fn child_text_trimmed(node: Node<'_, '_>, local: &str) -> Option<String> {
    find_child_elem(node, local).map(|n| node_text_raw(n).trim().to_owned())
}

pub fn parse_cwmp_envelope(xml: &str) -> Result<ParsedEnvelope, String> {
    let opts = ParsingOptions {
        allow_dtd: false,
        nodes_limit: 16_384,
    };
    let mut owned_buf: Option<String> = None;
    for _ in 0..6 {
        let current = owned_buf.as_deref().unwrap_or(xml);
        match Document::parse_with_options(current, opts) {
            Ok(doc) => return extract_cwmp_envelope(&doc),
            Err(roxmltree::Error::UnknownNamespace(prefix, _)) => {
                if let Some(uri) = std_soap_namespace_uri(&prefix) {
                    if let Some(patched) = inject_root_xmlns(current, &prefix, uri) {
                        owned_buf = Some(patched);
                        continue;
                    }
                }
                return Err(format!("unknown XML namespace prefix: {prefix}"));
            }
            Err(err) => return Err(format!("XML parse error: {err}")),
        }
    }
    Err("too many undeclared XML namespace prefixes".to_owned())
}

fn extract_cwmp_envelope(doc: &Document<'_>) -> Result<ParsedEnvelope, String> {
    let root = doc.root_element();
    if root.tag_name().name() != "Envelope" {
        return Err(format!(
            "expected SOAP Envelope root, got {}",
            root.tag_name().name()
        ));
    }
    let header = find_child_elem(root, "Header");
    let cwmp_id = header.and_then(|h| child_text_trimmed(h, "ID"));
    let body = find_child_elem(root, "Body").ok_or_else(|| "SOAP Body missing".to_owned())?;
    let rpc = body
        .children()
        .find(|c| c.is_element())
        .ok_or_else(|| "SOAP Body empty".to_owned())?;

    let msg = match rpc.tag_name().name() {
        "InformResponse" => CwmpMessage::InformResponse {
            max_envelopes: child_text_trimmed(rpc, "MaxEnvelopes")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1),
        },
        "TransferCompleteResponse" => CwmpMessage::TransferCompleteResponse,
        "GetRPCMethods" => CwmpMessage::GetRPCMethods,
        "GetParameterNames" => {
            let parameter_path = child_text_trimmed(rpc, "ParameterPath").unwrap_or_default();
            let nl = child_text_trimmed(rpc, "NextLevel").unwrap_or_default();
            let next_level = matches!(nl.as_str(), "1" | "true" | "TRUE");
            CwmpMessage::GetParameterNames {
                parameter_path,
                next_level,
            }
        }
        "GetParameterValues" => {
            let mut parameter_names = Vec::new();
            if let Some(list) = find_child_elem(rpc, "ParameterNames") {
                for c in list.children().filter(|c| c.is_element()) {
                    parameter_names.push(node_text_raw(c).trim().to_owned());
                }
            }
            CwmpMessage::GetParameterValues { parameter_names }
        }
        "SetParameterValues" => {
            let parameter_key = child_text_trimmed(rpc, "ParameterKey").unwrap_or_default();
            let mut params = Vec::new();
            if let Some(list) = find_child_elem(rpc, "ParameterList") {
                for c in list.children().filter(|c| c.is_element()) {
                    let name = child_text_trimmed(c, "Name").unwrap_or_default();
                    let val_node = find_child_elem(c, "Value");
                    let val = val_node.map(node_text_raw).unwrap_or_default();
                    let declared_type = val_node.and_then(|v| {
                        v.attribute((XSI_NS, "type"))
                            .or_else(|| {
                                v.attributes()
                                    .find(|a| a.name() == "type")
                                    .map(|a| a.value())
                            })
                            .map(str::to_owned)
                    });
                    params.push((name, val, declared_type));
                }
            }
            CwmpMessage::SetParameterValues {
                params,
                parameter_key,
            }
        }
        "GetParameterAttributes" => {
            let mut parameter_names = Vec::new();
            if let Some(list) = find_child_elem(rpc, "ParameterNames") {
                for c in list.children().filter(|c| c.is_element()) {
                    parameter_names.push(node_text_raw(c).trim().to_owned());
                }
            }
            CwmpMessage::GetParameterAttributes { parameter_names }
        }
        "SetParameterAttributes" => {
            let mut items = Vec::new();
            if let Some(list) = find_child_elem(rpc, "ParameterList") {
                for c in list.children().filter(|c| c.is_element()) {
                    let name = child_text_trimmed(c, "Name").unwrap_or_default();
                    let notif_change = child_text_trimmed(c, "NotificationChange")
                        .map(|s| matches!(s.as_str(), "1" | "true"))
                        .unwrap_or(false);
                    let notif = if notif_change {
                        child_text_trimmed(c, "Notification").and_then(|s| s.parse::<u8>().ok())
                    } else {
                        None
                    };
                    let acl_change = child_text_trimmed(c, "AccessListChange")
                        .map(|s| matches!(s.as_str(), "1" | "true"))
                        .unwrap_or(false);
                    let acl = if acl_change {
                        Some(
                            find_child_elem(c, "AccessList")
                                .map(|a| {
                                    a.children()
                                        .filter(|s| s.is_element())
                                        .map(|s| node_text_raw(s).trim().to_owned())
                                        .collect()
                                })
                                .unwrap_or_default(),
                        )
                    } else {
                        None
                    };
                    items.push((name, notif, acl));
                }
            }
            CwmpMessage::SetParameterAttributes { items }
        }
        "AddObject" => CwmpMessage::AddObject {
            object_name: child_text_trimmed(rpc, "ObjectName").unwrap_or_default(),
            parameter_key: child_text_trimmed(rpc, "ParameterKey").unwrap_or_default(),
        },
        "DeleteObject" => CwmpMessage::DeleteObject {
            object_name: child_text_trimmed(rpc, "ObjectName").unwrap_or_default(),
            parameter_key: child_text_trimmed(rpc, "ParameterKey").unwrap_or_default(),
        },
        "Reboot" => CwmpMessage::Reboot {
            command_key: child_text_trimmed(rpc, "CommandKey").unwrap_or_default(),
        },
        "FactoryReset" => CwmpMessage::FactoryReset,
        "Download" => CwmpMessage::Download {
            command_key: child_text_trimmed(rpc, "CommandKey").unwrap_or_default(),
            file_type: child_text_trimmed(rpc, "FileType").unwrap_or_default(),
            url: child_text_trimmed(rpc, "URL").unwrap_or_default(),
        },
        "Fault" => CwmpMessage::Fault {
            code: child_text_trimmed(rpc, "faultcode").unwrap_or_else(|| "Fault".to_owned()),
            message: child_text_trimmed(rpc, "faultstring").unwrap_or_default(),
        },
        other => return Err(format!("unsupported CWMP RPC method: {other}")),
    };
    Ok(ParsedEnvelope {
        cwmp_id,
        message: msg,
    })
}
