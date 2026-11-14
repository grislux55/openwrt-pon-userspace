#!/usr/bin/env ucode
// SPDX-License-Identifier: Apache-2.0

'use strict';

import { access, glob, lsdir, open, popen, readfile, stat, statvfs } from 'fs';
import { cursor } from 'uci';
import { connect as ubus_connect } from 'ubus';

function readTrim(path) {
	let content = readfile(path);
	if (content == null)
		return null;
	return trim(replace(content, /\0/g, ''));
}

function readNumber(path) {
	let raw = readTrim(path);
	if (raw == null || raw == '')
		return null;
	let val = +raw;
	return (val == val) ? val : null;
}

function safeToken(val) {
	return (type(val) == 'string' && match(val, /^[A-Za-z0-9_.-]+$/)) ? val : null;
}

function execJson(cmd) {
	let p = popen(cmd + ' 2>/dev/null', 'r');
	if (!p)
		return null;
	let out = p.read('all');
	let rc = p.close();
	if (rc != 0 || !out)
		return null;
	try {
		return json(out);
	} catch (e) {
		return null;
	}
}

function initEnabled(name) {
	let links = glob('/etc/rc.d/S??' + name);
	return type(links) == 'array' && length(links) > 0;
}

function readCpuStat() {
	let fd = open('/proc/stat', 'r');
	if (!fd)
		return null;

	let total = null;
	let cores = [];
	for (let line = fd.read('line'); length(line); line = fd.read('line')) {
		let m = match(trim(line), /^(cpu[0-9]*)\s+(.+)$/);
		if (!m)
			continue;
		let parts = split(trim(m[2]), /\s+/);
		if (length(parts) < 4)
			continue;
		let user = +(parts[0] || 0);
		let nice = +(parts[1] || 0);
		let sys = +(parts[2] || 0);
		let idle = +(parts[3] || 0);
		let iowait = +(parts[4] || 0);
		let irq = +(parts[5] || 0);
		let softirq = +(parts[6] || 0);
		let steal = +(parts[7] || 0);
		let busy = user + nice + sys + irq + softirq + steal;
		let sum = busy + idle + iowait;
		if (m[1] == 'cpu')
			total = { busy, total: sum };
		else
			push(cores, { id: m[1], busy, total: sum });
	}
	fd.close();
	return { total, cores };
}

function readStorage() {
	for (let mp in ['/overlay', '/']) {
		let st = statvfs(mp);
		if (st && st.blocks > 0) {
			let bsize = st.frsize || st.bsize || 4096;
			let total_bytes = st.blocks * bsize;
			let avail_bytes = st.bavail * bsize;
			let free_bytes = st.bfree * bsize;
			return {
				mount: mp,
				total_bytes,
				used_bytes: total_bytes - free_bytes,
				avail_bytes
			};
		}
	}
	return null;
}

function readUbiHealth() {
	let entries = lsdir('/sys/class/ubi');
	if (!entries)
		return { present: false, healthy: false, volumes: {}, missing: [] };

	let volumes = {};
	for (let entry in entries) {
		if (!match(entry, /^ubi[0-9]+_[0-9]+$/))
			continue;
		let base = '/sys/class/ubi/' + entry;
		let vname = readTrim(base + '/name');
		if (!vname)
			continue;
		let data_bytes = readNumber(base + '/data_bytes') ?? 0;
		let reserved_ebs = readNumber(base + '/reserved_ebs') ?? 0;
		let eb_size = readNumber(base + '/usable_eb_size') ?? 0;
		let corrupted = readNumber(base + '/corrupted') ?? 0;
		volumes[vname] = {
			dev: entry,
			data_bytes,
			reserved_bytes: reserved_ebs * eb_size,
			corrupted: corrupted != 0
		};
	}

	let critical = ['bosa', 'ri', 'fip', 'ubootenv', 'ubootenv2'];
	let missing = [];
	for (let req in critical) {
		let v = volumes[req];
		if (!v || v.corrupted || (req == 'fip' && v.data_bytes <= 0 && v.reserved_bytes <= 0))
			push(missing, req);
	}

	return {
		present: length(keys(volumes)) > 0,
		healthy: length(keys(volumes)) > 0 && length(missing) == 0,
		volumes,
		missing
	};
}

function readPort(spec) {
	let base = '/sys/class/net/' + spec.id;
	if (!stat(base))
		return { ...spec, present: false, up: false };

	let operstate = readTrim(base + '/operstate') || 'down';
	let carrier = readNumber(base + '/carrier');
	let speed = readNumber(base + '/speed');
	if (speed != null && speed <= 0)
		speed = null;
	let duplex = readTrim(base + '/duplex');
	if (duplex != 'full' && duplex != 'half')
		duplex = null;

	let up = (carrier == 1) || (spec.role == 'optical' && operstate == 'up');

	return {
		...spec,
		present: true,
		up,
		operstate,
		speed_mbps: up ? speed : null,
		duplex: up ? duplex : null,
		mac: readTrim(base + '/address'),
		rx_bytes: readNumber(base + '/statistics/rx_bytes') ?? 0,
		tx_bytes: readNumber(base + '/statistics/tx_bytes') ?? 0,
		rx_packets: readNumber(base + '/statistics/rx_packets') ?? 0,
		tx_packets: readNumber(base + '/statistics/tx_packets') ?? 0
	};
}

function readUsbPorts() {
	let devs = lsdir('/sys/bus/usb/devices') || [];
	let groups = {
		usb1: { id: 'usb1', label: 'USB 1', connected: false, max_speed_mbps: 0, devices: [] },
		usb2: { id: 'usb2', label: 'USB 2', connected: false, max_speed_mbps: 0, devices: [] }
	};

	for (let d in devs) {
		let m = match(d, /^([1-4])-[0-9]+(\.[0-9]+)*$/);
		if (!m)
			continue;
		let base = '/sys/bus/usb/devices/' + d;
		let prod = readTrim(base + '/product') || readTrim(base + '/manufacturer') || d;
		let spd = readNumber(base + '/speed') ?? 0;
		let slot = (m[1] == '1' || m[1] == '2') ? groups.usb1 : groups.usb2;
		slot.connected = true;
		if (spd > slot.max_speed_mbps)
			slot.max_speed_mbps = spd;
		push(slot.devices, { bus: d, product: prod, speed_mbps: spd });
	}

	return [groups.usb1, groups.usb2];
}

function readActiveTrigger(path) {
	let raw = readTrim(path);
	if (!raw)
		return 'none';
	let m = match(raw, /\[([^\]]+)\]/);
	return m ? m[1] : raw;
}

function readLeds() {
	let dir = lsdir('/sys/class/leds');
	if (!dir)
		return [];

	let preferred = [
		{ sysfs: 'green:power', label: 'PWR', color: 'green' },
		{ sysfs: 'green:wan', label: 'PON', color: 'green' },
		{ sysfs: 'red:wan', label: 'LOS', color: 'red' },
		{ sysfs: 'green:wan-online', label: 'INET', color: 'green' },
		{ sysfs: 'mt7530-0:0f:green:lan-1', label: 'LAN1', color: 'green' },
		{ sysfs: 'mt7530-0:0a:green:lan-2', label: 'LAN2', color: 'green' },
		{ sysfs: 'mt7530-0:0b:green:lan-3', label: 'LAN3', color: 'green' },
		{ sysfs: 'mt7530-0:0c:green:lan-4', label: 'LAN4', color: 'green' },
		{ sysfs: 'green:usb-1', label: 'USB1', color: 'green' },
		{ sysfs: 'green:usb-2', label: 'USB2', color: 'green' }
	];

	let seen = {};
	let out = [];

	for (let item in preferred) {
		let base = '/sys/class/leds/' + item.sysfs;
		if (!stat(base))
			continue;
		seen[item.sysfs] = true;
		let brightness = readNumber(base + '/brightness') ?? 0;
		let max_b = readNumber(base + '/max_brightness') ?? 255;
		let trigger = readActiveTrigger(base + '/trigger');
		push(out, {
			sysfs: item.sysfs,
			label: item.label,
			color: item.color,
			brightness,
			max_brightness: max_b,
			lit: brightness > 0,
			trigger
		});
	}

	for (let name in sort(dir)) {
		if (seen[name])
			continue;
		let base = '/sys/class/leds/' + name;
		let brightness = readNumber(base + '/brightness') ?? 0;
		let max_b = readNumber(base + '/max_brightness') ?? 255;
		let trigger = readActiveTrigger(base + '/trigger');
		let color = index(name, 'red') >= 0 ? 'red' : (index(name, 'yellow') >= 0 || index(name, 'amber') >= 0 ? 'amber' : 'green');
		push(out, {
			sysfs: name,
			label: name,
			color,
			brightness,
			max_brightness: max_b,
			lit: brightness > 0,
			trigger
		});
	}

	return out;
}

function readPonStatus(uci_ctx) {
	let result = { available: false };
	if (!access('/etc/config/pon', 'r'))
		return result;

	uci_ctx.load('pon');
	let xpon_sec = null;
	let omci_sec = null;
	let oam_sec = null;

	uci_ctx.foreach('pon', 'xpon', function(s) {
		if (!xpon_sec)
			xpon_sec = s;
	});
	if (!xpon_sec)
		return result;

	let section_name = xpon_sec['.name'];
	let device = safeToken(xpon_sec.device || 'pon0');
	let cfg_mode = xpon_sec.mode || '';

	uci_ctx.foreach('pon', 'omci', function(s) {
		if (!omci_sec && (!s.line || s.line == section_name))
			omci_sec = s;
	});
	uci_ctx.foreach('pon', 'oam', function(s) {
		if (!oam_sec && (!s.line || s.line == section_name))
			oam_sec = s;
	});

	if (!device || !access('/usr/sbin/ponctl', 'x'))
		return { available: false, device, mode_configured: cfg_mode };

	let snap = execJson('/usr/sbin/ponctl --device ' + device + ' status --json');
	if (!snap || snap.schema_version != 1 || !snap.line)
		return { available: false, device, mode_configured: cfg_mode };

	let line = snap.line || {};
	let fe = snap.frontend || {};
	let reg = snap.registration || {};
	let dp = snap.datapath || {};
	let cnt = snap.counters || {};
	let active_mode = line.active_mode_valid ? (line.active_mode || '') : '';
	let shown_mode = active_mode || line.configured_mode || cfg_mode;
	let is_epon = index(shown_mode, 'epon-') == 0;

	let proto = null;
	let line_tok = safeToken(section_name);
	if (line_tok && access('/usr/bin/pondctl', 'x')) {
		if (is_epon && oam_sec)
			proto = execJson('/usr/bin/pondctl status --line ' + line_tok);
		else if (!is_epon && omci_sec)
			proto = execJson('/usr/bin/pondctl status --line ' + line_tok);
	}

	return {
		available: true,
		device,
		is_epon,
		mode_active: active_mode,
		mode_configured: line.configured_mode || cfg_mode,
		lifecycle: line.lifecycle || 'unknown',
		optical_signal: line.optical_signal === true || line.optical_signal == 1,
		phy_ready: line.phy_ready === true || line.pcs_sync === true,
		sync_state: is_epon ? (line.pcs_sync ? 'in-sync' : 'hunt') : (line.xgtc_sync || 'unknown'),
		rx_power_dbm: (fe && !fe.error && type(fe.rx_power_dbm) in ['int', 'double']) ? fe.rx_power_dbm : null,
		tx_power_dbm: (fe && !fe.error && type(fe.tx_power_dbm) in ['int', 'double']) ? fe.tx_power_dbm : null,
		temp_c: (fe && !fe.error && type(fe.temperature_celsius) in ['int', 'double']) ? fe.temperature_celsius : null,
		voltage_v: (fe && !fe.error && type(fe.voltage_volts) in ['int', 'double']) ? fe.voltage_volts : null,
		tx_bias_ma: (fe && !fe.error && type(fe.tx_bias_ma) in ['int', 'double']) ? fe.tx_bias_ma : null,
		calibration: fe?.calibration || 'unknown',
		tx_gate_enabled: fe?.tx_gate_enabled === true,
		onu_state: reg.onu_state || null,
		onu_id: reg.onu_id_valid === true ? reg.onu_id : null,
		mpcp_state: reg.mpcp_state || null,
		llid: reg.llid_valid === true ? reg.llid : null,
		upstream_tx_armed: reg.upstream_tx_armed === true,
		data_path_configured: dp.data_path_configured === true,
		service_ready: dp.service_ready === true,
		counters: {
			sync_losses: cnt.sync_losses ?? 0,
			recoveries: cnt.recoveries ?? 0,
			xgem_rx: cnt.xgem_rx ?? null,
			xgem_tx: cnt.xgem_tx ?? null
		},
		protocol: proto ? {
			channel_online: proto.channel_available === true,
			loid_configured: proto.loid_configured === true,
			auth: proto.authentication_meaning || proto.authentication_status || null,
			olt_vendor: proto.olt_vendor_id || null,
			olt_equipment: proto.olt_equipment_id || null,
			backend_state: proto.backend_state || null,
			vlan_ids: type(proto.vlan_ids) == 'array' ? proto.vlan_ids : [],
			all_vlans: proto.data_path_all_vlans === true,
			multicast_vlan_ids: type(proto.multicast_vlan_ids) == 'array' ? proto.multicast_vlan_ids : []
		} : null
	};
}

function readAccel(uci_ctx) {
	let ppe = {
		available: false,
		total: 0,
		bind: 0,
		unbind: 0,
		fin: 0,
		ipv4: 0,
		ipv6: 0,
		l2b: 0,
		bind_rate: readTrim('/sys/kernel/debug/ppe/bind_rate')
	};

	let fd = open('/sys/kernel/debug/ppe/entries', 'r');
	if (fd) {
		ppe.available = true;
		for (let line = fd.read('line'); length(line); line = fd.read('line')) {
			let s = trim(line);
			if (!length(s))
				continue;
			ppe.total++;
			if (match(s, /(^|\s)(BND|BIND)(\s|$)/))
				ppe.bind++;
			else if (match(s, /(^|\s)(UNB|UNBIND)(\s|$)/))
				ppe.unbind++;
			else if (match(s, /(^|\s)FIN(\s|$)/))
				ppe.fin++;
			if (index(s, 'L2B') >= 0)
				ppe.l2b++;
			if (match(s, /IPv4|IPV4/))
				ppe.ipv4++;
			if (match(s, /IPv6|IPV6/))
				ppe.ipv6++;
		}
		fd.close();
	}

	let sw_offload = false;
	let hw_offload = false;
	let fullcone = 0;
	if (access('/etc/config/firewall', 'r')) {
		uci_ctx.load('firewall');
		uci_ctx.foreach('firewall', 'defaults', function(s) {
			sw_offload = (s.flow_offloading == '1');
			hw_offload = (s.flow_offloading_hw == '1');
			fullcone = +(s.fullcone || 0);
		});
	}

	let packet_steering = 0;
	if (access('/etc/config/network', 'r')) {
		uci_ctx.load('network');
		uci_ctx.foreach('network', 'globals', function(s) {
			packet_steering = +(s.packet_steering || 0);
		});
	}

	let crypto_raw = readfile('/proc/crypto') || '';
	let eip93 = index(crypto_raw, 'eip93') >= 0;
	let devcrypto = stat('/dev/crypto') != null;

	return {
		ppe,
		sw_offload,
		hw_offload,
		fullcone,
		packet_steering,
		eip93,
		devcrypto
	};
}

function serviceRunning(svc_list, name) {
	let svc = svc_list?.[name];
	if (!svc || type(svc.instances) != 'object')
		return false;
	for (let k in svc.instances) {
		if (svc.instances[k]?.running === true)
			return true;
	}
	return false;
}

function readServices(uci_ctx) {
	let svc_list = {};
	try {
		let ub = ubus_connect();
		if (ub) {
			svc_list = ub.call('service', 'list') || {};
			ub.disconnect();
		}
	} catch (e) {}

	let items = [];

	if (access('/etc/init.d/airoha-pond', 'x')) {
		let run = serviceRunning(svc_list, 'airoha-pond');
		push(items, {
			id: 'pond',
			name: 'airoha-pond',
			state: run ? 'running' : 'stopped',
			path: 'admin/network/pon/status'
		});
	}

	if (access('/etc/init.d/firewall', 'x')) {
		let en = initEnabled('firewall');
		push(items, {
			id: 'firewall',
			name: 'fw4 / PPE',
			state: en ? 'active' : 'standby',
			path: 'admin/network/firewall'
		});
	}

	if (access('/etc/config/iptv', 'r')) {
		uci_ctx.load('iptv');
		let iptv_en = false;
		uci_ctx.foreach('iptv', 'iptv', function(s) {
			if (s.enabled == '1')
				iptv_en = true;
		});
		push(items, {
			id: 'iptv',
			name: 'IPTV',
			state: iptv_en ? 'active' : 'standby',
			path: 'admin/network/iptv'
		});
	}

	if (access('/etc/init.d/tr069-fake', 'x') || access('/etc/config/tr069_fake', 'r')) {
		let run = serviceRunning(svc_list, 'tr069-fake');
		let cfg_en = false;
		if (access('/etc/config/tr069_fake', 'r')) {
			uci_ctx.load('tr069_fake');
			uci_ctx.foreach('tr069_fake', 'tr069_fake', function(s) {
				if (s.enabled == '1')
					cfg_en = true;
			});
			if (uci_ctx.get('tr069_fake', 'main', 'enabled') == '1' ||
			    uci_ctx.get('tr069_fake', 'config', 'enabled') == '1')
				cfg_en = true;
		}
		push(items, {
			id: 'tr069_fake',
			name: 'TR-069 Fake',
			state: run ? 'running' : (cfg_en ? 'stopped' : 'standby'),
			path: 'admin/network/tr069_fake'
		});
	}

	if (access('/etc/init.d/tailscale', 'x')) {
		let run = serviceRunning(svc_list, 'tailscale');
		let en = initEnabled('tailscale');
		let ts_cfg = '0';
		if (access('/etc/config/tailscale', 'r')) {
			uci_ctx.load('tailscale');
			ts_cfg = uci_ctx.get('tailscale', 'settings', 'service_enabled') ?? (en ? '1' : '0');
		}
		push(items, {
			id: 'tailscale',
			name: 'Tailscale',
			state: run ? 'running' : ((en || ts_cfg == '1') ? 'stopped' : 'standby'),
			path: 'admin/vpn/tailscale'
		});
	}

	if (access('/etc/init.d/ddns', 'x')) {
		let run = serviceRunning(svc_list, 'ddns');
		let en = initEnabled('ddns');
		let active_rules = 0;
		if (access('/etc/config/ddns', 'r')) {
			uci_ctx.load('ddns');
			uci_ctx.foreach('ddns', 'service', function(s) {
				if (s.enabled in ['1', 'on', 'true', 'yes', 'enabled'])
					active_rules++;
			});
		}
		push(items, {
			id: 'ddns',
			name: 'DDNS',
			state: run ? 'running' : ((en && active_rules > 0) ? 'stopped' : 'standby'),
			rules: active_rules,
			path: 'admin/services/ddns'
		});
	}

	if (access('/etc/config/sqm', 'r')) {
		uci_ctx.load('sqm');
		let sqm_en = false;
		uci_ctx.foreach('sqm', 'queue', function(s) {
			if (s.enabled == '1')
				sqm_en = true;
		});
		push(items, {
			id: 'sqm',
			name: 'SQM QoS',
			state: sqm_en ? 'active' : 'standby',
			path: 'admin/network/sqm'
		});
	}

	if (access('/etc/init.d/ksmbd', 'x')) {
		let run = serviceRunning(svc_list, 'ksmbd');
		let shares = 0;
		if (access('/etc/config/ksmbd', 'r')) {
			uci_ctx.load('ksmbd');
			uci_ctx.foreach('ksmbd', 'share', function(s) {
				shares++;
			});
		}
		push(items, {
			id: 'ksmbd',
			name: 'SMB / Ksmbd',
			state: (run && shares > 0) ? 'running' : 'standby',
			shares,
			path: 'admin/services/ksmbd'
		});
	}

	push(items, {
		id: 'leds',
		name: 'LED',
		state: 'active',
		path: 'admin/system/leds'
	});

	return items;
}

const methods = {
	get_telemetry: {
		call: function() {
			let uci_ctx = cursor();
			let uptime_raw = readTrim('/proc/uptime') || '0 0';
			let uptime_sec = +(split(uptime_raw, /\s+/)[0] || 0);
			let variant = readTrim('/proc/device-tree/variant') || 'standard';
			let soc_temp_milli = readNumber('/sys/class/thermal/thermal_zone0/temp');

			let port_specs = [
				{ id: 'pon0', label: 'PON', role: 'optical', max_mbps: 10000 },
				{ id: 'lan1', label: 'LAN 1', role: '2.5g', max_mbps: 2500 },
				{ id: 'lan2', label: 'LAN 2', role: '1g', max_mbps: 1000 },
				{ id: 'lan3', label: 'LAN 3', role: '1g', max_mbps: 1000 },
				{ id: 'lan4', label: 'LAN 4', role: '1g', max_mbps: 1000 }
			];
			if (variant == 'usb-sfp' || stat('/sys/class/net/lan5'))
				push(port_specs, { id: 'lan5', label: 'LAN 5 SFP', role: 'sfp', max_mbps: 2500 });

			let ports = [];
			for (let spec in port_specs)
				push(ports, readPort(spec));

			return {
				ts_ms: int(uptime_sec * 1000),
				variant,
				soc_temp_c: soc_temp_milli != null ? (soc_temp_milli / 1000.0) : null,
				cpu_stat: readCpuStat(),
				conntrack: {
					count: readNumber('/proc/sys/net/netfilter/nf_conntrack_count'),
					max: readNumber('/proc/sys/net/netfilter/nf_conntrack_max')
				},
				storage: readStorage(),
				ubi: readUbiHealth(),
				chassis: {
					ports,
					usb: readUsbPorts(),
					leds: readLeds()
				},
				pon: readPonStatus(uci_ctx),
				accel: readAccel(uci_ctx),
				services: readServices(uci_ctx)
			};
		}
	}
};

return { 'luci.nnrrwrt_dashboard': methods };
