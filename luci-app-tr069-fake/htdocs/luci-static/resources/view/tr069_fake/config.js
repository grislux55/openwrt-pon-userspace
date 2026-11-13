// SPDX-License-Identifier: Apache-2.0

'use strict';
'require fs';
'require form';
'require rpc';
'require ui';
'require uci';
'require view';

var callNetworkInterfaceDump = rpc.declare({
	object: 'network.interface',
	method: 'dump',
	expect: { interface: [] }
});

function parseJsonSafe(raw, fallback) {
	if (!raw)
		return fallback;
	try {
		return JSON.parse(raw);
	} catch (e) {
		return fallback;
	}
}

function maskIfSecret(name, value) {
	if (/password/i.test(name))
		return value ? '***' : '';
	return value || '';
}

function extractInterfaceIps(ifaces, name) {
	var entry = (ifaces || []).find(function(i) { return i.interface === name; });
	if (!entry || !entry.up)
		return _('Down');

	var addrs = [];
	(entry['ipv4-address'] || []).forEach(function(a) {
		if (a.address)
			addrs.push(a.address + '/' + (a.mask || ''));
	});
	(entry['ipv6-address'] || []).forEach(function(a) {
		if (a.address)
			addrs.push(a.address + '/' + (a.mask || ''));
	});
	return addrs.length ? addrs.join(', ') : _('Up (no address)');
}

return view.extend({
	load: function() {
		return Promise.all([
			uci.load('tr069_fake'),
			fs.exec('/usr/libexec/tr069-fake-ctl', [ 'status' ]).catch(function() { return { stdout: '{}' }; }),
			fs.exec('/usr/libexec/tr069-fake-ctl', [ 'model' ]).catch(function() { return { stdout: '{}' }; }),
			fs.exec('/usr/libexec/tr069-fake-ctl', [ 'logs' ]).catch(function() { return { stdout: '' }; }),
			callNetworkInterfaceDump().catch(function() { return []; })
		]);
	},

	renderStatusSection: function(statusData, ifaces) {
		var daemon = statusData.daemon || {};
		var omci = statusData.omci || null;
		var pending = statusData.pending || {};
		var v4Status = extractInterfaceIps(ifaces, 'tr069');
		var v6Status = extractInterfaceIps(ifaces, 'tr069_6');

		var omciSummary = _('Unavailable');
		if (omci) {
			var srv = (omci.tr069_servers && omci.tr069_servers[0]) || {};
			omciSummary = _('VLAN: %s | ACS: %s').format(
				omci.management_vlan != null ? String(omci.management_vlan) : '-',
				srv.acs_url || '-'
			);
		}

		var rows = [
			[ _('Daemon Status'), daemon.running ? _('Running') : _('Stopped') ],
			[ _('Isolated IPv4 (tr069)'), v4Status ],
			[ _('Isolated IPv6 (tr069_6)'), v6Status ],
			[ _('Virtual SoftwareVersion'), daemon.software_version || '-' ],
			[ _('Virtual Boot Epoch'), pending.virtual_boot_epoch != null ? String(pending.virtual_boot_epoch) : '-' ],
			[ _('OMCI Exported Snapshot (Manual Priority)'), omciSummary ]
		];

		var table = E('table', { 'class': 'table' }, rows.map(function(r) {
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left', 'width': '35%' }, E('strong', {}, r[0])),
				E('td', { 'class': 'td left' }, r[1])
			]);
		}));

		var self = this;
		var btnInform = E('button', {
			'class': 'cbi-button cbi-button-action',
			'click': ui.createHandlerFn(this, function() {
				return fs.exec('/usr/libexec/tr069-fake-ctl', [ 'trigger-inform' ]).then(function(res) {
					if (res.code !== 0)
						ui.addNotification(null, E('p', {}, res.stderr || _('Inform trigger failed')), 'error');
					else
						ui.addNotification(null, E('p', {}, _('Inform triggered on isolated channel.')), 'info');
					return self.refreshView();
				});
			})
		}, _('Trigger Inform'));

		var btnResetVirtual = E('button', {
			'class': 'cbi-button cbi-button-negative',
			'click': ui.createHandlerFn(this, function() {
				if (!confirm(_('Reset persisted CWMP virtual model and pending events back to local template? System settings will NOT be altered.')))
					return;
				return fs.exec('/usr/libexec/tr069-fake-ctl', [ 'reset-virtual' ]).then(function(res) {
					if (res.code !== 0)
						ui.addNotification(null, E('p', {}, res.stderr || _('Reset virtual state failed')), 'error');
					else
						ui.addNotification(null, E('p', {}, _('Virtual CWMP model reset to local template.')), 'info');
					return self.refreshView();
				});
			})
		}, _('Reset Virtual State'));

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Sandbox & Dual-Stack Channel Status')),
			E('div', { 'class': 'cbi-section-descr' },
				_('TR-069 Fake isolates CWMP traffic inside dedicated netifd routing tables and firewall zone tr069. Remote ACS commands never reboot, flash, or alter host system files.')),
			table,
			E('div', { 'class': 'cbi-page-actions' }, [ btnInform, ' ', btnResetVirtual ])
		]);
	},

	renderModelDiffSection: function(modelData) {
		var tpl = modelData.template || {};
		var cur = modelData.model || {};
		var keys = Object.keys(cur).sort();

		var tbody = keys.map(function(k) {
			var tVal = tpl[k] ? maskIfSecret(k, tpl[k].value) : '-';
			var cVal = cur[k] ? maskIfSecret(k, cur[k].value) : '-';
			var changed = tVal !== cVal;
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td left' }, E('code', {}, k)),
				E('td', { 'class': 'td left' }, tVal),
				E('td', { 'class': 'td left' }, changed ? E('strong', {}, cVal) : cVal)
			]);
		});

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Initial Template vs Persisted Virtual Model')),
			E('div', { 'class': 'cbi-section-descr' },
				_('Passwords are masked. Modified values reflect last-write-wins updates from either ACS SetParameterValues or LuCI.')),
			E('div', { 'style': 'max-height: 320px; overflow-y: auto;' }, [
				E('table', { 'class': 'table' }, [
					E('tr', { 'class': 'tr table-titles' }, [
						E('th', { 'class': 'th left' }, _('Parameter Path')),
						E('th', { 'class': 'th left' }, _('Initial Template')),
						E('th', { 'class': 'th left' }, _('Current Virtual Value'))
					])
				].concat(tbody))
			])
		]);
	},

	renderAuditLogSection: function(logText) {
		var self = this;
		var btnClear = E('button', {
			'class': 'cbi-button cbi-button-reset',
			'click': ui.createHandlerFn(this, function() {
				return fs.exec('/usr/libexec/tr069-fake-ctl', [ 'clear-log' ]).then(function() {
					return self.refreshView();
				});
			})
		}, _('Clear /tmp Audit Log'));

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Sanitized /tmp Ring Audit Log')),
			E('div', { 'class': 'cbi-section-descr' },
				_('Stored exclusively in /tmp memory with automatic secret redaction; never written to NAND flash.')),
			E('pre', {
				'style': 'max-height: 240px; overflow-y: auto; padding: 8px; background: #1e1e1e; color: #dcdcdc; border-radius: 4px;'
			}, logText || _('(empty)')),
			E('div', { 'class': 'cbi-page-actions' }, [ btnClear ])
		]);
	},

	refreshView: function() {
		window.location.reload();
	},

	render: function(results) {
		var statusData = parseJsonSafe(results[1] && results[1].stdout, {});
		var modelData = parseJsonSafe(results[2] && results[2].stdout, {});
		var logText = (results[3] && results[3].stdout) || '';
		var ifaces = results[4] || [];

		var m = new form.Map('tr069_fake', _('TR-069 Fake Sandbox'),
			_('Dual-stack isolated CWMP fake client with persistent virtual TR-098/TR-181 model and optional OMCI parameter linkage.'));

		var s = m.section(form.NamedSection, 'main', 'tr069_fake', _('Configuration'));
		s.anonymous = true;
		s.tab('channel', _('Isolated Channel'));
		s.tab('acs', _('ACS & ConnectionRequest'));
		s.tab('identity', _('Fake Fingerprint'));

		var o;
		o = s.taboption('channel', form.Flag, 'enabled', _('Enable TR-069 Fake'));
		o.rmempty = false;

		o = s.taboption('channel', form.Flag, 'omci_sync', _('Sync Empty Fields from OMCI'),
			_('Read ME 134/136/340/347 exported defaults from airoha-pond; manually configured fields always take precedence.'));
		o.rmempty = false;

		o = s.taboption('channel', form.Value, 'pon_line', _('PON Line'));
		o.default = 'line0';

		o = s.taboption('channel', form.Value, 'uplink', _('Uplink Device'));
		o.default = 'pon0';

		o = s.taboption('channel', form.Value, 'vlan_id', _('Management VLAN ID'),
			_('Optional 802.1Q VLAN ID (1-4094). Leave empty to use OMCI management VLAN when sync is enabled.'));
		o.datatype = 'range(1,4094)';
		o.optional = true;

		o = s.taboption('channel', form.Value, 'macaddr', _('Cloned MAC Address'));
		o.datatype = 'macaddr';
		o.optional = true;

		o = s.taboption('channel', form.Value, 'option60', _('DHCPv4 Option 60 (Vendor ID)'));
		o.optional = true;

		o = s.taboption('channel', form.ListValue, 'ipv4_mode', _('IPv4 Mode'));
		o.value('dhcp', _('DHCPv4'));
		o.value('static', _('Static'));
		o.value('none', _('Disabled'));
		o.default = 'dhcp';

		o = s.taboption('channel', form.Value, 'ipv4_addr', _('IPv4 Address'));
		o.depends('ipv4_mode', 'static');
		o.datatype = 'ip4addr';

		o = s.taboption('channel', form.Value, 'ipv4_mask', _('IPv4 Netmask'));
		o.depends('ipv4_mode', 'static');
		o.datatype = 'ip4addr';

		o = s.taboption('channel', form.Value, 'ipv4_gw', _('IPv4 Gateway'));
		o.depends('ipv4_mode', 'static');
		o.datatype = 'ip4addr';

		o = s.taboption('channel', form.Value, 'ipv4_dns', _('IPv4 DNS'));
		o.depends('ipv4_mode', 'static');
		o.datatype = 'ip4addr';

		o = s.taboption('channel', form.ListValue, 'ipv6_mode', _('IPv6 Mode'));
		o.value('dhcpv6', _('DHCPv6 + RA'));
		o.value('slaac', _('SLAAC / RA'));
		o.value('static', _('Static'));
		o.value('none', _('Disabled'));
		o.default = 'dhcpv6';

		o = s.taboption('channel', form.Value, 'ipv6_addr', _('IPv6 Address/Prefix'));
		o.depends('ipv6_mode', 'static');
		o.datatype = 'cidr6';

		o = s.taboption('channel', form.Value, 'ipv6_gw', _('IPv6 Gateway'));
		o.depends('ipv6_mode', 'static');
		o.datatype = 'ip6addr';

		o = s.taboption('channel', form.Value, 'ipv6_dns', _('IPv6 DNS'));
		o.depends('ipv6_mode', 'static');
		o.datatype = 'ip6addr';

		o = s.taboption('channel', form.Value, 'ip4table', _('Isolated IPv4 Routing Table'));
		o.datatype = 'uinteger';
		o.default = '169';

		o = s.taboption('channel', form.Value, 'ip6table', _('Isolated IPv6 Routing Table'));
		o.datatype = 'uinteger';
		o.default = '169';

		o = s.taboption('acs', form.Value, 'acs_url', _('ACS URL'));
		o.placeholder = 'http://acs.example.invalid:9090/acs';

		o = s.taboption('acs', form.Value, 'acs_username', _('ACS Username'));
		o.optional = true;

		o = s.taboption('acs', form.Value, 'acs_password', _('ACS Password'));
		o.password = true;
		o.optional = true;

		o = s.taboption('acs', form.Flag, 'insecure_tls', _('Allow Self-Signed ACS TLS Certificate'));
		o.rmempty = false;

		o = s.taboption('acs', form.Flag, 'periodic_inform_enable', _('Enable Periodic Inform'));
		o.rmempty = false;

		o = s.taboption('acs', form.Value, 'periodic_inform_interval', _('Periodic Inform Interval (s)'));
		o.datatype = 'min(10)';
		o.default = '43200';

		o = s.taboption('acs', form.Flag, 'conn_req_enable', _('Enable ConnectionRequest Listener'),
			_('Binds strictly to the isolated tr069 interface IPv4/IPv6 addresses (never wildcard 0.0.0.0 or ::).'));
		o.rmempty = false;

		o = s.taboption('acs', form.Value, 'conn_req_port', _('ConnectionRequest Port'));
		o.depends('conn_req_enable', '1');
		o.datatype = 'port';
		o.default = '7547';

		o = s.taboption('acs', form.Value, 'conn_req_path', _('ConnectionRequest Path'));
		o.depends('conn_req_enable', '1');
		o.default = '/tr069';

		o = s.taboption('acs', form.Value, 'conn_req_username', _('ConnectionRequest Username'));
		o.depends('conn_req_enable', '1');
		o.optional = true;

		o = s.taboption('acs', form.Value, 'conn_req_password', _('ConnectionRequest Password'));
		o.depends('conn_req_enable', '1');
		o.password = true;
		o.optional = true;

		o = s.taboption('acs', form.Value, 'conn_req_allowed_ips', _('Allowed ACS Source IPs/CIDRs'),
			_('Optional space-separated allowlist for ConnectionRequest ingress inside zone tr069.'));
		o.depends('conn_req_enable', '1');
		o.optional = true;

		o = s.taboption('identity', form.Value, 'manufacturer', _('Manufacturer'));
		o.placeholder = 'NNRRWrt';
		o = s.taboption('identity', form.Value, 'oui', _('Manufacturer OUI'));
		o.placeholder = '000000';
		o = s.taboption('identity', form.Value, 'product_class', _('ProductClass'));
		o.placeholder = 'XG-040G-MD';
		o = s.taboption('identity', form.Value, 'serial_number', _('SerialNumber'));
		o.placeholder = 'FAKE00000000';
		o = s.taboption('identity', form.Value, 'hardware_version', _('HardwareVersion'));
		o.placeholder = 'AN7581-1.0';
		o = s.taboption('identity', form.Value, 'software_version', _('SoftwareVersion'));
		o.placeholder = 'NNRRWrt-1.0.0';

		var cp = m.section(form.GridSection, 'custom_param', _('Custom CWMP Parameters (TR-098 / TR-181 KV)'),
			_('Extra writable parameters exposed in the virtual model.'));
		cp.addremove = true;
		cp.anonymous = true;
		o = cp.option(form.Value, 'path', _('Parameter Path'));
		o.placeholder = 'Device.DeviceInfo.X_CUSTOM_Tag';
		o.rmempty = false;
		o = cp.option(form.Value, 'value', _('Value'));

		var dm = m.section(form.GridSection, 'download_map', _('Virtual Firmware Download Mappings'),
			_('Virtual Download RPC matches URL substring and updates SoftwareVersion without downloading or flashing real firmware.'));
		dm.addremove = true;
		dm.anonymous = true;
		o = dm.option(form.Value, 'pattern', _('URL / Filename Match'));
		o.rmempty = false;
		o = dm.option(form.Value, 'file_type', _('FileType (optional)'));
		o.placeholder = '1 Firmware Upgrade Image';
		o = dm.option(form.Value, 'target_version', _('Target Virtual SoftwareVersion'));
		o.rmempty = false;

		var self = this;
		return m.render().then(function(mapEl) {
			return E('div', {}, [
				self.renderStatusSection(statusData, ifaces),
				mapEl,
				self.renderModelDiffSection(modelData),
				self.renderAuditLogSection(logText)
			]);
		});
	}
});
