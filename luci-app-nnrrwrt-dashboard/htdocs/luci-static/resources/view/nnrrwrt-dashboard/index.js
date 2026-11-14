// SPDX-License-Identifier: Apache-2.0

'use strict';
'require dom';
'require poll';
'require rpc';
'require view';

var SVG_NS = 'http://www.w3.org/2000/svg';
var NBSP = '\u00a0';
var HISTORY_LIMIT = 60;

var callSystemBoard = rpc.declare({
	object: 'system',
	method: 'board'
});

var callSystemInfo = rpc.declare({
	object: 'system',
	method: 'info'
});

var callNetDump = rpc.declare({
	object: 'network.interface',
	method: 'dump'
});

var callTelemetry = rpc.declare({
	object: 'luci.nnrrwrt_dashboard',
	method: 'get_telemetry'
});

function svgEl(tag, attrs, children) {
	var node = document.createElementNS(SVG_NS, tag);
	if (attrs) {
		Object.keys(attrs).forEach(function(k) {
			if (attrs[k] !== null && attrs[k] !== undefined)
				node.setAttribute(k, String(attrs[k]));
		});
	}
	if (Array.isArray(children)) {
		children.forEach(function(child) {
			if (child)
				node.appendChild(child);
		});
	} else if (typeof children === 'string') {
		node.textContent = children;
	}
	return node;
}

function ensureStylesheet() {
	if (document.getElementById('nnrrwrt-dashboard-css'))
		return;
	var link = document.createElement('link');
	link.id = 'nnrrwrt-dashboard-css';
	link.rel = 'stylesheet';
	link.href = L.resource('view/nnrrwrt-dashboard/dashboard.css');
	document.head.appendChild(link);
}

function fmtNum(value, maxFrac, minFrac) {
	var n = Number(value);
	if (!Number.isFinite(n))
		return '0';
	try {
		return new Intl.NumberFormat(undefined, {
			maximumFractionDigits: maxFrac !== undefined ? maxFrac : 1,
			minimumFractionDigits: minFrac !== undefined ? minFrac : 0
		}).format(n);
	} catch (e) {
		return n.toFixed(maxFrac !== undefined ? maxFrac : 1);
	}
}

function formatBitrate(bps) {
	var n = Number(bps);
	if (!Number.isFinite(n) || n <= 0)
		return '0' + NBSP + 'bps';
	if (n >= 1e9)
		return fmtNum(n / 1e9, 2, 2) + NBSP + 'Gbps';
	if (n >= 1e6)
		return fmtNum(n / 1e6, 1, 1) + NBSP + 'Mbps';
	if (n >= 1e3)
		return fmtNum(n / 1e3, 0, 0) + NBSP + 'Kbps';
	return fmtNum(n, 0, 0) + NBSP + 'bps';
}

function formatBytes(bytes) {
	var n = Number(bytes);
	if (!Number.isFinite(n) || n <= 0)
		return '0' + NBSP + 'B';
	var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
	var idx = 0;
	while (n >= 1024 && idx < units.length - 1) {
		n /= 1024;
		idx++;
	}
	return fmtNum(n, idx >= 2 ? 1 : 0, idx >= 3 ? 2 : 0) + NBSP + units[idx];
}

function formatDuration(sec) {
	var s = Math.max(0, Math.floor(Number(sec) || 0));
	var days = Math.floor(s / 86400);
	var hours = Math.floor((s % 86400) / 3600);
	var mins = Math.floor((s % 3600) / 60);
	if (days > 0)
		return days + _('d') + ' ' + hours + _('h') + ' ' + mins + _('m');
	if (hours > 0)
		return hours + _('h') + ' ' + mins + _('m');
	return mins + _('m') + ' ' + (s % 60) + _('s');
}

function formatLinkSpeed(mbps) {
	var n = Number(mbps);
	if (!Number.isFinite(n) || n <= 0)
		return _('Link up');
	if (n >= 1000) {
		var g = n / 1000;
		return fmtNum(g, g % 1 === 0 ? 0 : 1, 0) + NBSP + 'Gbps';
	}
	return fmtNum(n, 0, 0) + NBSP + 'Mbps';
}

function ponModeLabel(mode) {
	switch (mode) {
	case 'xgpon': return 'XG-PON';
	case 'xgspon': return 'XGS-PON';
	case 'gpon': return 'GPON';
	case 'epon-10g-1g': return '10G-EPON 10G/1G';
	case 'epon-10g-10g': return '10G-EPON 10G/10G';
	case 'epon-1g': return 'EPON 1G';
	default: return mode || _('Unconfigured');
	}
}

function ponStateSummary(pon) {
	if (!pon || !pon.available)
		return { text: _('Unavailable'), tone: 'warn' };
	if (!pon.optical_signal)
		return { text: _('Loss of signal (LOS)'), tone: 'crit' };
	if (pon.is_epon) {
		if (pon.mpcp_state === 'registered')
			return { text: _('MPCP registered'), tone: 'ok' };
		if (pon.mpcp_state === 'denied')
			return { text: _('Registration denied'), tone: 'crit' };
		return { text: pon.mpcp_state || _('Registering…'), tone: 'warn' };
	}
	var st = (pon.onu_state || '').toUpperCase();
	if (st.indexOf('O5') === 0 || pon.lifecycle === 'operational')
		return { text: st ? (st + ' (' + _('Operational') + ')') : _('Operational'), tone: 'ok' };
	if (st.indexOf('O6') === 0 || st.indexOf('O7') === 0)
		return { text: st, tone: 'crit' };
	return { text: st || _('Synchronizing…'), tone: 'warn' };
}

function rxOpticalJudge(pon) {
	if (!pon || !pon.optical_signal || typeof pon.rx_power_dbm !== 'number')
		return { tone: 'crit', note: _('No optical carrier detected on SC/APC input') };
	var rx = pon.rx_power_dbm;
	if (rx < -30)
		return { tone: 'crit', note: _('Critical attenuation (below -30 dBm)') };
	if (rx < -27)
		return { tone: 'warn', note: _('Marginal low power (-30 to -27 dBm)') };
	if (rx <= -8)
		return { tone: 'ok', note: _('Optimal receive window (-27 to -8 dBm)') };
	if (rx <= -6)
		return { tone: 'warn', note: _('High input power (-8 to -6 dBm); consider attenuator') };
	return { tone: 'crit', note: _('Optical overload risk (above -6 dBm); add attenuator') };
}

function computeScopeCeiling(maxBps) {
	var tiers = [
		1e6, 5e6, 10e6, 25e6, 50e6, 100e6,
		250e6, 500e6, 1e9, 2.5e9, 5e9, 10e9
	];
	var target = Math.max(1e6, (Number(maxBps) || 0) * 1.15);
	for (var i = 0; i < tiers.length; i++) {
		if (tiers[i] >= target)
			return tiers[i];
	}
	return 10e9;
}

function readUrlPort() {
	try {
		var params = new URLSearchParams(window.location.search);
		return params.get('port') || 'pon0';
	} catch (e) {
		return 'pon0';
	}
}

function syncUrlPort(portId) {
	try {
		var url = new URL(window.location.href);
		if (portId && portId !== 'pon0')
			url.searchParams.set('port', portId);
		else
			url.searchParams.delete('port');
		window.history.replaceState(null, '', url.pathname + url.search + url.hash);
	} catch (e) {}
}

function codeSpan(value, cls) {
	return E('span', {
		'class': cls || '',
		'translate': 'no'
	}, value);
}

function pickSessionInterfaces(netDump) {
	var list = Array.isArray(netDump && netDump.interface) ? netDump.interface : [];
	var byName = {};
	list.forEach(function(ifc) {
		if (ifc && ifc.interface)
			byName[ifc.interface] = ifc;
	});

	var wan4 = byName.wan || null;
	var wan6 = byName.wan6 || null;
	var lan = byName.lan || null;

	if (!wan4 || !wan4.up) {
		for (var i = 0; i < list.length; i++) {
			var cand = list[i];
			if (!cand || !cand.up || cand.interface === 'loopback' || cand.interface === 'lan' || cand.interface === 'tr069')
				continue;
			if (Array.isArray(cand['ipv4-address']) && cand['ipv4-address'].length > 0) {
				wan4 = cand;
				break;
			}
		}
	}

	if (!wan6 || !wan6.up) {
		for (var j = 0; j < list.length; j++) {
			var cand6 = list[j];
			if (!cand6 || !cand6.up || cand6.interface === 'loopback' || cand6.interface === 'lan' || cand6.interface === 'tr069')
				continue;
			if ((Array.isArray(cand6['ipv6-address']) && cand6['ipv6-address'].length > 0) ||
			    (Array.isArray(cand6['ipv6-prefix']) && cand6['ipv6-prefix'].length > 0)) {
				wan6 = cand6;
				break;
			}
		}
	}

	return { wan4: wan4, wan6: wan6, lan: lan, all: list };
}

function renderSocketGraphic(role) {
	if (role === 'optical') {
		return E('div', { 'class': 'nnrrwrt-jack is-sc-apc', 'aria-hidden': 'true' }, [
			E('span', { 'class': 'nnrrwrt-jack-ferrule' })
		]);
	}
	if (role === 'usb') {
		return E('div', { 'class': 'nnrrwrt-jack is-usb', 'aria-hidden': 'true' }, [
			E('span', { 'class': 'nnrrwrt-jack-usb-bar' })
		]);
	}
	return E('div', { 'class': 'nnrrwrt-jack', 'aria-hidden': 'true' }, [
		E('div', { 'class': 'nnrrwrt-jack-pins' }, [
			E('span'), E('span'), E('span'), E('span'),
			E('span'), E('span'), E('span'), E('span')
		])
	]);
}

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: function() {
		ensureStylesheet();
		return this.fetchBundle();
	},

	fetchBundle: function() {
		return Promise.all([
			L.resolveDefault(callSystemBoard(), {}),
			L.resolveDefault(callSystemInfo(), {}),
			L.resolveDefault(callNetDump(), {}),
			L.resolveDefault(callTelemetry(), {})
		]);
	},

	initState: function() {
		if (this._state)
			return this._state;
		this._state = {
			selectedPort: readUrlPort(),
			paused: false,
			lastError: null,
			prevTsMs: null,
			prevPorts: {},
			prevCpu: null,
			portRates: {},
			cpuUsage: { total: null, cores: [] },
			scopeDev: 'pon0',
			history: [],
			latest: null
		};
		return this._state;
	},

	ingestSample: function(bundle) {
		var st = this.initState();
		var board = bundle[0] || {};
		var sysinfo = bundle[1] || {};
		var netDump = bundle[2] || {};
		var telemetry = bundle[3] || {};

		var tsMs = Number(telemetry.ts_ms);
		var dtMs = (st.prevTsMs !== null && Number.isFinite(tsMs)) ? (tsMs - st.prevTsMs) : 0;
		var ports = (telemetry.chassis && Array.isArray(telemetry.chassis.ports)) ? telemetry.chassis.ports : [];

		if (dtMs > 150) {
			var nextRates = {};
			ports.forEach(function(p) {
				var prev = st.prevPorts[p.id];
				if (prev && p.present) {
					var dRx = Math.max(0, (Number(p.rx_bytes) || 0) - prev.rx_bytes);
					var dTx = Math.max(0, (Number(p.tx_bytes) || 0) - prev.tx_bytes);
					nextRates[p.id] = {
						rx_bps: (dRx * 8 * 1000) / dtMs,
						tx_bps: (dTx * 8 * 1000) / dtMs
					};
				} else {
					nextRates[p.id] = { rx_bps: 0, tx_bps: 0 };
				}
			});
			st.portRates = nextRates;

			var curCpu = telemetry.cpu_stat;
			if (curCpu && st.prevCpu && curCpu.total && st.prevCpu.total) {
				var dTotal = curCpu.total.total - st.prevCpu.total.total;
				var dBusy = curCpu.total.busy - st.prevCpu.total.busy;
				var totalPct = dTotal > 0 ? Math.min(100, Math.max(0, (dBusy * 100) / dTotal)) : 0;
				var corePcts = [];
				var prevCoreMap = {};
				(st.prevCpu.cores || []).forEach(function(c) { prevCoreMap[c.id] = c; });
				(curCpu.cores || []).forEach(function(c, idx) {
					var pc = prevCoreMap[c.id];
					var pct = 0;
					if (pc && (c.total - pc.total) > 0)
						pct = Math.min(100, Math.max(0, ((c.busy - pc.busy) * 100) / (c.total - pc.total)));
					corePcts.push({ label: 'C' + idx, pct: pct });
				});
				st.cpuUsage = { total: totalPct, cores: corePcts };
			}
		}

		if (Number.isFinite(tsMs)) {
			st.prevTsMs = tsMs;
			var map = {};
			ports.forEach(function(p) {
				map[p.id] = {
					rx_bytes: Number(p.rx_bytes) || 0,
					tx_bytes: Number(p.tx_bytes) || 0
				};
			});
			st.prevPorts = map;
			if (telemetry.cpu_stat)
				st.prevCpu = telemetry.cpu_stat;
		}

		var sessions = pickSessionInterfaces(netDump);
		var ponPort = ports.find(function(p) { return p.id === 'pon0'; });
		var meterPortId = 'pon0';
		var meterMode = _('WAN optical uplink');

		if (ponPort && ponPort.present && ponPort.up) {
			meterPortId = 'pon0';
			meterMode = (sessions.wan4 && sessions.wan4.up) ? _('WAN routed uplink') : _('Optical bridge / L2 trunk');
		} else {
			var activeLan = ports.find(function(p) { return p.id !== 'pon0' && p.up; });
			if (activeLan) {
				meterPortId = activeLan.id;
				meterMode = _('LAN / relay port');
			}
		}
		st.scopeDev = meterPortId;
		st.scopeMode = meterMode;

		if (dtMs > 150) {
			var mr = st.portRates[meterPortId] || { rx_bps: 0, tx_bps: 0 };
			st.history.push({ rx: mr.rx_bps, tx: mr.tx_bps });
			if (st.history.length > HISTORY_LIMIT)
				st.history.shift();
		}

		st.latest = {
			board: board,
			sysinfo: sysinfo,
			sessions: sessions,
			telemetry: telemetry
		};
	},

	buildChassisSection: function() {
		var self = this;
		var st = this._state;
		var data = st.latest;
		var board = data.board || {};
		var sysinfo = data.sysinfo || {};
		var tel = data.telemetry || {};
		var pon = tel.pon || {};
		var chassis = tel.chassis || {};
		var ports = Array.isArray(chassis.ports) ? chassis.ports : [];
		var usbList = Array.isArray(chassis.usb) ? chassis.usb : [];
		var leds = Array.isArray(chassis.leds) ? chassis.leds : [];

		var hostname = board.hostname || 'NNRRWrt';
		var model = board.model || 'Nokia XG-040G-MD';
		var variantTag = tel.variant === 'usb-sfp' ? 'USB-SFP' : 'UBI';
		var releaseDesc = (board.release && (board.release.description || board.release.version)) || 'NNRRWrt';
		var kernel = board.kernel || '—';

		var tempParts = [];
		if (typeof tel.soc_temp_c === 'number')
			tempParts.push('SoC ' + fmtNum(tel.soc_temp_c, 1, 1) + NBSP + '°C');
		if (typeof pon.temp_c === 'number')
			tempParts.push('BOSA ' + fmtNum(pon.temp_c, 1, 1) + NBSP + '°C');

		var ledNodes = leds.map(function(led) {
			var dotClass = 'nnrrwrt-led-dot';
			if (led.lit)
				dotClass += ' is-' + (led.color || 'green');
			var tip = led.label + ' (' + led.sysfs + '): ' +
				(led.lit ? _('On') : _('Off')) + ' [' + (led.trigger || 'none') + ']';
			return E('span', {
				'class': 'nnrrwrt-led-pill' + (led.lit ? ' is-lit' : ''),
				'title': tip,
				'translate': 'no'
			}, [
				E('span', { 'class': dotClass, 'aria-hidden': 'true' }),
				led.label
			]);
		});

		var pauseBtn = E('button', {
			'type': 'button',
			'class': 'nnrrwrt-pause-btn' + (st.paused ? ' is-paused' : ''),
			'aria-pressed': st.paused ? 'true' : 'false',
			'click': function() {
				st.paused = !st.paused;
				self.refreshDom();
			}
		}, [
			E('span', { 'class': 'nnrrwrt-live-dot', 'aria-hidden': 'true' }),
			st.paused ? _('Resume updates') : _('Pause updates')
		]);

		var allSlots = [];
		ports.forEach(function(p) {
			allSlots.push({ kind: 'net', item: p, id: p.id });
		});
		usbList.forEach(function(u) {
			allSlots.push({ kind: 'usb', item: u, id: u.id });
		});

		var selectedExists = allSlots.some(function(s) { return s.id === st.selectedPort; });
		if (!selectedExists && allSlots.length > 0)
			st.selectedPort = allSlots[0].id;

		var portButtons = allSlots.map(function(slot) {
			var isSelected = slot.id === st.selectedPort;
			if (slot.kind === 'net') {
				var p = slot.item;
				var isOptical = p.role === 'optical';
				var isUp = isOptical ? (pon.available ? pon.optical_signal : p.up) : p.up;
				var lampCls = 'nnrrwrt-port-lamp';
				if (isOptical) {
					if (pon.available && !pon.optical_signal)
						lampCls += ' is-fault';
					else if (isUp)
						lampCls += ' is-optical';
				} else if (isUp) {
					lampCls += (p.speed_mbps && p.speed_mbps < 1000) ? ' is-slow' : ' is-fast';
				}

				var speedText = _('Unplugged');
				if (isOptical) {
					speedText = isUp ? ponModeLabel(pon.mode_active || pon.mode_configured || '10G PON') : _('No signal');
				} else if (isUp) {
					speedText = formatLinkSpeed(p.speed_mbps);
				}

				var r = st.portRates[p.id] || { rx_bps: 0, tx_bps: 0 };
				var rateText = isUp
					? ('↓' + NBSP + formatBitrate(r.rx_bps))
					: (p.max_mbps >= 2500 ? (fmtNum(p.max_mbps / 1000, 1, 0) + 'G') : '1G');

				return E('button', {
					'type': 'button',
					'class': 'nnrrwrt-port-btn' + (isUp ? ' is-up' : '') + (isSelected ? ' is-selected' : ''),
					'aria-pressed': isSelected ? 'true' : 'false',
					'click': function() {
						st.selectedPort = p.id;
						syncUrlPort(p.id);
						self.refreshDom();
					}
				}, [
					E('div', { 'class': 'nnrrwrt-port-head' }, [
						E('span', { 'class': 'nnrrwrt-port-name', 'translate': 'no' }, p.label),
						E('span', { 'class': lampCls, 'aria-hidden': 'true' })
					]),
					renderSocketGraphic(p.role),
					E('div', { 'class': 'nnrrwrt-port-speed' }, speedText),
					E('div', { 'class': 'nnrrwrt-port-rate' }, rateText)
				]);
			}

			var u = slot.item;
			var usbUp = u.connected === true;
			var usbSpeed = usbUp ? formatLinkSpeed(u.max_speed_mbps) : _('Empty slot');
			var usbDevName = (usbUp && u.devices && u.devices[0])
				? u.devices[0].product
				: 'USB 3.0 / 2.0';

			return E('button', {
				'type': 'button',
				'class': 'nnrrwrt-port-btn' + (usbUp ? ' is-up' : '') + (isSelected ? ' is-selected' : ''),
				'aria-pressed': isSelected ? 'true' : 'false',
				'click': function() {
					st.selectedPort = u.id;
					syncUrlPort(u.id);
					self.refreshDom();
				}
			}, [
				E('div', { 'class': 'nnrrwrt-port-head' }, [
					E('span', { 'class': 'nnrrwrt-port-name', 'translate': 'no' }, u.label),
					E('span', {
						'class': 'nnrrwrt-port-lamp' + (usbUp ? ' is-fast' : ''),
						'aria-hidden': 'true'
					})
				]),
				renderSocketGraphic('usb'),
				E('div', { 'class': 'nnrrwrt-port-speed' }, usbSpeed),
				E('div', { 'class': 'nnrrwrt-port-rate', 'translate': 'no' }, usbDevName)
			]);
		});

		var activeSlot = allSlots.find(function(s) { return s.id === st.selectedPort; }) || allSlots[0];
		var inspector = this.buildPortInspector(activeSlot, pon);

		return E('section', { 'class': 'nnrrwrt-chassis' }, [
			E('div', { 'class': 'nnrrwrt-chassis-top' }, [
				E('div', { 'class': 'nnrrwrt-identity' }, [
					E('div', { 'class': 'nnrrwrt-identity-row' }, [
						E('h2', { 'class': 'nnrrwrt-hostname', 'translate': 'no' }, hostname),
						E('span', { 'class': 'nnrrwrt-model-tag', 'translate': 'no' }, model + ' (' + variantTag + ')')
					]),
					E('div', { 'class': 'nnrrwrt-meta-list' }, [
						E('span', { 'class': 'nnrrwrt-meta-item' }, [
							_('Firmware'), ': ', E('strong', { 'translate': 'no' }, releaseDesc)
						]),
						E('span', { 'class': 'nnrrwrt-meta-item' }, [
							_('Kernel'), ': ', E('strong', { 'translate': 'no' }, kernel)
						]),
						E('span', { 'class': 'nnrrwrt-meta-item' }, [
							_('Uptime'), ': ', E('strong', {}, formatDuration(sysinfo.uptime))
						]),
						tempParts.length > 0 ? E('span', { 'class': 'nnrrwrt-meta-item' }, [
							_('Thermal'), ': ', E('strong', { 'translate': 'no' }, tempParts.join(' / '))
						]) : null
					])
				]),
				E('div', { 'class': 'nnrrwrt-chassis-actions' }, [
					leds.length > 0 ? E('a', {
						'class': 'nnrrwrt-led-strip',
						'href': L.url('admin/system/leds'),
						'aria-label': _('Configure front-panel LEDs')
					}, ledNodes) : null,
					pauseBtn
				])
			]),
			E('div', { 'class': 'nnrrwrt-port-bay' }, portButtons),
			inspector
		]);
	},

	buildPortInspector: function(slot, pon) {
		if (!slot)
			return null;

		if (slot.kind === 'usb') {
			var u = slot.item;
			var devs = Array.isArray(u.devices) ? u.devices : [];
			var summary = devs.length > 0
				? devs.map(function(d) {
					return d.product + ' (' + formatLinkSpeed(d.speed_mbps) + ')';
				}).join(', ')
				: _('No USB peripheral attached');

			return E('div', { 'class': 'nnrrwrt-port-inspector' }, [
				E('div', { 'class': 'nnrrwrt-inspector-stats' }, [
					E('strong', { 'translate': 'no' }, u.label),
					E('span', { 'translate': 'no' }, summary)
				]),
				E('a', {
					'class': 'nnrrwrt-inspector-link',
					'href': L.url('admin/system/mounts')
				}, _('Mount points'))
			]);
		}

		var p = slot.item;
		var r = this._state.portRates[p.id] || { rx_bps: 0, tx_bps: 0 };
		var isOptical = p.role === 'optical';
		var linkDesc = p.up ? formatLinkSpeed(p.speed_mbps) : _('Link down');
		if (isOptical) {
			linkDesc = pon.available
				? (ponModeLabel(pon.mode_active || pon.mode_configured) + ', ' + ponStateSummary(pon).text)
				: (p.up ? _('Interface up') : _('Link down'));
		} else if (p.up && p.duplex) {
			linkDesc += ' ' + (p.duplex === 'full' ? _('Full duplex') : _('Half duplex'));
		}

		var destUrl = isOptical ? L.url('admin/network/pon/status') : L.url('admin/network/network');
		var destText = isOptical ? _('PON diagnostics') : _('Network interfaces');

		return E('div', { 'class': 'nnrrwrt-port-inspector' }, [
			E('div', { 'class': 'nnrrwrt-inspector-stats' }, [
				E('strong', { 'translate': 'no' }, p.label + ' (' + p.id + ')'),
				E('span', {}, linkDesc),
				p.mac ? codeSpan(p.mac.toUpperCase(), 'nnrrwrt-inspector-code') : null,
				E('span', {}, 'RX ' + formatBitrate(r.rx_bps) + ' (' + formatBytes(p.rx_bytes) + ')'),
				E('span', {}, 'TX ' + formatBitrate(r.tx_bps) + ' (' + formatBytes(p.tx_bytes) + ')')
			]),
			E('a', { 'class': 'nnrrwrt-inspector-link', 'href': destUrl }, destText)
		]);
	},

	buildThroughputScopeSvg: function(history, ceiling) {
		var w = 600;
		var h = 132;
		var padTop = 10;
		var padBottom = 6;
		var plotH = h - padTop - padBottom;
		var n = HISTORY_LIMIT;
		var stepX = w / (n - 1);

		var samples = [];
		var padCount = Math.max(0, n - history.length);
		for (var i = 0; i < padCount; i++)
			samples.push({ rx: 0, tx: 0 });
		for (var j = 0; j < history.length; j++)
			samples.push(history[j]);

		function buildPoints(key) {
			var pts = [];
			for (var idx = 0; idx < samples.length; idx++) {
				var x = idx * stepX;
				var ratio = Math.min(1, Math.max(0, (samples[idx][key] || 0) / ceiling));
				var y = padTop + plotH * (1 - ratio);
				pts.push(x.toFixed(1) + ',' + y.toFixed(1));
			}
			return pts;
		}

		var rxPts = buildPoints('rx');
		var txPts = buildPoints('tx');
		var baseLineY = (padTop + plotH).toFixed(1);
		var rxArea = 'M0,' + baseLineY + ' L' + rxPts.join(' L') + ' L' + w + ',' + baseLineY + ' Z';
		var txArea = 'M0,' + baseLineY + ' L' + txPts.join(' L') + ' L' + w + ',' + baseLineY + ' Z';

		var cur = samples[samples.length - 1] || { rx: 0, tx: 0 };
		var ariaText = _('Downstream') + ' ' + formatBitrate(cur.rx) + ', ' +
			_('Upstream') + ' ' + formatBitrate(cur.tx);

		return svgEl('svg', {
			'class': 'nnrrwrt-scope-svg',
			'viewBox': '0 0 ' + w + ' ' + h,
			'preserveAspectRatio': 'none',
			'role': 'img',
			'aria-label': ariaText
		}, [
			svgEl('defs', null, [
				svgEl('linearGradient', { 'id': 'nd-grad-rx', 'x1': '0', 'y1': '0', 'x2': '0', 'y2': '1' }, [
					svgEl('stop', { 'offset': '0%', 'stop-color': 'var(--nd-rx)', 'stop-opacity': '0.24' }),
					svgEl('stop', { 'offset': '100%', 'stop-color': 'var(--nd-rx)', 'stop-opacity': '0.0' })
				]),
				svgEl('linearGradient', { 'id': 'nd-grad-tx', 'x1': '0', 'y1': '0', 'x2': '0', 'y2': '1' }, [
					svgEl('stop', { 'offset': '0%', 'stop-color': 'var(--nd-tx)', 'stop-opacity': '0.22' }),
					svgEl('stop', { 'offset': '100%', 'stop-color': 'var(--nd-tx)', 'stop-opacity': '0.0' })
				])
			]),
			svgEl('line', {
				'x1': '0', 'y1': (padTop + plotH * 0.25).toFixed(1),
				'x2': String(w), 'y2': (padTop + plotH * 0.25).toFixed(1),
				'stroke': 'var(--nd-border)', 'stroke-dasharray': '3 3', 'stroke-width': '1'
			}),
			svgEl('line', {
				'x1': '0', 'y1': (padTop + plotH * 0.5).toFixed(1),
				'x2': String(w), 'y2': (padTop + plotH * 0.5).toFixed(1),
				'stroke': 'var(--nd-border)', 'stroke-dasharray': '3 3', 'stroke-width': '1'
			}),
			svgEl('line', {
				'x1': '0', 'y1': (padTop + plotH * 0.75).toFixed(1),
				'x2': String(w), 'y2': (padTop + plotH * 0.75).toFixed(1),
				'stroke': 'var(--nd-border)', 'stroke-dasharray': '3 3', 'stroke-width': '1'
			}),
			svgEl('path', { 'd': rxArea, 'fill': 'url(#nd-grad-rx)' }),
			svgEl('path', { 'd': txArea, 'fill': 'url(#nd-grad-tx)' }),
			svgEl('polyline', {
				'points': rxPts.join(' '),
				'fill': 'none',
				'stroke': 'var(--nd-rx)',
				'stroke-width': '2',
				'vector-effect': 'non-scaling-stroke'
			}),
			svgEl('polyline', {
				'points': txPts.join(' '),
				'fill': 'none',
				'stroke': 'var(--nd-tx)',
				'stroke-width': '1.75',
				'vector-effect': 'non-scaling-stroke'
			})
		]);
	},

	buildTrafficSessionPanel: function() {
		var st = this._state;
		var tel = st.latest.telemetry || {};
		var sessions = st.latest.sessions || {};
		var ports = (tel.chassis && Array.isArray(tel.chassis.ports)) ? tel.chassis.ports : [];
		var dev = st.scopeDev || 'pon0';
		var portObj = ports.find(function(p) { return p.id === dev; }) || {};
		var curRate = st.portRates[dev] || { rx_bps: 0, tx_bps: 0 };

		var peak = 0;
		st.history.forEach(function(h) {
			if (h.rx > peak) peak = h.rx;
			if (h.tx > peak) peak = h.tx;
		});
		var ceiling = computeScopeCeiling(peak);

		var wan4 = sessions.wan4;
		var wan6 = sessions.wan6;
		var lan = sessions.lan;

		var v4Text = _('Not connected');
		if (wan4 && Array.isArray(wan4['ipv4-address']) && wan4['ipv4-address'][0]) {
			var a4 = wan4['ipv4-address'][0];
			v4Text = a4.address + '/' + a4.mask;
			if (wan4.proto)
				v4Text += ' (' + wan4.proto.toUpperCase() + ')';
		}

		var v6Parts = [];
		var v6Src = wan6 || wan4;
		if (v6Src) {
			if (Array.isArray(v6Src['ipv6-address']) && v6Src['ipv6-address'][0]) {
				var a6 = v6Src['ipv6-address'][0];
				v6Parts.push(a6.address + '/' + a6.mask);
			}
			if (Array.isArray(v6Src['ipv6-prefix']) && v6Src['ipv6-prefix'][0]) {
				var pfx = v6Src['ipv6-prefix'][0];
				v6Parts.push('PD ' + pfx.address + '/' + pfx.mask);
			}
		}
		var v6Text = v6Parts.length > 0 ? v6Parts.join(', ') : _('No global IPv6 lease');

		var dnsServers = [];
		if (wan4 && Array.isArray(wan4['dns-server']))
			dnsServers = dnsServers.concat(wan4['dns-server']);
		if (wan6 && Array.isArray(wan6['dns-server'])) {
			wan6['dns-server'].forEach(function(d) {
				if (dnsServers.indexOf(d) === -1)
					dnsServers.push(d);
			});
		}
		var dnsText = dnsServers.length > 0 ? dnsServers.slice(0, 2).join(', ') : _('Local / relay');
		if (wan4 && typeof wan4.uptime === 'number' && wan4.up)
			dnsText += ' (' + formatDuration(wan4.uptime) + ')';

		var lanIp = '—';
		if (lan && Array.isArray(lan['ipv4-address']) && lan['ipv4-address'][0])
			lanIp = lan['ipv4-address'][0].address + '/' + lan['ipv4-address'][0].mask;

		var ct = tel.conntrack || {};
		var ctText = (typeof ct.count === 'number' && typeof ct.max === 'number')
			? (fmtNum(ct.count, 0, 0) + ' / ' + fmtNum(ct.max, 0, 0))
			: '—';

		return E('section', { 'class': 'nnrrwrt-panel' }, [
			E('div', { 'class': 'nnrrwrt-panel-head' }, [
				E('h3', { 'class': 'nnrrwrt-panel-title' }, _('Upstream Throughput & Session')),
				E('a', {
					'class': 'nnrrwrt-panel-link',
					'href': L.url('admin/network/network')
				}, _('Manage interfaces'))
			]),
			E('div', { 'class': 'nnrrwrt-panel-body' }, [
				E('div', { 'class': 'nnrrwrt-rates-row' }, [
					E('div', { 'class': 'nnrrwrt-rate-group' }, [
						E('div', { 'class': 'nnrrwrt-rate-item' }, [
							E('span', { 'class': 'nnrrwrt-rate-label' }, [
								E('span', { 'class': 'nnrrwrt-swatch is-rx', 'aria-hidden': 'true' }),
								_('Downstream')
							]),
							E('span', { 'class': 'nnrrwrt-rate-val' }, formatBitrate(curRate.rx_bps)),
							E('span', { 'class': 'nnrrwrt-rate-sub' }, _('Total') + ': ' + formatBytes(portObj.rx_bytes))
						]),
						E('div', { 'class': 'nnrrwrt-rate-item' }, [
							E('span', { 'class': 'nnrrwrt-rate-label' }, [
								E('span', { 'class': 'nnrrwrt-swatch is-tx', 'aria-hidden': 'true' }),
								_('Upstream')
							]),
							E('span', { 'class': 'nnrrwrt-rate-val' }, formatBitrate(curRate.tx_bps)),
							E('span', { 'class': 'nnrrwrt-rate-sub' }, _('Total') + ': ' + formatBytes(portObj.tx_bytes))
						])
					]),
					E('span', { 'class': 'nnrrwrt-badge' }, [
						codeSpan(dev),
						': ',
						st.scopeMode || _('Optical uplink')
					])
				]),
				E('div', { 'class': 'nnrrwrt-scope-wrap' }, [
					E('span', { 'class': 'nnrrwrt-scope-ceil' }, _('Scale') + ': ' + formatBitrate(ceiling)),
					this.buildThroughputScopeSvg(st.history, ceiling)
				]),
				E('div', { 'class': 'nnrrwrt-kv-grid' }, [
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('WAN IPv4')),
						E('span', { 'class': 'nnrrwrt-kv-val is-mono', 'translate': 'no' }, v4Text)
					]),
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('WAN IPv6 & Prefix')),
						E('span', { 'class': 'nnrrwrt-kv-val is-mono', 'translate': 'no' }, v6Text)
					]),
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('DNS & Session Uptime')),
						E('span', { 'class': 'nnrrwrt-kv-val is-mono', 'translate': 'no' }, dnsText)
					]),
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('LAN Gateway & Conntrack')),
						E('span', { 'class': 'nnrrwrt-kv-val is-mono', 'translate': 'no' }, lanIp + ' (' + ctText + ')')
					])
				])
			])
		]);
	},

	buildOpticsPanel: function() {
		var pon = (this._state.latest.telemetry && this._state.latest.telemetry.pon) || {};
		if (!pon.available) {
			return E('section', { 'class': 'nnrrwrt-panel' }, [
				E('div', { 'class': 'nnrrwrt-panel-head' }, [
					E('h3', { 'class': 'nnrrwrt-panel-title' }, _('10G PON Optical Transceiver')),
					E('a', {
						'class': 'nnrrwrt-panel-link',
						'href': L.url('admin/network/pon/config')
					}, _('Configure PON'))
				]),
				E('div', { 'class': 'nnrrwrt-panel-body' }, [
					E('div', { 'class': 'nnrrwrt-empty-state' }, [
						E('strong', {}, _('PON telemetry is not active')),
						E('span', {}, _('Check fiber insertion on the SC/APC port or verify the line mode in PON configuration.'))
					])
				])
			]);
		}

		var judge = rxOpticalJudge(pon);
		var stateBadge = ponStateSummary(pon);
		var rxStr = typeof pon.rx_power_dbm === 'number'
			? (fmtNum(pon.rx_power_dbm, 2, 2) + NBSP + 'dBm')
			: _('No signal');
		var txStr = typeof pon.tx_power_dbm === 'number'
			? (fmtNum(pon.tx_power_dbm, 2, 2) + NBSP + 'dBm')
			: '—';
		var tempStr = typeof pon.temp_c === 'number'
			? (fmtNum(pon.temp_c, 1, 1) + NBSP + '°C')
			: '—';

		var minDbm = -32;
		var maxDbm = -4;
		var markerPct = 0;
		if (typeof pon.rx_power_dbm === 'number') {
			markerPct = ((pon.rx_power_dbm - minDbm) / (maxDbm - minDbm)) * 100;
			markerPct = Math.min(99, Math.max(1, markerPct));
		}

		var modeText = ponModeLabel(pon.mode_active || pon.mode_configured);
		if (pon.onu_id !== null && pon.onu_id !== undefined)
			modeText += ' / ONU-ID ' + pon.onu_id;
		else if (pon.llid !== null && pon.llid !== undefined)
			modeText += ' / LLID ' + pon.llid;

		var proto = pon.protocol || {};
		var authText = proto.auth || (proto.channel_online ? _('Channel online') : _('Waiting for OLT'));
		var oltParts = [];
		if (proto.olt_vendor)
			oltParts.push(proto.olt_vendor);
		if (proto.olt_equipment)
			oltParts.push(proto.olt_equipment);
		var oltText = oltParts.length > 0 ? oltParts.join(' / ') : (pon.sync_state || '—');

		var vlanText = _('Untagged / transparent');
		if (Array.isArray(proto.vlan_ids) && proto.vlan_ids.length > 0)
			vlanText = 'VLAN ' + proto.vlan_ids.join(', ');
		else if (proto.all_vlans)
			vlanText = _('All VLANs trunked');

		var biasSub = [];
		if (typeof pon.tx_bias_ma === 'number')
			biasSub.push(fmtNum(pon.tx_bias_ma, 1, 1) + NBSP + 'mA');
		if (typeof pon.voltage_v === 'number')
			biasSub.push(fmtNum(pon.voltage_v, 2, 2) + NBSP + 'V');

		return E('section', { 'class': 'nnrrwrt-panel' }, [
			E('div', { 'class': 'nnrrwrt-panel-head' }, [
				E('h3', { 'class': 'nnrrwrt-panel-title' }, _('10G PON Optical Transceiver')),
				E('a', {
					'class': 'nnrrwrt-panel-link',
					'href': L.url('admin/network/pon/status')
				}, _('PON diagnostics'))
			]),
			E('div', { 'class': 'nnrrwrt-panel-body' }, [
				E('div', { 'class': 'nnrrwrt-optics-metrics' }, [
					E('div', { 'class': 'nnrrwrt-optic-stat' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('Rx Optical Power')),
						E('span', { 'class': 'nnrrwrt-optic-num is-' + judge.tone }, rxStr)
					]),
					E('div', { 'class': 'nnrrwrt-optic-stat' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('Tx Optical Power')),
						E('span', { 'class': 'nnrrwrt-optic-num' }, txStr)
					]),
					E('div', { 'class': 'nnrrwrt-optic-stat' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('BOSA Laser')),
						E('span', { 'class': 'nnrrwrt-optic-num' }, tempStr),
						biasSub.length > 0 ? E('span', { 'class': 'nnrrwrt-rate-sub' }, biasSub.join(' / ')) : null
					])
				]),
				E('div', { 'class': 'nnrrwrt-window-meter' }, [
					E('div', {
						'style': 'display:flex;justify-content:space-between;align-items:center;gap:0.5rem;flex-wrap:wrap'
					}, [
						E('span', { 'class': 'nnrrwrt-rate-sub' }, judge.note),
						E('span', { 'class': 'nnrrwrt-badge is-' + stateBadge.tone }, stateBadge.text)
					]),
					E('div', { 'class': 'nnrrwrt-window-track', 'aria-hidden': 'true' }, [
						typeof pon.rx_power_dbm === 'number' ? E('span', {
							'class': 'nnrrwrt-window-marker',
							'style': 'left:' + markerPct.toFixed(1) + '%'
						}) : null
					]),
					E('div', { 'class': 'nnrrwrt-window-scale', 'aria-hidden': 'true' }, [
						E('span', {}, '-32' + NBSP + 'dBm'),
						E('span', {}, '-27' + NBSP + 'dBm'),
						E('span', {}, '-8' + NBSP + 'dBm'),
						E('span', {}, '-4' + NBSP + 'dBm')
					])
				]),
				E('div', { 'class': 'nnrrwrt-kv-grid' }, [
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('Mode & Registration')),
						E('span', { 'class': 'nnrrwrt-kv-val', 'translate': 'no' }, modeText)
					]),
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('OMCI / OAM Auth')),
						E('span', { 'class': 'nnrrwrt-kv-val' }, String(authText))
					]),
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('OLT Peer & Sync')),
						E('span', { 'class': 'nnrrwrt-kv-val is-mono', 'translate': 'no' }, oltText)
					]),
					E('div', { 'class': 'nnrrwrt-kv' }, [
						E('span', { 'class': 'nnrrwrt-kv-label' }, _('Service VLANs')),
						E('span', { 'class': 'nnrrwrt-kv-val is-mono', 'translate': 'no' }, vlanText)
					])
				])
			])
		]);
	},

	buildSiliconPanel: function() {
		var st = this._state;
		var sysinfo = st.latest.sysinfo || {};
		var tel = st.latest.telemetry || {};
		var accel = tel.accel || {};
		var ppe = accel.ppe || {};
		var mem = sysinfo.memory || {};
		var storage = tel.storage || {};
		var ubi = tel.ubi || {};

		var ppeHeadline = ppe.available
			? (fmtNum(ppe.bind || 0, 0, 0) + ' ' + _('bound') + ' / ' + fmtNum(ppe.total || 0, 0, 0) + ' ' + _('entries'))
			: (accel.hw_offload ? _('PPE flow offload enabled') : _('Software forwarding'));

		var ppeBreakdown = ppe.available
			? ('IPv4 ' + fmtNum(ppe.ipv4 || 0, 0, 0) + ', IPv6 ' + fmtNum(ppe.ipv6 || 0, 0, 0) + ', L2B ' + fmtNum(ppe.l2b || 0, 0, 0))
			: _('Flow table stats inactive');

		var cpuPct = st.cpuUsage.total;
		var loadArr = Array.isArray(sysinfo.load) ? sysinfo.load : [];
		var loadStr = loadArr.length >= 3
			? loadArr.slice(0, 3).map(function(v) { return (Number(v) / 65536).toFixed(2); }).join(', ')
			: '—';
		var cpuValText = (cpuPct !== null ? (fmtNum(cpuPct, 0, 0) + '% / ') : '') + _('Load') + ' ' + loadStr;
		var cpuScale = cpuPct !== null ? (cpuPct / 100) : 0;

		var memTotal = Number(mem.total) || 0;
		var memAvail = Number(mem.available) || ((Number(mem.free) || 0) + (Number(mem.buffered) || 0) + (Number(mem.cached) || 0));
		var memUsed = Math.max(0, memTotal - memAvail);
		var memCache = Math.max(0, (Number(mem.buffered) || 0) + (Number(mem.cached) || 0));
		var memUsedScale = memTotal > 0 ? Math.min(1, memUsed / memTotal) : 0;
		var memPlusCacheScale = memTotal > 0 ? Math.min(1, (memUsed + memCache) / memTotal) : 0;

		var stTotal = Number(storage.total_bytes) || 0;
		var stUsed = Number(storage.used_bytes) || 0;
		var stScale = stTotal > 0 ? Math.min(1, stUsed / stTotal) : 0;
		var ubiNote = ubi.present
			? (ubi.healthy ? _('UBI bosa/ri/fip verified') : (_('Check UBI: ') + (ubi.missing || []).join(', ')))
			: '';

		return E('section', { 'class': 'nnrrwrt-panel' }, [
			E('div', { 'class': 'nnrrwrt-panel-head' }, [
				E('h3', { 'class': 'nnrrwrt-panel-title' }, _('AN7581 Silicon & Hardware Offload')),
				E('a', {
					'class': 'nnrrwrt-panel-link',
					'href': L.url('admin/network/pon/hardware')
				}, _('Calibration & UBI backup'))
			]),
			E('div', { 'class': 'nnrrwrt-panel-body' }, [
				E('div', { 'class': 'nnrrwrt-ppe-box' }, [
					E('div', { 'class': 'nnrrwrt-ppe-top' }, [
						E('span', { 'class': 'nnrrwrt-ppe-count' }, ppeHeadline),
						E('span', { 'class': 'nnrrwrt-rate-sub', 'translate': 'no' }, ppeBreakdown)
					]),
					E('div', { 'class': 'nnrrwrt-chip-row' }, [
						E('span', {
							'class': 'nnrrwrt-chip' + (accel.hw_offload ? ' is-active' : '')
						}, accel.hw_offload ? _('PPE HW Offload') : (accel.sw_offload ? _('SW Flow Offload') : _('Offload disabled'))),
						accel.fullcone ? E('span', { 'class': 'nnrrwrt-chip is-active' }, 'FullCone NAT') : null,
						accel.packet_steering ? E('span', { 'class': 'nnrrwrt-chip is-active' }, _('Packet Steering')) : null,
						accel.eip93 ? E('span', { 'class': 'nnrrwrt-chip is-active', 'translate': 'no' }, 'EIP-93 Crypto') : null
					])
				]),
				E('div', { 'class': 'nnrrwrt-meter-list' }, [
					E('div', { 'class': 'nnrrwrt-meter' }, [
						E('div', { 'class': 'nnrrwrt-meter-head' }, [
							E('span', { 'class': 'nnrrwrt-meter-title' }, _('CPU Utilization')),
							E('span', { 'class': 'nnrrwrt-meter-val' }, cpuValText)
						]),
						E('div', { 'class': 'nnrrwrt-bar-track', 'aria-hidden': 'true' }, [
							E('div', {
								'class': 'nnrrwrt-bar-fill' + (cpuScale > 0.85 ? ' is-crit' : (cpuScale > 0.65 ? ' is-warn' : '')),
								'style': '--nd-scale:' + cpuScale.toFixed(3)
							})
						]),
						st.cpuUsage.cores.length > 0 ? E('div', { 'class': 'nnrrwrt-cores-row' },
							st.cpuUsage.cores.map(function(c) {
								return E('span', { 'class': 'nnrrwrt-core-cell', 'translate': 'no' }, [
									E('span', {}, c.label),
									E('strong', {}, fmtNum(c.pct, 0, 0) + '%')
								]);
							})
						) : null
					]),
					E('div', { 'class': 'nnrrwrt-meter' }, [
						E('div', { 'class': 'nnrrwrt-meter-head' }, [
							E('span', { 'class': 'nnrrwrt-meter-title' }, _('Memory')),
							E('span', { 'class': 'nnrrwrt-meter-val' },
								formatBytes(memUsed) + ' / ' + formatBytes(memTotal) +
								' (' + fmtNum(memUsedScale * 100, 0, 0) + '%)')
						]),
						E('div', { 'class': 'nnrrwrt-bar-track', 'aria-hidden': 'true' }, [
							E('div', {
								'class': 'nnrrwrt-bar-fill is-secondary',
								'style': '--nd-scale:' + memPlusCacheScale.toFixed(3)
							}),
							E('div', {
								'class': 'nnrrwrt-bar-fill',
								'style': '--nd-scale:' + memUsedScale.toFixed(3)
							})
						])
					]),
					E('div', { 'class': 'nnrrwrt-meter' }, [
						E('div', { 'class': 'nnrrwrt-meter-head' }, [
							E('span', { 'class': 'nnrrwrt-meter-title' },
								_('Storage') + (storage.mount ? ' (' + storage.mount + ')' : '')),
							E('span', { 'class': 'nnrrwrt-meter-val' },
								(stTotal > 0 ? (formatBytes(stUsed) + ' / ' + formatBytes(stTotal)) : '—') +
								(ubiNote ? (' (' + ubiNote + ')') : ''))
						]),
						E('div', { 'class': 'nnrrwrt-bar-track', 'aria-hidden': 'true' }, [
							E('div', {
								'class': 'nnrrwrt-bar-fill ' + (ubi.present && !ubi.healthy ? 'is-crit' : 'is-teal'),
								'style': '--nd-scale:' + stScale.toFixed(3)
							})
						])
					])
				])
			])
		]);
	},

	buildServicesPanel: function() {
		var services = (this._state.latest.telemetry && Array.isArray(this._state.latest.telemetry.services))
			? this._state.latest.telemetry.services
			: [];

		var activeCount = 0;
		var standbyCount = 0;
		services.forEach(function(svc) {
			if (svc.state === 'running' || svc.state === 'active')
				activeCount++;
			else if (svc.state === 'standby')
				standbyCount++;
		});

		var svcCards = services.map(function(svc) {
			var stateLabel = _('Standby (0 proc)');
			if (svc.state === 'running')
				stateLabel = _('Running');
			else if (svc.state === 'active')
				stateLabel = _('Active');
			else if (svc.state === 'stopped')
				stateLabel = _('Stopped');

			var displayName = svc.id === 'leds' ? _('LED Configuration') : svc.name;

			return E('a', {
				'class': 'nnrrwrt-svc-item',
				'href': L.url(svc.path || 'admin/system/startup')
			}, [
				E('span', { 'class': 'nnrrwrt-svc-left' }, [
					E('span', {
						'class': 'nnrrwrt-svc-dot is-' + (svc.state || 'standby'),
						'aria-hidden': 'true'
					}),
					E('span', {
						'class': 'nnrrwrt-svc-name',
						'translate': svc.id === 'leds' ? null : 'no'
					}, displayName)
				]),
				E('span', {
					'class': 'nnrrwrt-svc-state is-' + (svc.state || 'standby')
				}, stateLabel)
			]);
		});

		return E('section', { 'class': 'nnrrwrt-panel' }, [
			E('div', { 'class': 'nnrrwrt-panel-head' }, [
				E('h3', { 'class': 'nnrrwrt-panel-title' }, _('Service Runtime & Navigation')),
				E('a', {
					'class': 'nnrrwrt-panel-link',
					'href': L.url('admin/system/startup')
				}, _('Manage startup'))
			]),
			E('div', { 'class': 'nnrrwrt-panel-body' }, [
				E('div', { 'class': 'nnrrwrt-rate-sub' },
					fmtNum(activeCount, 0, 0) + ' ' + _('active') + ', ' +
					fmtNum(standbyCount, 0, 0) + ' ' + _('on standby without background processes')),
				E('div', { 'class': 'nnrrwrt-svc-grid' }, svcCards),
				E('div', { 'class': 'nnrrwrt-svc-note' },
					_('Unconfigured services such as Tailscale and DDNS stay in zero-process standby until enabled.'))
			])
		]);
	},

	buildTree: function() {
		var st = this._state;
		return [
			st.lastError ? E('div', {
				'class': 'nnrrwrt-live-status',
				'aria-live': 'polite'
			}, st.lastError) : null,
			this.buildChassisSection(),
			E('div', { 'class': 'nnrrwrt-band nnrrwrt-band-top' }, [
				this.buildTrafficSessionPanel(),
				this.buildOpticsPanel()
			]),
			E('div', { 'class': 'nnrrwrt-band nnrrwrt-band-bottom' }, [
				this.buildSiliconPanel(),
				this.buildServicesPanel()
			])
		];
	},

	refreshDom: function() {
		if (!this._root)
			return;
		dom.content(this._root, this.buildTree());
	},

	render: function(initialBundle) {
		var self = this;
		this.ingestSample(initialBundle);

		var root = E('div', { 'class': 'nnrrwrt-dash' }, this.buildTree());
		this._root = root;

		window.setTimeout(function() {
			if (!document.body.contains(root) || self._state.paused)
				return;
			self.fetchBundle().then(function(b) {
				if (!document.body.contains(root) || self._state.paused)
					return;
				self._state.lastError = null;
				self.ingestSample(b);
				self.refreshDom();
			}).catch(function() {});
		}, 450);

		poll.add(function() {
			if (self._state.paused)
				return Promise.resolve();
			return self.fetchBundle().then(function(b) {
				self._state.lastError = null;
				self.ingestSample(b);
				self.refreshDom();
			}).catch(function() {
				self._state.lastError = _('Telemetry refresh failed; retrying automatically…');
				self.refreshDom();
			});
		}, 2);

		return root;
	}
});
