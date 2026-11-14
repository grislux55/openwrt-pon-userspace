// SPDX-License-Identifier: Apache-2.0

'use strict';
'require fs';
'require form';
'require ui';
'require uci';
'require view';

/* Printable ASCII keeps JavaScript character counts equal to wire byte counts. */
function validatePrintableAscii(value, minimum, maximum) {
	if (value == null || value === '')
		return true;

	if (!/^[\x20-\x7e]+$/.test(value))
		return _('Only printable ASCII characters are allowed.');

	if (value.length < minimum || value.length > maximum) {
		if (minimum === maximum)
			return _('The value must contain exactly %d bytes.').format(maximum);

		return _('The value must contain between %d and %d bytes.')
			.format(minimum, maximum);
	}

	return true;
}

function asciiLength(minimum, maximum) {
	return function(sectionId, value) {
		return validatePrintableAscii(value, minimum, maximum);
	};
}

function validateSerialNumber(sectionId, value) {
	if (value == null || value === '')
		return true;

	if (/^[0-9a-fA-F]{16}$/.test(value) ||
	    /^[A-Za-z0-9]{4}[0-9a-fA-F]{8}$/.test(value))
		return true;

	return _('Use 16 hexadecimal digits or VEND followed by 8 hexadecimal digits.');
}

function validateChipsetId(sectionId, value) {
	if (value == null || value === '' || /^[0-9a-fA-F]{16}$/.test(value))
		return true;

	return _('Use 16 hexadecimal digits.');
}

function isEponMode(mode) {
	return (mode || '').indexOf('epon-') === 0;
}

function sectionUsesEpon(sectionId) {
	var line = uci.get('pon', sectionId, 'line');

	return isEponMode(uci.get('pon', line, 'mode'));
}

function formatStorageSize(bytes) {
	var units = [ 'B', 'KiB', 'MiB', 'GiB' ];
	var size = Number(bytes);
	var unit = 0;

	while (size >= 1024 && unit < units.length - 1) {
		size /= 1024;
		unit++;
	}

	return '%s %s'.format(size >= 10 || unit === 0 ? size.toFixed(0) : size.toFixed(1), units[unit]);
}

function parseStorageList(output) {
	var targets = JSON.parse(output);
	return Object.keys(targets).map(function(name) {
		var target = targets[name];
		return {
			id: name,
			label: '%s · %s · %s'.format(
				name, target.type.toUpperCase(), formatStorageSize(target.size))
		};
	});
}

function downloadBlob(path, filename) {
	return fs.read_direct(path, 'blob').then(function(blob) {
		var url = window.URL.createObjectURL(blob);
		var link = document.createElement('a');

		link.style.display = 'none';
		link.href = url;
		link.download = filename;
		document.body.appendChild(link);
		link.click();
		link.remove();
		window.URL.revokeObjectURL(url);
	});
}

function formatVolumeRole(role) {
	switch (role) {
	case 'calibration': return _('Optical calibration');
	case 'identity': return _('Board identity');
	case 'bootloader': return _('Bootloader (BL31 / U-Boot)');
	case 'ubootenv': return _('U-Boot environment');
	case 'ubootenv_redundant': return _('U-Boot redundant environment');
	default: return _('Board data');
	}
}

function formatVolumeStatus(vol) {
	if (vol.status === 'ok')
		return _('OK');
	if (vol.status === 'missing')
		return _('Missing');
	if (vol.error && vol.error.indexOf('empty') !== -1)
		return _('Empty');
	return _('Read error');
}

function formatVolumeStorage(vol) {
	var details = [];

	if (!vol.present)
		return '%s (%s)'.format((vol.storage || 'ubi').toUpperCase(), _('Missing'));
	if (vol.device)
		details.push(vol.device);
	if (vol.volume_type)
		details.push(vol.volume_type);
	return details.length
		? '%s (%s)'.format((vol.storage || 'ubi').toUpperCase(), details.join(', '))
		: (vol.storage || 'ubi').toUpperCase();
}

function formatVolumeBytes(vol) {
	if (!vol.present)
		return '-';
	if (vol.reserved_bytes > 0)
		return '%s / %s'.format(
			formatStorageSize(vol.data_bytes || 0),
			formatStorageSize(vol.reserved_bytes));
	return formatStorageSize(vol.data_bytes || 0);
}

return view.extend({
	load: function() {
		return Promise.all([
			fs.exec('/usr/libexec/airoha-pon-data', [ 'list' ]).then(function(result) {
				if (result.code != 0)
					throw new Error(result.stderr || result.stdout || _('Unable to list storage.'));

				return parseStorageList(result.stdout);
			}),
			fs.exec('/usr/libexec/airoha-pon-data', [ 'status' ]).then(function(result) {
				if (result.code != 0)
					return null;
				try {
					return JSON.parse(result.stdout);
				} catch (e) {
					return null;
				}
			}).catch(function() {
				return null;
			})
		]);
	},

	handleBoardDataExport: function(storage, ev) {
		var button = ev && ev.currentTarget ? ev.currentTarget : null;

		if (button) {
			button.disabled = true;
			button.classList.add('spinning');
		}
		return fs.exec('/usr/libexec/airoha-pon-data', [ 'export', storage.id ]).then(function(result) {
			if (result.code != 0)
				throw new Error((result.stderr || result.stdout || _('Helper exited with status %d').format(result.code)).trim());
			var meta;
			try {
				meta = JSON.parse(result.stdout);
			} catch (e) {
				throw new Error(result.stderr || _('Invalid JSON response from helper.'));
			}

			return downloadBlob(meta.path, storage.id + '.bin').then(function() {
				ui.addNotification(null, E('p', [
					_('Exported %s (%s).').format(storage.id + '.bin', formatStorageSize(meta.size)),
					E('br'),
					'SHA-256: ' + (meta.sha256 || '-')
				]), 'info');
			});
		}).catch(function(error) {
			ui.addNotification(null, E('p', [
				_('Exporting %s failed: %s').format(storage.id, error.message)
			]), 'danger');
		}).finally(function() {
			if (button) {
				button.disabled = false;
				button.classList.remove('spinning');
			}
		});
	},

	handleCriticalBackup: function(ev) {
		var button = ev && ev.currentTarget ? ev.currentTarget : null;
		var ts = new Date().toISOString().replace(/[:.]/g, '-');

		if (button) {
			button.disabled = true;
			button.classList.add('spinning');
		}
		return fs.exec('/usr/libexec/airoha-pon-data', [ 'backup' ]).then(function(result) {
			if (result.code != 0)
				throw new Error((result.stderr || result.stdout || _('Helper exited with status %d').format(result.code)).trim());
			var meta;
			try {
				meta = JSON.parse(result.stdout);
			} catch (e) {
				throw new Error(result.stderr || _('Invalid JSON response from helper.'));
			}
			var filename = meta.complete
				? ('pon-ubi-backup-' + ts + '.tar.gz')
				: ('pon-ubi-backup-partial-' + ts + '.tar.gz');

			return downloadBlob(meta.path, filename).then(function() {
				if (!meta.complete) {
					ui.addNotification(null, E('p', [
						_('Partial UBI backup downloaded (%d/%d volumes). Missing or unreadable volumes are recorded in MANIFEST.txt: %s')
							.format(meta.ok_count, meta.total_count, (meta.warnings || []).join('; '))
					]), 'warning');
				} else {
					ui.addNotification(null, E('p', [
						_('Complete UBI backup downloaded (%d/%d volumes, %s).')
							.format(meta.ok_count, meta.total_count, formatStorageSize(meta.size)),
						E('br'),
						'SHA-256: ' + (meta.sha256 || '-')
					]), 'info');
				}
			});
		}).catch(function(error) {
			ui.addNotification(null, E('p', [
				_('Creating critical UBI backup failed: %s').format(error.message)
			]), 'danger');
		}).finally(function() {
			if (button) {
				button.disabled = false;
				button.classList.remove('spinning');
			}
		});
	},

	renderVolumeHealthSection: function(volumeStatus) {
		if (!volumeStatus || !Array.isArray(volumeStatus.volumes))
			return null;

		var summaryClass = volumeStatus.sysupgrade_ready
			? 'alert-message success'
			: 'alert-message warning';
		var summaryText = volumeStatus.sysupgrade_ready
			? _('Sysupgrade UBI layout check passed: all critical volumes (bosa, ri, fip, ubootenv, ubootenv2) are present and FIP is non-empty.')
			: _('Sysupgrade UBI layout check incomplete: missing or invalid volumes (%s). Repair the UBI layout before flashing.')
				.format((volumeStatus.missing_required || []).join(', ') || _('unknown'));

		var rows = [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('Volume')),
				E('th', { 'class': 'th' }, _('Purpose')),
				E('th', { 'class': 'th' }, _('Access')),
				E('th', { 'class': 'th' }, _('Storage')),
				E('th', { 'class': 'th' }, _('Data / Reserved')),
				E('th', { 'class': 'th' }, _('Status'))
			])
		];

		volumeStatus.volumes.forEach(function(vol) {
			var statusText = formatVolumeStatus(vol);
			if (vol.status !== 'ok' && vol.error)
				statusText += ' (' + vol.error + ')';

			rows.push(E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, E('strong', {}, vol.name)),
				E('td', { 'class': 'td' }, formatVolumeRole(vol.role)),
				E('td', { 'class': 'td' }, vol.writable ? _('Read / Write') : _('Read-only')),
				E('td', { 'class': 'td' }, formatVolumeStorage(vol)),
				E('td', { 'class': 'td' }, formatVolumeBytes(vol)),
				E('td', { 'class': 'td' }, statusText)
			]));
		});

		return E('div', { 'class': 'cbi-section' }, [
			E('h3', {}, _('Critical UBI volume health')),
			E('div', { 'class': 'cbi-section-descr' },
				_('Read-only status of calibration, identity, bootloader and U-Boot environment volumes. The bl2 partition is intentionally excluded and stays read-only.')),
			E('div', { 'class': summaryClass }, summaryText),
			E('table', { 'class': 'table' }, rows)
		]);
	},

	handleBoardDataUpload: function(storages, selector) {
		var storage = storages[Number(selector.value)];

		return ui.uploadFile('/tmp/pon-board-data.bin').then(function() {
			return fs.exec('/usr/libexec/airoha-pon-data', [ 'write', storage.id ]).then(function(result) {
				if (result.code != 0)
					throw new Error(result.stderr || result.stdout || _('Write failed.'));

				var message = [
					_('Board data written to %s and verified. Reboot the device to apply it.')
						.format(storage.label)
				];
				if (result.stdout.trim())
					message.push(E('br'), result.stdout.trim());
				ui.addNotification(null, E('p', message));
			}).catch(function(error) {
				ui.addNotification(null, E('p', [
					_('Writing board data failed: %s').format(error.message)
				]));
			});
		});
	},

	render: function(loaded) {
		var storages = loaded[0] || [];
		var volumeStatus = loaded[1] || null;
		var m, s, o, selector;

		m = new form.Map('pon', _('PON'),
			_('Project source:') +
			' <a href="https://github.com/grislux55/nnrrwrt-packages/tree/main/luci-app-pon" target="_blank" rel="noreferrer noopener">nnrrwrt-packages/luci-app-pon</a>');
		m.readonly = !L.hasViewPermission();

		s = m.section(form.TypedSection, 'xpon', _('PON line'));
		s.anonymous = false;
		s.addremove = false;
		s.description = _('Line mode and registration identity take effect after the PON interface restarts.');

		o = s.option(form.DummyValue, 'device', _('PON interface'));
		o.default = '-';

		o = s.option(form.ListValue, 'mode', _('Line mode'));
		o.default = '';
		o.value('', _('Driver default'));
		o.value('xgpon', _('XG-PON'));
		o.value('xgspon', _('XGS-PON'));
		o.value('epon-10g-1g', _('10G-EPON 10G/1G'));
		o.value('epon-10g-10g', _('10G-EPON 10G/10G'));

		o = s.option(form.Value, 'serial_number', _('Serial number (SN)'));
		o.placeholder = _('Board serial number');
		o.rmempty = true;
		o.validate = validateSerialNumber;
		o.depends('mode', '');
		o.depends('mode', 'xgpon');
		o.depends('mode', 'xgspon');

		o = s.option(form.Value, 'registration_id', _('Registration-ID'));
		o.password = true;
		o.rmempty = true;
		o.depends('mode', '');
		o.depends('mode', 'xgpon');
		o.depends('mode', 'xgspon');
		o.validate = asciiLength(1, 36);
		o.description = _('Optional; sent as all zeros when empty.');

		s = m.section(form.TypedSection, 'omci', _('OMCI settings'));
		s.anonymous = false;
		s.addremove = false;
		s.filter = function(sectionId) {
			return !sectionUsesEpon(sectionId);
		};
		s.tab('authentication', _('Authentication'));
		s.tab('identity', _('ONU identity'));
		s.tab('compatibility', _('Compatibility'));

		o = s.taboption('authentication', form.DummyValue, 'line', _('XG-PON configuration'));
		o.default = '-';

		o = s.taboption('authentication', form.DummyValue, 'device', _('OMCI interface'));
		o.default = '-';

		o = s.taboption('authentication', form.Value, 'loid', _('LOID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 24);

		o = s.taboption('authentication', form.Value, 'loid_password', _('LOID password'));
		o.password = true;
		o.rmempty = true;
		o.validate = asciiLength(1, 12);

		o = s.taboption('identity', form.Value, 'vendor_id', _('Vendor ID'));
		o.rmempty = true;
		o.validate = asciiLength(4, 4);
		o.description = _('Usually the same as the first four characters of the serial number.');

		o = s.taboption('identity', form.Value, 'equipment_id', _('Equipment ID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 20);

		o = s.taboption('identity', form.Value, 'hardware_version', _('Hardware version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 14);

		o = s.taboption('identity', form.Value, 'software_version', _('Software version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 14);

		o = s.taboption('identity', form.Value, 'operator_id', _('Operator ID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 4);

		o = s.taboption('compatibility', form.ListValue, 'omcc_version', _('OMCC version'));
		o.value('0xb0', '0xb0');
		o.value('0x86', '0x86');
		o.default = '0xb0';
		o.rmempty = false;
		o.description = _('If the ONU cannot register with a Huawei OLT, try OMCC version 0x86.');

		o = s.taboption('compatibility', form.Flag, 'disable_enhanced_security', _('Disable enhanced security (Class 332)'));
		o.default = '0';
		o.rmempty = true;

		o = s.taboption('compatibility', form.Value, 'alloc_id_timeout', _('Alloc-ID wait timeout'));
		o.datatype = 'uinteger';
		o.placeholder = '30';
		o.rmempty = true;
		o.description = _('Seconds a data path may wait for PLOAM to assign its Alloc-ID before it is reported as failed. The ONU keeps waiting afterwards; 0 disables the timeout.');

		s = m.section(form.TypedSection, 'oam', _('EPON OAM settings'));
		s.anonymous = false;
		s.addremove = false;
		s.filter = function(sectionId) {
			return sectionUsesEpon(sectionId);
		};
		s.tab('authentication', _('Authentication'));
		s.tab('identity', _('ONU identity'));

		o = s.taboption('authentication', form.DummyValue, 'line', _('EPON configuration'));
		o.default = '-';

		o = s.taboption('authentication', form.DummyValue, 'device', _('OAM interface'));
		o.default = '-';

		o = s.taboption('authentication', form.ListValue, 'operator', _('OAM profile'));
		o.default = 'ctc';
		o.value('ieee', _('IEEE 802.3ah'));
		o.value('ctc', _('IEEE 802.3ah + CTC'));

		o = s.taboption('authentication', form.Value, 'loid', _('LOID'));
		o.rmempty = true;
		o.depends('operator', 'ctc');
		o.validate = asciiLength(1, 24);

		o = s.taboption('authentication', form.Value, 'loid_password', _('LOID password'));
		o.password = true;
		o.rmempty = true;
		o.depends('operator', 'ctc');
		o.validate = asciiLength(1, 12);

		o = s.taboption('identity', form.Value, 'vendor_id', _('Vendor ID'));
		o.rmempty = true;
		o.validate = asciiLength(4, 4);

		o = s.taboption('identity', form.Value, 'model', _('ONU short model'));
		o.rmempty = true;
		o.validate = asciiLength(4, 4);

		o = s.taboption('identity', form.Value, 'equipment_id', _('Equipment ID'));
		o.rmempty = true;
		o.validate = asciiLength(1, 16);

		o = s.taboption('identity', form.Value, 'hardware_version', _('Hardware version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 8);

		o = s.taboption('identity', form.Value, 'software_version', _('Software version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 16);

		o = s.taboption('identity', form.Value, 'firmware_version', _('Firmware version'));
		o.rmempty = true;
		o.validate = asciiLength(1, 127);

		o = s.taboption('identity', form.Value, 'chipset_id', _('Chipset ID'));
		o.rmempty = true;
		o.validate = validateChipsetId;

		o = s.taboption('identity', form.Value, 'ge_ports', _('Ethernet port count'));
		o.default = '1';
		o.datatype = 'range(1,64)';

		return m.render().then(L.bind(function(map) {
			var sections = [ map ];
			var healthCard = this.renderVolumeHealthSection(volumeStatus);
			var boardRows = [];

			if (healthCard)
				sections.push(healthCard);

			if (storages.length) {
				selector = E('select', { 'class': 'cbi-input-select' },
					storages.map(function(storage, index) {
						return E('option', { 'value': String(index) }, storage.label);
					}));

				boardRows.push(E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Target storage')),
					E('div', { 'class': 'cbi-value-field' }, [
						selector,
						E('button', {
							'class': 'cbi-button cbi-button-action',
							'disabled': m.readonly || null,
							'click': ui.createHandlerFn(this, 'handleBoardDataUpload', storages, selector)
						}, [ _('Upload and write') ])
					])
				]));

				boardRows.push(E('div', { 'class': 'cbi-value' }, [
					E('label', { 'class': 'cbi-value-title' }, _('Single volume export (read-only)')),
					E('div', { 'class': 'cbi-value-field' },
						storages.map(L.bind(function(storage) {
							return E('button', {
								'class': 'cbi-button cbi-button-neutral',
								'style': 'margin-right: 0.5em;',
								'click': ui.createHandlerFn(this, 'handleBoardDataExport', storage)
							}, [ _('Download %s').format(storage.id + '.bin') ]);
						}, this))
					)
				]));
			}

			boardRows.push(E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Full critical UBI backup')),
				E('div', { 'class': 'cbi-value-field' }, [
					E('button', {
						'class': 'cbi-button cbi-button-apply',
						'click': ui.createHandlerFn(this, 'handleCriticalBackup')
					}, [ _('Download full UBI backup (.tar.gz)') ]),
					E('div', { 'class': 'cbi-value-description' },
						_('Archives bosa, ri, fip, ubootenv and ubootenv2 (read-only, excluding bl2) with SHA-256 MANIFEST.txt. If any volume is missing or unreadable, available volumes are still included with a warning.'))
				])
			]));

			sections.push(E('div', { 'class': 'cbi-section' },
				[ E('h3', {}, _('PON board data')) ].concat(boardRows)));

			return E([], sections);
		}, this));
	}
});
