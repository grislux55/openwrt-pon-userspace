'use strict';
'require baseclass';

return baseclass.extend({
	trigger: _('PON service online (kernel: pon0-online)'),
	description: _('Lights up when the PON line has optical signal and the data path is ready for service.'),
	kernel: true,
	addFormOptions: function(s) {}
});
