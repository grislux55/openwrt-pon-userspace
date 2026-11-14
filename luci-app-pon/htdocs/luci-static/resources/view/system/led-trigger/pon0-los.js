'use strict';
'require baseclass';

return baseclass.extend({
	trigger: _('PON optical signal loss (kernel: pon0-los)'),
	description: _('Blinks when PON optical signal loss (LOS) is detected and stays off while optical signal is present.'),
	kernel: true,
	addFormOptions: function(s) {}
});
