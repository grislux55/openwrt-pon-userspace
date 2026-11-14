'use strict';
'require baseclass';

return baseclass.extend({
	trigger: _('PON registration state (kernel: pon0-registration)'),
	description: _('Blinks fast during discovery, blinks slowly while ranging, and stays lit once O5 or MPCP registration completes.'),
	kernel: true,
	addFormOptions: function(s) {}
});
