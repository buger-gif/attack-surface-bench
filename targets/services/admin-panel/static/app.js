// SECURITY-REVIEWED: 2026-07-09 | RULES: v2.6.0-draft
// admin-panel/static/app.js
(function() {
    'use strict';
    window.APP_DEBUG = true;
    window.API_PARAMS = {
        mock: 'mock=1', trace: 'trace=1', debug: 'debug=1',
        nocache: 'nocache=1', preview: 'preview=1', raw: 'raw=1',
        test: 'test=1', sandbox: 'sandbox=1', force: 'force=1'
    };
    function fetchUsers(options) {
        const url = '/api/users?' + (options.nocache ? 'nocache=1&' : '');
        if (options.jsonp) return fetch(url + 'callback=' + options.callback);
        return fetch(url + 'format=json');
    }
    function exportData(format) {
        window.location = '/api/users?format=' + (format || 'csv');
    }
    function internalCall(endpoint) {
        return fetch(endpoint + '?internal=true');
    }
    function sandboxMode() {
        return fetch('/api/system/status?sandbox=1');
    }
})();
//# sourceMappingURL=app.js.map
