// before making a change, make sure that tests in /tests/ucwa/xframe.js pass
(function () {
    'use strict';

    // In the implicit OAuth2 flow the access token is sent by Azure AD inside the fragment part: 
    // .../xframe#access_token=ABC&token_type=Bearer&state=123
    //
    // In case of an error, its description is also specified in the URL parameters:
    // .../xframe#error=invalid_resource&error_description=...
    //
    var args = decodeArgs(location.hash.slice(1));

    // Prevent IE from sending it in the Referer header.
    // Note, that changing .hash doesn't reload the xframe.
    if (location.hash)
        location.hash = '';

    // The xframe allows to send the OAuth token only to the same server
    // where the xframe (and UCWA) is hosted. This prevents stealing the
    // token by untrusted sites. However if the xframe was used to get a
    // token for a resource different from UCWA, then it makes sense to
    // send the token to that resource server. The resource's URL can be
    // extracted from the token, but since the token's format is undocumented,
    // the list of such trusted external resources is listed here.
    var trusted_graph_urls = [
        'https://graph.ppe.windows.net/',
        'https://graph.windows.net/',
        'https://graph.microsoft.com/'
    ];

    // ECWS is turned off, keeping these urls just in case 
    var trusted_ecws_urls = [
        'https://ecwsc2cint.westus.cloudapp.azure.com/',
        'https://ecwsc2cdg.westus.cloudapp.azure.com/',
        'https://perfevent.westus.cloudapp.azure.com/',
        'https://nawest.ecws.services.skypeforbusiness.com/',
        'https://naeast.ecws.services.skypeforbusiness.com/',
        'https://nacntrl.ecws.services.skypeforbusiness.com/',
        'https://c2cint.ecws.services.skypeforbusiness.com/',
        'https://c2cdg.ecws.services.skypeforbusiness.com/',
        'https://euwest.ecws.services.skypeforbusiness.com/',
        'https://eunorth.ecws.services.skypeforbusiness.com/',
        'https://asiase.ecws.services.skypeforbusiness.com/',
        'https://asiaeast.ecws.services.skypeforbusiness.com/'
    ];

    var origins = {}; // origins[url] tells whether url is whitelisted
    var pending_whitelist_checks = {};

    // parses inputs like "A=1&B=2&C=3"
    function decodeArgs(str) {
        var i, kv, q = {}, pairs = str ? str.split('&') : [];

        for (i = 0; i < pairs.length; i++) {
            kv = pairs[i].split('=');
            q[decodeArg(kv[0])] = decodeArg(kv[1] || '');
        }

        return q;
    }

    function decodeArg(str) {
        return decodeURIComponent(str.replace(/\+/gm, ' '));
    }

    function isTrustedUrl(url, trusted_urls) {
        for (var i = 0; i < trusted_urls.length; i++) {
            var t = trusted_urls[i];

            if (url.slice(0, t.length) == t)
                return true;
        }
        return false;
    }

    function isTrustedGraphUrl(url) {
        return isTrustedUrl(url, trusted_graph_urls);
    }

    function isTrustedEcwsUrl(url) {
        return isTrustedUrl(url, trusted_ecws_urls);
    }

    // ECWS is turned off, so we are checking graph urls only. If ECWS ever comes back
    // return isTrustedGraphUrl(url) || isTrustedEcwsUrl(url)
    function isTrusted(url) {
        return isTrustedGraphUrl(url);
    }

    function parseUrl(url) {
        var s, domain, parts, len;
        // RFC 3986 specifies an ABNF of URI which has the following structure:
        // [scheme ":"] ["//" [user "@"] host [":" port]] path ["?" query] ["#" hash]
        var p = /^(?:([a-zA-Z][\w+-.]*):)?(?:\/\/(?:([^/@]*)@)?([^:/?#]*)(?:\:(\d*))?)?([^?#]*)(\?([^#]*))?(#(.*))?$/.exec(url);
        if (!p)
            return null;

        s = (p[5] || '/') + (p[6] || '') + (p[8] || '');
        s = s[0] == '/' ? s : '/' + s;

        domain = p[3]; // hostname
        if (domain) {
            parts = domain.split('.');
            len = parts.length;
            if (len > 2) {
                domain = parts[len - 2] + '.' + parts[len - 1];
                // is it a ccTLD ("co.uk")?
                if (parts[len - 2].length == 2 && parts[len - 1].length == 2) {
                    domain = parts[len - 3] + '.' + domain;
                }
            }
        }

        return { scheme: p[1], user: p[2], host: p[3], port: p[4], path: p[5], query: p[7], hash: p[9], fullPath: s, domain: domain};
    }

    // extracts from a URL its path, query and hash
    function extractUrlPath(url) {
        var p = parseUrl(url);
        return p && p.fullPath;
    }

    function validateHeaders(headers) {
        for (var name in headers) {
            if (/[\x00-\x20()<>@,;:\x5C\x22\x2F?={}\x7F]/.test(name))
                throw new SyntaxError('Invalid header: ' + name + ' (see RFC 2616 sections 2.2 and 4.2)');

            if (/^X-Ms-Origin$/i.test(name))
                throw new Error('Unsafe header: ' + name);
        }
    }

    // parses a raw header string (as returned by xhr.getAllResponseHeaders) into a dictionary
    function headers(text) {

        // the header names are normalized, i.e. look like dash-separated
        // sequences of words in which the first letter is capital: X-Ms-Server-Fqdn
        var headers = {};
        var lines = text ? text.split('\r\n') : [];
        var sep, name, value, line;

        function normalize(name) {
            return name.toLowerCase().replace(/\b(\w)/g, 
                function (char) { return char.toUpperCase() });
        }

        function trim(s) {
            return s.trim ? s.trim() : s.replace(/^\s+|\s+$/gm, '');
        }

        for (var i = 0; i < lines.length; i++) {
            if (line = trim(lines[i])) {
                sep = line.indexOf(':');
                if (sep >= 0) {
                    name = trim(line.substr(0, sep));
                    value = trim(line.substr(sep + 1));

                    name = normalize(name);
                    if (headers[name])
                        headers[name] += '\n' + value;
                    else
                        headers[name] = value;
                }
            }
        }

        return headers;
    }

    // there may be existing web apps that depend on the deprecated jQuery.ajax
    // interface; to avoid breaking them, some parts of that interface are handled
    function handleDeprecatedInterface(request) {
        if (request.accepts && request.accepts['*'])
            request.headers['Accept'] = request.accepts['*'];

        // the absence of this header is treated differently in different browsers:
        // some may set */*, while others may set something like application/xml
        if (!request.headers['Accept'])
            request.headers['Accept'] = '*/*';

        if (request.contentType)
            request.headers['Content-Type'] = request.contentType;

        if (request.data && typeof request.data != 'string') {
            request.data = makeQueryString(request.data);
            request.headers['Content-Type'] = 'application/x-www-form-urlencoded; charset=UTF-8';
        }

        if (request.type == 'GET' && request.data) {
            request.url = /^[^#]*/.exec(request.url)[0]; // remove the fragment after #...
            request.url += (request.url.indexOf('?') < 0 ? '?' : '&') + request.data;
            delete request.data;
        }
    }

    function makeQueryString(values) {
        var i, v, q = [];

        for (i in values) {
            v = values[i];
            if (v === null)
                v = '';
            if (v !== void 0)
                q.push(encodeURIComponent(i) + '=' + encodeURIComponent(v + ''));
        }

        return q.join('&');
    }

    function sendRequest(request, callback) {
        var i, xhr = new XMLHttpRequest;

        handleDeprecatedInterface(request);

        xhr.open(request.type, request.url, true);

        for (i in request.headers)
            if (request.headers[i])
                xhr.setRequestHeader(i, request.headers[i]);

        xhr.onreadystatechange = function () {
            if (xhr.readyState == 4 /* DONE */) {
                callback({
                    // in some cases IE replaces 204 with 1223
                    status: xhr.status == 1223 ? 204 : xhr.status,
                    statusText: xhr.statusText,
                    headers: xhr.getAllResponseHeaders(),
                    responseText: xhr.responseText
                });
            }
        };

        xhr.send(request.data || null);
    }

    function addListener(event, callback) {
        if (window.addEventListener)
            window.addEventListener(event, callback, false);
        else if (window.attachEvent) // IE 8
            window.attachEvent('on' + event, callback);
        else
            throw new Error('Cannot add an event listener to the ' + event + ' event.');
    }

    addListener('message', function (e) {
        try { if (!JSON.parse) { return } } catch (err) { return } // accessing JSON may throw in IE
        var request = JSON.parse(e.data);

        function sendResponse(response) {
            try { if (!JSON.stringify) { return } } catch (err) { return } // accessing JSON may throw in IE
            response.messageId = request.messageId;
            e.source.postMessage(JSON.stringify(response), '*');
        }

        function verifyCaller(e) {
            var callerUrl = parseUrl(e.origin);
            var thisUrl = parseUrl(location.origin);
            if (callerUrl.domain !== thisUrl.domain)
                throw new Error('The caller is not trusted');
        }

        function sendRequestViaAuthXframe(request, ucwa_oauth_uri) {
            var iframe;
            iframe = document.createElement('iframe');
            iframe.style.display = 'none';
            iframe.title = (new Date).toJSON();
            iframe.id = "auth_xframe_id";
            iframe.name = "auth_xframe_name";
            iframe.src = ucwa_oauth_uri;
            iframe.onload = function () {
                iframe.contentWindow.postMessage(JSON.stringify(request), '*');
            }
            document.body.appendChild(iframe);
            return iframe;
        }

        function prepareRequest(type, origin) {
            request.type = type;
            request.headers = request.headers || {};
            validateHeaders(request.headers);
            request.headers['X-Ms-Origin'] = origin;
        }

        var rargs = request.type.split(':');
        var rtype = rargs[0].toUpperCase();
        var data = request.data;
        var auth_frame, hdr, is_auth_request;

        try {
            switch (rtype) {
                case 'PING':
                    return sendResponse({
                        status: 200,
                        oauth2: args.error && { error: args.error } // AAD error codes do not contain PII
                    });

                case 'WHITELISTED':
                    // parent xframe receives a response from a child auth xframe;
                    // make sure this is a request from a child iframe by matching the domain
                    verifyCaller(e);

                    auth_frame = pending_whitelist_checks[request.messageId];
                    if (auth_frame) {
                        hdr = headers(request.headers)['X-Ms-Origin-Allowed'];
                        if (hdr) {
                            origins[hdr] = true;
                        }
                        document.body.removeChild(auth_frame.iframe);
                        auth_frame.source.postMessage(JSON.stringify(request), '*');
                        delete pending_whitelist_checks[request.messageId];
                        auth_frame = null;
                    }
                    break;

                case 'GET':
                    // a special request to figure out if the origin is whitelisted
                    is_auth_request = /^\/ucwa\/oauth\/?$/i.test(request.url);
                    if (is_auth_request && data) {
                        // xframe handles a request from the app
                        if (data.origin === undefined) {
                            prepareRequest(rtype, e.origin);

                            // try an unauthenticated request first
                            delete request.headers['Authorization'];
                            delete request.data;
                            sendRequest(request, function (response) {
                                if (headers(response.headers)['X-Ms-Origin-Allowed'] == e.origin) {
                                    origins[e.origin] = true;
                                    sendResponse(response);
                                } else if (data.ucwa_oauth_uri) {
                                    // if an unauthenticated request told us nothing resend this 
                                    // request via an auth xframe
                                    request.data = { origin: e.origin };
                                    delete request.headers['X-Ms-Origin'];
                                    pending_whitelist_checks[request.messageId] = {
                                        iframe: sendRequestViaAuthXframe(request, data.ucwa_oauth_uri),
                                        source: e.source
                                    };
                                } else {
                                    sendResponse(response);
                                }
                            });
                        // child auth xframe handles a request from a parent xframe 
                        } else { 
                            // make sure this is a request from a parent xframe (like graph) by matching the domain
                            verifyCaller(e);

                            // auth failed when auth xframe was created 
                            if (args.error) {
                                return sendResponse({
                                    type: 'WHITELISTED',
                                    status: 401,
                                    oauth2: args.error
                                });
                            }

                            prepareRequest(rtype, request.data.origin);
                            delete request.data;
                            request.url = (location.origin || location.protocol + '//' + location.hostname + (location.port ? ':' + location.port : '')) + extractUrlPath(request.url);
                            request.headers['Authorization'] = args.token_type + ' ' + args.access_token;
                            sendRequest(request, function (response) {
                                response.type = 'WHITELISTED';
                                sendResponse(response);
                            });
                        }
                        break;
                    } // this clause should be removed once all WebSDK and UCWA deployments are updated
                    else if (is_auth_request) {
                        prepareRequest(rtype, e.origin);
                        sendRequest(request, function (response) {
                            var code = response.status;
                            if (code >= 200 && code < 300 || code == 401)
                                origins[e.origin] = true;

                            sendResponse(response);
                        });
                        break;
                    }
                case 'POST':
                case 'PUT':
                case 'DELETE':
                case 'OPTIONS':
                    prepareRequest(rtype, e.origin);

                    if (args.access_token && request.headers['Authorization'] === undefined) {
                        // the destination's scheme and host name are determined by the xframe's origin
                        if (location.protocol != 'https:')
                            throw new Error('Token can be sent only via HTTPS.');

                        // check whether origin is whitelisted
                        if (isTrusted(request.url) && !origins[e.origin])
                            throw new Error('The origin is not trusted.');

                        // allow read-only access to trusted domains
                        if (isTrusted(request.url) && rtype !== 'GET' && rtype !== 'OPTIONS')
                            throw new Error('The method is not allowed.');

                        // remove from the URL the FQDN part to prevent the leak of the access token to a third party server:
                        // if the URL doesn't have the FQDN, the request will be sent to UCWA that hosts this xframe
                        if (!isTrusted(request.url))
                            request.url = (location.origin || location.protocol + '//' + location.hostname + (location.port ? ':' + location.port : '')) + extractUrlPath(request.url);

                        request.headers['Authorization'] = args.token_type + ' ' + args.access_token;
                    }

                    if (rargs[1] == 'beforeunload') {
                        addListener('beforeunload', function () {
                            sendRequest(request, sendResponse);
                        });
                    } else {
                        sendRequest(request, sendResponse);
                    }
                    return;
            }
        } catch (err) {
            sendResponse({
                status: 500,
                statusText: 'XFrame Error',
                responseText: err + ''
            });
        }
    });
})();