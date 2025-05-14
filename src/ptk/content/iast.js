/* Author: Denis Podgurskii */

console.info('IAST agent loaded');
let __IAST_DISABLE_HOOKS__ = false;

// Deduplication set for mutation hooks
const __IAST_REPORTED_NODES__ = new Set();

// Encoding helpers
function withoutHooks(fn) {
    const prev = __IAST_DISABLE_HOOKS__;
    __IAST_DISABLE_HOOKS__ = true;
    try {
        return fn();
    } finally {
        __IAST_DISABLE_HOOKS__ = prev;
    }
}

// Re-write htmlDecode & htmlEncode

function htmlDecode(input) {
    return withoutHooks(() => {
        const ta = document.createElement('textarea');
        ta.innerHTML = input;
        return ta.value;
    });
}

function htmlEncode(input) {
    return withoutHooks(() => {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    });
}

// Taint collection
function collectTaintedSources() {
    const raw = {};
    const add = (key, valRaw) => {
        if (!valRaw) return;
        let val = String(valRaw).trim().replace(/^#/, '');
        const hasAlnum = /[A-Za-z0-9]/.test(val);
        if (!hasAlnum && val !== '/') return;
        raw[key] = val;
    };
    for (const [k, v] of new URLSearchParams(location.search)) add(`query:${k}`, v);
    if (location.hash) add('hash', decodeURIComponent(location.hash.slice(1)));
    if (document.referrer) add('referrer', document.referrer);
    document.cookie.split(';').forEach(c => {
        const [k, v] = c.split('=').map(s => s.trim());
        add(`cookie:${k}`, decodeURIComponent(v || ''));
    });
    ['localStorage', 'sessionStorage'].forEach(store => {
        try {
            for (let i = 0; i < window[store].length; i++) {
                const key = window[store].key(i), val = window[store].getItem(key);
                add(`${store}:${key}`, val);
            }
        } catch { };
    });
    if (window.name) add('window.name', window.name);
    console.info('[IAST] Collected taints', raw);
    return raw;
}
window.__IAST_TAINTED__ = collectTaintedSources();

// Dynamic monitoring (storage, cookie, window.name, hash)
(function () {
    const taints = window.__IAST_TAINTED__;
    const record = (key, val) => {
        if (!val) return;
        const s = String(val);
        const hasAlnum = /[A-Za-z0-9]/.test(s);
        if (!hasAlnum && s !== '/') return;
        taints[key] = s;
        console.info('[IAST] Updated source', key, s);
    };
    // Storage wrappers
    const proto = Storage.prototype;
    ['setItem', 'removeItem', 'clear'].forEach(fn => {
        const orig = proto[fn];
        proto[fn] = function (k, v) {
            if (fn === 'setItem') record(`${this === localStorage ? 'localStorage' : 'sessionStorage'}:${k}`, v);
            if (fn === 'removeItem') delete taints[`${this === localStorage ? 'localStorage' : 'sessionStorage'}:${k}`];
            if (fn === 'clear') Object.keys(taints)
                .filter(x => x.startsWith(this === localStorage ? 'localStorage:' : 'sessionStorage:'))
                .forEach(x => delete taints[x]);
            return orig.apply(this, arguments);
        };
    });
    // window.name
    if (typeof window.__defineSetter__ === 'function') {
        let cur = window.name;
        window.__defineSetter__('name', v => { cur = v; record('window.name', v); });
        window.__defineGetter__('name', () => cur);
    }
    // cookie
    const desc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
    if (desc && desc.configurable) {
        Object.defineProperty(Document.prototype, 'cookie', {
            get() { return desc.get.call(document); },
            set(v) {
                const res = desc.set.call(document, v);
                const [p] = v.split(';'); const [k, val] = p.split('=');
                record(`cookie:${k}`, decodeURIComponent(val)); return res;
            },
            configurable: true
        });
    }
    // hashchange
    window.addEventListener('hashchange', () => {
        const h = decodeURIComponent(location.hash.slice(1)); record('hash', h);
    });
})();

// Inline source capture: trap input.value reads
(function () {
    const desc = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
    if (desc && desc.get && desc.set) {
        Object.defineProperty(HTMLInputElement.prototype, 'value', {
            get: function () {
                const val = desc.get.call(this);
                if (val) {
                    window.__IAST_TAINTED__[`inline:${this.id || this.name || 'input'}`] = String(val);
                    console.info('[IAST] Captured inline taint from', this.id || this.name || 'input', val);
                }
                return val;
            },
            set: function (v) { return desc.set.call(this, v); },
            configurable: true
        });
    }
})();


function matchesTaint(input) {
    if (__IAST_DISABLE_HOOKS__) return null;
    // 1) Normalize / decode the raw input
    let rawStr = String(input || '');
    try {
        rawStr = htmlDecode(rawStr);
    } catch { }
    rawStr = rawStr.toLowerCase();

    if (!/[a-z0-9\/]/i.test(rawStr)) return null;

    // 2) Collect taints
    const taints = Object.entries(window.__IAST_TAINTED__ || {})
        .filter(([, v]) => v)
        .map(([k, v]) => [k, String(v).trim().toLowerCase().replace(/^#/, '').replace(/;$/, '')]);

    for (const [source, tv] of taints) {
        if (!tv) continue;

        // If this taint looks like a URL, canonicalize both sides
        let rawToMatch = rawStr;
        let tvToMatch = tv;
        if (/^[a-z][\w+.-]+:\/\//i.test(tv) && /^[a-z][\w+.-]+:\/\//i.test(rawStr)) {
            try {
                rawToMatch = new URL(rawStr, location.href).href.toLowerCase();
                tvToMatch = new URL(tv, location.href).href.toLowerCase();
            } catch (e) {
                // fall back if URL parsing fails
                rawToMatch = rawStr;
                tvToMatch = tv;
            }
        }

        // 3) Matching
        if (/^[a-z0-9]+$/i.test(tv)) {
            // pure word token
            const esc = tv.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
            const re = new RegExp(`\\b${esc}\\b`, 'i');
            if (re.test(rawToMatch)) {
                return { source, raw: window.__IAST_TAINTED__[source] };
            }
        } else {
            // anything else: substring
            if (rawToMatch.includes(tvToMatch)) {
                return { source, raw: window.__IAST_TAINTED__[source] };
            }
        }
    }

    return null;
}

(function flushBufferedFindings() {
    const key = 'ptk_iast_buffer';
    const data = localStorage.getItem(key);
    if (!data) return;
    let arr;
    try { arr = JSON.parse(data); } catch { arr = null; }
    if (Array.isArray(arr)) {
        arr.forEach(msg => {
            try { window.postMessage(msg, '*'); }
            catch (e) {/*ignore*/ }
        });
    }
    localStorage.removeItem(key);
})();


function reportFinding({ type, sink, matched, source, context = {} }) {
    const loc = window.location.href;
    let trace = '';
    try {
        trace = (new Error(`Sink: ${type}`)).stack;
        //console.log(trace)
    } catch (e) { }
    const details = {
        type: type,
        sink,
        matched,
        source,
        context,
        location: loc,
        trace: trace,
        timestamp: Date.now()
    };

    // 1) Console output
    console.groupCollapsed(`%cIAST%c ${type}`,
        'color:#d9534f;font-weight:bold', '');
    console.log('• location:', loc);
    console.log('• sink:    ', sink);
    console.log('• source:  ', source);
    console.log('• matched: ', matched);
    // log any extra context fields
    Object.entries(context).forEach(([k, v]) =>
        console.log(`• ${k}:       `, v)
    );
    console.groupEnd();


    // 2) PostMessage to background (sanitized)
    const sanitized = {};
    Object.entries(details).forEach(([k, v]) => {
        sanitized[k] = (typeof v === 'object') ? String(v) : v;
    });
    try {
        const msg = {
            ptk_iast: 'finding_report',
            channel: 'ptk_content_iast2background_iast',
            finding: details
        }
        const key = 'ptk_iast_buffer';
        const buf = JSON.parse(localStorage.getItem(key) || '[]');
        buf.push(msg);
        localStorage.setItem(key, JSON.stringify(buf));

        window.postMessage(msg, '*');
    } catch (e) {
        console.error('IAST reportFinding.postMessage failed:', e);
    }
}


// Inline-event scanner helper
function scanInlineEvents(htmlFragment) {
    let m;
    try {
        const doc = new DOMParser().parseFromString(htmlFragment, 'text/html');
        doc.querySelectorAll('*').forEach(el => {
            Array.from(el.attributes).forEach(attr => {
                const name = attr.name.toLowerCase();
                if (!name.startsWith('on')) return;
                const val = attr.value;
                m = matchesTaint(val);
                if (!m) return;

                // unified reporting
                reportFinding({
                    type: 'dom-inline-event-handler',
                    sink: name,        // e.g. "onclick" or "onerror"
                    matched: m.raw,
                    source: m.source,
                    severity: 'high',
                    context: {
                        element: el.outerHTML,
                        tag: el.tagName,
                        attribute: name,
                        value: val
                    }
                });
            });
        });
    } catch (e) {
        console.warn('[IAST] inline-event scan error', e);
    }
}


// Eval & Function hooks
; (function () {
    const originalEval = window.eval;
    window.eval = function (code) {
        const m = matchesTaint(code);
        if (m) {
            let el = document?.activeElement ? document.activeElement.outerHTML : ''
            reportFinding({
                type: 'xss-via-eval',
                sink: 'eval',
                matched: m.raw,
                source: m.source,
                severity: 'high',
                context: {
                    element: el,
                    value: code
                }
            });
        }
        return originalEval.call(this, code);
    };
})();

; (function () {
    const OriginalFunction = window.Function;
    window.Function = new Proxy(OriginalFunction, {
        construct(target, args, newTarget) {
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                let el = document?.activeElement ? document?.activeElement.outerHTML : ''
                reportFinding({
                    type: 'xss-via-Function',
                    sink: 'Function.constructor',
                    matched: m.raw,
                    source: m.source,
                    severity: 'high',
                    context: {
                        element: el,
                        value: args
                    }
                });
            }
            return Reflect.construct(target, args, newTarget);
        },
        apply(target, thisArg, args) {
            const body = args.slice(-1)[0] + '';
            const m = matchesTaint(body);
            if (m) {
                reportFinding({
                    type: 'xss-via-Function',
                    sink: 'Function.apply',
                    matched: m.raw,
                    source: m.source,
                    context: { args }
                });
            }
            return Reflect.apply(target, thisArg, args);
        }
    });
})();


// document.write
; (function () {
    const origWrite = document.write;

    document.write = function (...args) {
        const html = args.join('');
        let fragment;
        try {
            // Parse the HTML into a DocumentFragment
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            fragment = doc.body;
            // Traverse and report any taint in attributes or text nodes
            traverseAndReport(fragment, 'document.write');
        } catch (e) {
            // Fallback to the old behavior if parsing fails
            const m = matchesTaint(html);
            if (m) {
                let el = document?.activeElement ? document?.activeElement.outerHTML : ''
                reportFinding({
                    type: 'xss-via-document.write',
                    sink: 'document.write',
                    matched: m.raw,
                    source: m.source,
                    severity: 'high',
                    context: { value: html, element: el }
                });
                scanInlineEvents(html, m);
            }
        }
        return origWrite.apply(document, args);
    };

    // Helper: walk a DOM subtree and report the first taint per node
    function traverseAndReport(root, sink) {
        const seen = new Set();  // avoid duplicates
        postOrderTraverse(root, node => {
            if (node.nodeType === Node.TEXT_NODE) {
                const txt = node.textContent;
                const m = matchesTaint(txt);
                if (m && !seen.has(node)) {
                    let el = document?.activeElement ? document?.activeElement.outerHTML : ''
                    reportFinding({
                        type: 'xss-via-document.write',
                        sink: 'document.write',
                        matched: m.raw,
                        source: m.source,
                        severity: 'high',
                        context: { value: html, element: el }
                    });
                    seen.add(node);
                }
            } else if (node.nodeType === Node.ELEMENT_NODE) {
                // check each attribute
                for (const { name, value } of Array.from(node.attributes)) {
                    const m = matchesTaint(value);
                    if (m && !seen.has(node)) {
                        let el = document?.activeElement ? document?.activeElement.outerHTML : ''
                        reportFinding({
                            type: 'xss-via-document.write',
                            sink: 'document.write',
                            matched: m.raw,
                            source: m.source,
                            severity: 'high',
                            context: { value: html, element: el }
                        });
                        seen.add(node);
                        break;
                    }
                }
                // inline‐event handlers
                scanInlineEvents(node.outerHTML, m);
            }
        });
    }

    // reuse your existing postOrderTraverse
    function postOrderTraverse(node, fn) {
        node.childNodes.forEach(c => postOrderTraverse(c, fn));
        fn(node);
    }
})();

// innerHTML/outerHTML
['innerHTML', 'outerHTML'].forEach(prop => {
    const desc = Object.getOwnPropertyDescriptor(Element.prototype, prop);
    Object.defineProperty(Element.prototype, prop, {
        get: desc.get,
        set(htmlString) {
            try {
                const frag = document.createRange().createContextualFragment(htmlString);
                traverseAndReport(frag, `xss-via-${prop}`);
            } catch {
                const m = matchesTaint(htmlString);
                if (m) {
                    let el = document?.activeElement ? document?.activeElement.outerHTML : ''
                    reportFinding({
                        type: `xss-via-${prop}`,
                        sink: prop,
                        matched: m.raw,
                        source: m.source,
                        severity: 'high',
                        context: { value: htmlString, element: el }
                    });
                    scanInlineEvents(htmlString, m);
                }
            }
            return desc.set.call(this, htmlString);
        },
        configurable: true,
        enumerable: desc.enumerable
    });
});


// insertAdjacentHTML
; (function () {
    const origInsert = Element.prototype.insertAdjacentHTML;
    Element.prototype.insertAdjacentHTML = function (pos, htmlString) {
        try {
            // parse HTML to a fragment for precise matching
            const frag = document.createRange().createContextualFragment(htmlString);
            traverseAndReport(frag, `insertAdjacentHTML(${pos})`);
        } catch {
            // fallback to simple match
            const m = matchesTaint(htmlString);
            if (m) {
                let el = document?.activeElement ? document?.activeElement.outerHTML : ''
                reportFinding({
                    type: 'xss-via-insertAdjacentHTML',
                    sink: 'insertAdjacentHTML',
                    matched: m.raw,
                    source: m.source,
                    severity: 'high',
                    context: { value: htmlString, element: el, position: pos }
                });
                scanInlineEvents(htmlString, m);
            }
        }
        return origInsert.call(this, pos, htmlString);
    };
})();

// createContextualFragment & appendChild/insertBefore
; (function () {
    // 1) Walk a subtree in post-order, checking text nodes and element attributes
    function traverseAndReport(root, trigger) {
        const seen = new Set();
        function scanNode(n) {
            if (seen.has(n)) return;

            // TEXT NODE: look for taint in its textContent
            if (n.nodeType === Node.TEXT_NODE) {
                const txt = n.textContent || '';
                const m = matchesTaint(txt);
                if (m) {
                    seen.add(n);
                    let el = document?.activeElement ? document?.activeElement.outerHTML : ''
                    reportFinding({
                        type: 'xss-via-mutation',
                        sink: trigger,
                        matched: m.raw,
                        source: m.source,
                        severity: 'high',
                        context: {
                            element: el,
                            value: txt,
                            nodeType: 'TEXT_NODE',
                            snippet: txt.trim().slice(0, 200)
                        }
                    });
                }
                return;
            }

            // ELEMENT NODE: check each attribute for taint
            if (n.nodeType === Node.ELEMENT_NODE) {
                for (const attr of n.attributes) {
                    const m = matchesTaint(attr.value);
                    if (m) {
                        seen.add(n);

                        reportFinding({
                            type: 'xss-via-mutation',
                            sink: trigger,
                            matched: m.raw,
                            source: m.source,
                            context: {
                                element: n.outerHTML,
                                nodeType: 'ELEMENT_NODE',
                                tag: n.tagName,
                                attribute: attr.name,
                                value: attr.value
                            }
                        });
                        return;  // one finding per element
                    }
                }
            }
        }

        // post-order traverse everything under root (including root itself if text or element)
        (function walk(n) {
            n.childNodes.forEach(walk);
            scanNode(n);
        })(root);
    }

    // 2) List of prototypes & methods to hook
    const hooks = [
        [Node.prototype, ['appendChild', 'insertBefore', 'replaceChild']],
        [Element.prototype, ['append', 'prepend', 'before', 'after', 'replaceWith']],
        [Document.prototype, ['adoptNode']]
    ];

    for (const [proto, methods] of hooks) {
        for (const name of methods) {
            const orig = proto[name];
            if (typeof orig !== 'function') continue;

            Object.defineProperty(proto, name, {
                configurable: true,
                writable: true,
                value: function (...args) {
                    //console.debug(`[IAST] mutation hook: ${name}`, this, args);

                    // figure out which Nodes are being inserted/adopted
                    const nodes = [];
                    switch (name) {
                        case 'insertBefore':
                        case 'replaceChild':
                            nodes.push(args[0]);
                            break;
                        case 'appendChild':
                        case 'adoptNode':
                            nodes.push(args[0]);
                            break;
                        default:
                            // append/prepend/before/after/replaceWith take Node or strings
                            args.forEach(a => {
                                if (typeof a === 'string') {
                                    // strings become TextNodes at runtime; scan them too
                                    const txtNode = document.createTextNode(a);
                                    nodes.push(txtNode);
                                } else if (a instanceof Node) {
                                    nodes.push(a);
                                }
                            });
                    }

                    // run our taint scan on each
                    for (const n of nodes) {
                        traverseAndReport(n, name);
                    }

                    // and finally perform the real mutation
                    return orig.apply(this, args);
                }
            });
        }
    }
})();


// Open-Redirect Detection

; (function () {
    function isExternalRedirect(url) {
        try {
            // resolve relative URLs against current location
            const resolved = new URL(url, window.location.href);
            // only consider http(s) URLs…
            if (!/^https?:$/i.test(resolved.protocol)) return false;
            // …and only if the origin really differs
            return resolved.origin !== window.location.origin;
        } catch (e) {
            // not a valid URL at all
            return false;
        }
    }

    function recordRedirect(url, method) {
        // 1) skip anything that isn’t an external http(s) redirect
        if (!isExternalRedirect(url)) return;

        // 2) now check for taint
        const m = matchesTaint(url);
        if (m) {
            let el = document?.activeElement ? document?.activeElement.outerHTML : ''
            reportFinding({
                type: 'open-redirect',
                sink: method,          // e.g. "window.open" or "navigation.navigate"
                matched: m.raw,
                source: m.source,
                severity: 'medium',
                context: {
                    elsement: el,
                    value: url
                }
            });
        }
    }

    //Wrap window.open()
    const origOpen = window.open;
    window.open = function (url, ...rest) {
        if (typeof url === 'string') {
            recordRedirect(url, 'window.open');
        }
        return origOpen.call(this, url, ...rest);
    };

    if ('navigation' in window && typeof navigation.addEventListener === 'function') {
        navigation.addEventListener('navigate', event => {
            // event.destination.url is the URL we’re about to go to
            const url = event.destination.url;
            // reuse your open-redirect checker
            recordRedirect(url, 'navigation.navigate');
        });
    }

})();


