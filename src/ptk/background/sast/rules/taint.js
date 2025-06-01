// rules/taintFlowRule.js
import { ancestor, base } from '../acorn/walk.mjs';

//
// Helper: checks if a MemberExpression/Identifier chain matches a given path.
//   e.g. matchesPath(node, ["window","location","href"]) returns true for window.location.href, location.href, etc.
//
function matchesPath(node, segments) {
    let idx = segments.length - 1;
    let cur = node;
    while (idx >= 0 && cur) {
        if (cur.type === 'MemberExpression' && cur.property.name === segments[idx]) {
            cur = cur.object;
            idx--;
        } else if (cur.type === 'Identifier' && idx === 0 && cur.name === segments[0]) {
            return true;
        } else {
            return false;
        }
    }
    return idx < 0;
}

//
// Helper: search a subtree for any Identifier matching `name`.
// Returns true if found.
//
function hasIdentifier(node, name) {
    let found = false;
    ancestor(
        node,
        {
            Identifier(inner) {
                if (inner.name === name) found = true;
            }
        },
        base
    );
    return found;
}

//
// Helper: search a subtree for any CallExpression whose callee name is in wrapperSources.
// Returns true if found.
//
function containsWrapperSourceCall(node, wrapperSources) {
    if (!node) return false;
    let found = false;
    ancestor(
        node,
        {
            CallExpression(c) {
                if (c.callee.type === 'Identifier' && wrapperSources.has(c.callee.name)) {
                    found = true;
                }
            }
        },
        base
    );
    return found;
}

//
// Helper: search a subtree for any Identifier whose name is in taintedVars.
// Returns true if found.
//
function containsTainted(node, taintedVars) {
    if (!node) return false;
    let found = false;
    ancestor(
        node,
        {
            Identifier(inner) {
                if (taintedVars.has(inner.name)) found = true;
            }
        },
        base
    );
    return found;
}

//
// Helper: retrieve the stored { loc, file } for the first tainted identifier found in this subtree.
// Now we store the full node.loc (with start & end).
//
function getFirstTaintedInfo(node, taintedVars) {
    if (!node) return {};
    let found = {};
    ancestor(
        node,
        {
            Identifier(inner) {
                if (taintedVars.has(inner.name) && Object.keys(found).length === 0) {
                    found = taintedVars.get(inner.name);
                }
            }
        },
        base
    );
    return found;
}

//
// Helper: stringify a small AST node into a property chain or identifier.
//   Handles Identifier, MemberExpression, and CallExpression (by showing its callee).
//
function nodeToString(node) {
    if (!node) return '';
    if (node.type === 'Identifier') {
        return node.name;
    }
    if (node.type === 'MemberExpression') {
        const obj = nodeToString(node.object);
        const prop = node.property.name;
        return obj ? `${obj}.${prop}` : prop;
    }
    if (node.type === 'CallExpression') {
        // show callee name + "(…)"
        if (node.callee.type === 'Identifier') {
            return `${node.callee.name}(…)`;
        }
        if (node.callee.type === 'MemberExpression') {
            return `${nodeToString(node.callee)}(…)`;
        }
    }
    // fallback: just show type
    return node.type;
}

//
// List of every “location‐based” path we treat as a source _or_ sink.
// (We will use this both in isDirectSource(...) and in isLocationSink(...).)
//
const allLocPaths = [
    ['location'],
    ['location', 'href'],
    ['location', 'search'],
    ['location', 'hash'],
    ['location', 'host'],
    ['location', 'origin'],
    ['location', 'hostname'],
    ['location', 'pathname'],
    ['location', 'toString'],

    ['window', 'location'],
    ['window', 'location', 'href'],
    ['window', 'location', 'search'],
    ['window', 'location', 'hash'],
    ['window', 'location', 'host'],
    ['window', 'location', 'origin'],
    ['window', 'location', 'hostname'],
    ['window', 'location', 'pathname'],
    ['window', 'location', 'toString'],

    ['window', 'document', 'location'],
    ['window', 'document', 'location', 'href'],
    ['window', 'document', 'location', 'search'],
    ['window', 'document', 'location', 'hash'],
    ['window', 'document', 'location', 'host'],
    ['window', 'document', 'location', 'origin'],
    ['window', 'document', 'location', 'hostname'],
    ['window', 'document', 'location', 'pathname'],
    ['window', 'document', 'location', 'toString']
];

//
// Helper: returns true if `node` is any of the above “location” paths.
// We treat all of these as sinks if they appear on the LHS of an assignment.
//
function isLocationSink(node) {
    if (!node) return false;

    // 1) Plain `location = ...`
    if (node.type === 'Identifier' && node.name === 'location') {
        return true;
    }

    // 2) Any MemberExpression matching one of the `allLocPaths`
    if (node.type === 'MemberExpression') {
        for (const path of allLocPaths) {
            if (matchesPath(node, path)) {
                return true;
            }
        }
    }

    return false;
}

//
// Detect direct taint sources: various document.* props (including window.document.*),
// any element.value, any “location.*” (host, origin, hash, search, etc.), window.name.
//
function isDirectSource(node) {
    if (!node) return false;

    // 1) Document properties (cookie, URL, baseURI, documentURI, URLUnencoded, referrer)
    //    either as document.prop or window.document.prop
    const docProps = ['cookie', 'URL', 'baseURI', 'documentURI', 'URLUnencoded', 'referrer'];
    for (const prop of docProps) {
        if (
            matchesPath(node, ['document', prop]) ||
            matchesPath(node, ['window', 'document', prop])
        ) {
            return true;
        }
    }

    // 2) Any element.value (e.g. <input>.value, event.target.value, etc.)
    if (node.type === 'MemberExpression' && node.property.name === 'value') {
        return true;
    }

    // 3) Any “location.*” as listed in allLocPaths
    if (node.type === 'MemberExpression' || node.type === 'Identifier') {
        for (const path of allLocPaths) {
            if (matchesPath(node, path)) {
                return true;
            }
        }
    }

    // 4) window.name
    if (matchesPath(node, ['window', 'name'])) {
        return true;
    }

    return false;
}

//
// Detect URLSearchParams.get(...) sources: new URLSearchParams(window.location.search).get("foo")
//
function isURLParamSource(node) {
    if (!node || node.type !== 'CallExpression') return false;
    const callee = node.callee;
    if (callee.type === 'MemberExpression' && callee.property.name === 'get') {
        const obj = callee.object;
        if (obj.type === 'NewExpression' && obj.callee.name === 'URLSearchParams') {
            const arg = obj.arguments[0];
            if (isDirectSource(arg)) return true;
        }
    }
    return false;
}

//
// Detect certain call‐based sources (storage/history APIs):
//   - localStorage.getItem(...)
//   - sessionStorage.getItem(...)
//   - history.pushState(...)
//   - history.replaceState(...)
//
function isCallSource(node) {
    if (!node || node.type !== 'CallExpression') return false;
    const callee = node.callee;
    if (
        callee.type === 'MemberExpression' &&
        matchesPath(callee, ['localStorage', 'getItem'])
    ) return true;
    if (
        callee.type === 'MemberExpression' &&
        matchesPath(callee, ['sessionStorage', 'getItem'])
    ) return true;
    if (
        callee.type === 'MemberExpression' &&
        matchesPath(callee, ['history', 'pushState'])
    ) return true;
    if (
        callee.type === 'MemberExpression' &&
        matchesPath(callee, ['history', 'replaceState'])
    ) return true;
    return false;
}

//
// New helper: detect params.get(...) when params was previously tainted
//
function isParamGetSource(node, taintedVars) {
    if (!node || node.type !== 'CallExpression') return false;
    const callee = node.callee;
    if (callee.type === 'MemberExpression' && callee.property.name === 'get') {
        const obj = callee.object;
        if (obj.type === 'Identifier' && taintedVars.has(obj.name)) {
            return true;
        }
    }
    return false;
}

//
// New helper: detect decodeURIComponent(location.hash.slice(…)) or location.hash.slice(…)
//
function containsHashSource(node) {
    if (!node) return false;
    let found = false;
    ancestor(
        node,
        {
            MemberExpression(expr) {
                if (matchesPath(expr, ['location', 'hash'])) {
                    found = true;
                }
            }
        },
        base
    );
    return found;
}

const Taint = {
    id: 'taint-flow',
    description: 'Detect flow of untrusted input into dangerous sinks without sanitization.',
    severity: 'high',

    // 1) All recognized sinks:
    sinks: [
        // a) innerHTML / outerHTML assignment
        n =>
            n.type === 'AssignmentExpression' &&
            n.left.type === 'MemberExpression' &&
            ['innerHTML', 'outerHTML'].includes(n.left.property.name),

        // b) insertAdjacentHTML()
        n =>
            n.type === 'CallExpression' &&
            n.callee.type === 'MemberExpression' &&
            n.callee.property.name === 'insertAdjacentHTML',

        // c) document.write()
        n =>
            n.type === 'CallExpression' &&
            n.callee.type === 'MemberExpression' &&
            n.callee.object.name === 'document' &&
            n.callee.property.name === 'write',

        // d) eval()
        n =>
            n.type === 'CallExpression' &&
            n.callee.type === 'Identifier' &&
            n.callee.name === 'eval',

        // e) document.cookie = …
        n =>
            n.type === 'AssignmentExpression' &&
            n.left.type === 'MemberExpression' &&
            n.left.object.name === 'document' &&
            n.left.property.name === 'cookie',

        // f) window.name = …
        n =>
            n.type === 'AssignmentExpression' &&
            n.left.type === 'MemberExpression' &&
            n.left.object.name === 'window' &&
            n.left.property.name === 'name',

        // g) window.open(...)
        n =>
            n.type === 'CallExpression' &&
            n.callee.type === 'MemberExpression' &&
            matchesPath(n.callee, ['window', 'open']),

        // h) ANY assignment to “location” or its sub‐properties (search, hash, href, host, origin, etc.)
        n =>
            n.type === 'AssignmentExpression' &&
            (
                // left is an identifier `location`
                (n.left.type === 'Identifier' && n.left.name === 'location') ||
                // OR left is any MemberExpression matching our allLocPaths
                (n.left.type === 'MemberExpression' && allLocPaths.some(path => matchesPath(n.left, path)))
            )
    ],

    // 2) Sanitizers: functions known to “clean” HTML, e.g. DOMPurify.sanitize
    sanitizers: [
        n =>
            n.type === 'CallExpression' &&
            n.callee.type === 'MemberExpression' &&
            n.callee.property.name === 'sanitize'
    ],

    check(ast, meta) {
        const self = this;
        // Map<variableName, { loc: SourceLocation, file: string }>
        const taintedVars = new Map();

        // Map<functionName, { loc: SourceLocation, file: string }>
        const wrapperSources = new Map();

        // Map<functionName, { loc: SourceLocation, file: string }>
        const wrapperSinks = new Map();

        // Final list of issues to return
        const issues = [];

        //
        // 1) Identify “wrapper‐source” functions:
        ancestor(
            ast,
            {
                FunctionDeclaration(fn) {
                    const name = fn.id?.name;
                    if (!name) return;
                    let wraps = false;

                    ancestor(
                        fn.body,
                        {
                            MemberExpression(expr) {
                                if (isDirectSource(expr)) wraps = true;
                            },
                            CallExpression(call) {
                                if (isCallSource(call)) wraps = true;
                            }
                        },
                        base
                    );

                    if (wraps) {
                        // Store full fn.loc, not just fn.loc.start
                        wrapperSources.set(name, {
                            loc: fn.loc,
                            file: fn.sourceFile
                        });
                    }
                }
            },
            base
        );

        //
        // 2) Identify “wrapper‐sink” functions:
        ancestor(
            ast,
            {
                FunctionDeclaration(fn) {
                    const name = fn.id?.name;
                    const param = fn.params[0];
                    if (!name || !param || param.type !== 'Identifier') return;
                    let wraps = false;

                    ancestor(
                        fn.body,
                        {
                            CallExpression(call) {
                                if (
                                    self.sinks.some(test => test(call)) &&
                                    hasIdentifier(call.arguments[0] || call, param.name)
                                ) wraps = true;
                            },
                            AssignmentExpression(a) {
                                if (
                                    self.sinks.some(test => test(a)) &&
                                    hasIdentifier(a.right, param.name)
                                ) wraps = true;
                            }
                        },
                        base
                    );

                    if (wraps) {
                        wrapperSinks.set(name, {
                            loc: fn.loc,
                            file: fn.sourceFile
                        });
                    }
                }
            },
            base
        );

        //
        // 3) Propagate taint:
        ancestor(
            ast,
            {
                VariableDeclarator(decl) {
                    const init = decl.init;
                    let foundWrapper = false;

                    // A) If initializer contains a wrapper‐source call, mark var tainted
                    if (init) {
                        ancestor(
                            init,
                            {
                                CallExpression(c) {
                                    if (
                                        c.callee.type === 'Identifier' &&
                                        wrapperSources.has(c.callee.name)
                                    ) {
                                        foundWrapper = true;
                                    }
                                }
                            },
                            base
                        );
                    }

                    // B) If initializer is new URLSearchParams(location.search), mark var tainted
                    const isNewUrlSearchParams =
                        init &&
                        init.type === 'NewExpression' &&
                        init.callee.name === 'URLSearchParams' &&
                        init.arguments.length > 0 &&
                        isDirectSource(init.arguments[0]);

                    if (
                        isDirectSource(init) ||
                        isURLParamSource(init) ||
                        isCallSource(init) ||
                        foundWrapper ||
                        isNewUrlSearchParams
                    ) {
                        // Store full decl.loc
                        taintedVars.set(decl.id.name, {
                            loc: decl.loc,
                            file: decl.id.sourceFile
                        });
                    }
                },

                AssignmentExpression(a) {
                    const { left, right } = a;
                    const rightHasWrapper = containsWrapperSourceCall(right, wrapperSources);
                    const rightHasTainted = right.type === 'Identifier' && taintedVars.has(right.name);
                    const isNewUrlSearchParams =
                        right &&
                        right.type === 'NewExpression' &&
                        right.callee.name === 'URLSearchParams' &&
                        right.arguments.length > 0 &&
                        isDirectSource(right.arguments[0]);

                    if (
                        left.type === 'Identifier' &&
                        (
                            isDirectSource(right) ||
                            isURLParamSource(right) ||
                            isCallSource(right) ||
                            rightHasTainted ||
                            rightHasWrapper ||
                            isNewUrlSearchParams
                        )
                    ) {
                        // Store full left.loc
                        taintedVars.set(left.name, {
                            loc: left.loc,
                            file: left.sourceFile
                        });
                    }
                },

                CallExpression(c, ancestors) {
                    // If this call is a wrapper‐source, taint its container variable
                    if (
                        c.callee.type === 'Identifier' &&
                        wrapperSources.has(c.callee.name)
                    ) {
                        for (let i = ancestors.length - 2; i >= 0; i--) {
                            const parent = ancestors[i];
                            if (parent.type === 'VariableDeclarator') {
                                // full parent.loc
                                taintedVars.set(parent.id.name, {
                                    loc: parent.loc,
                                    file: parent.id.sourceFile
                                });
                                break;
                            }
                            if (
                                parent.type === 'AssignmentExpression' &&
                                parent.left.type === 'Identifier'
                            ) {
                                taintedVars.set(parent.left.name, {
                                    loc: parent.left.loc,
                                    file: parent.left.sourceFile
                                });
                                break;
                            }
                        }
                    }

                    // Propagate taint through nested calls:
                    c.arguments.forEach(arg => {
                        if (arg.type === 'Identifier' && taintedVars.has(arg.name)) {
                            for (let i = ancestors.length - 2; i >= 0; i--) {
                                const parent = ancestors[i];
                                if (parent.type === 'VariableDeclarator') {
                                    taintedVars.set(parent.id.name, {
                                        loc: parent.loc,
                                        file: parent.id.sourceFile
                                    });
                                    break;
                                }
                                if (
                                    parent.type === 'AssignmentExpression' &&
                                    parent.left.type === 'Identifier' &&
                                    !self.sanitizers.some(test => test(c))
                                ) {
                                    taintedVars.set(parent.left.name, {
                                        loc: parent.left.loc,
                                        file: parent.left.sourceFile
                                    });
                                    break;
                                }
                            }
                        }
                    });
                }
            },
            base
        );

        //
        // 4a) Detect “direct” sinks (AssignmentExpression → sink) and “cookie/name” sinks
        ancestor(
            ast,
            {
                AssignmentExpression(a) {
                    const isHtmlSink =
                        a.left.type === 'MemberExpression' &&
                        ['innerHTML', 'outerHTML'].includes(a.left.property.name);

                    const isCookieSink =
                        a.left.type === 'MemberExpression' &&
                        a.left.object.name === 'document' &&
                        a.left.property.name === 'cookie';
                    const isNameSink =
                        a.left.type === 'MemberExpression' &&
                        a.left.object.name === 'window' &&
                        a.left.property.name === 'name';

                    // Now “location.*” assignments also count as sinks:
                    const isLocationSearchSink = isLocationSink(a.left);

                    if (isHtmlSink || isCookieSink || isNameSink || isLocationSearchSink) {
                        const rhs = a.right;
                        const rhsHasTaintedVar    = containsTainted(rhs, taintedVars);
                        const rhsHasDirectSource  = isDirectSource(rhs);
                        const rhsHasURLParam      = isURLParamSource(rhs);
                        const rhsHasCallSource    = isCallSource(rhs);
                        const rhsHasWrapperSource = containsWrapperSourceCall(rhs, wrapperSources);
                        const rhsHasParamGetSource = isParamGetSource(rhs, taintedVars);
                        const rhsHasHashSource    = containsHashSource(rhs);

                        // Always compute sourceName from rhs
                        const sourceName = nodeToString(rhs);

                        // Compute sinkName from left side
                        let sinkName = '';
                        if (isHtmlSink) {
                            sinkName = a.left.property.name; // "innerHTML" or "outerHTML"
                        } else if (isCookieSink) {
                            sinkName = 'document.cookie';
                        } else if (isNameSink) {
                            sinkName = 'window.name';
                        } else if (isLocationSearchSink) {
                            // If left is plain `location`:
                            if (a.left.type === 'Identifier' && a.left.name === 'location') {
                                sinkName = 'location';
                            } else {
                                sinkName = nodeToString(a.left);
                            }
                        } else {
                            sinkName = nodeToString(a.left);
                        }

                        if (
                            rhsHasTaintedVar    ||
                            rhsHasDirectSource  ||
                            rhsHasURLParam      ||
                            rhsHasCallSource    ||
                            rhsHasWrapperSource ||
                            rhsHasParamGetSource ||
                            rhsHasHashSource
                        ) {
                            // Determine sourceFile/sourceLoc
                            let srcInfo = {};
                            if (rhsHasTaintedVar) {
                                srcInfo = getFirstTaintedInfo(rhs, taintedVars);
                            } else if (rhsHasWrapperSource) {
                                // Find the wrapper‐source function’s info
                                let info = {};
                                ancestor(
                                    rhs,
                                    {
                                        CallExpression(c) {
                                            if (
                                                c.callee.type === 'Identifier' &&
                                                wrapperSources.has(c.callee.name) &&
                                                Object.keys(info).length === 0
                                            ) {
                                                info = wrapperSources.get(c.callee.name);
                                            }
                                        }
                                    },
                                    base
                                );
                                srcInfo = info;
                            } else {
                                // Direct‐source or URLParam or callSource or hash
                                srcInfo = {
                                    loc: rhs.loc,
                                    file: rhs.sourceFile
                                };
                            }

                            const sinkInfo = {
                                loc: a.loc,
                                file: a.left.sourceFile
                            };

                            issues.push({
                                ruleId:      self.id,
                                description: self.description,
                                severity:    self.severity,
                                type:        'AssignmentExpression',
                                sourceName,
                                sinkName,
                                sourceFile:  srcInfo.file,
                                sourceLoc:   srcInfo.loc,
                                sinkFile:    sinkInfo.file,
                                sinkLoc:     sinkInfo.loc
                            });
                        }
                    }
                }
            },
            base
        );

        //
        // 4b) Detect “call” sinks (eval, insertAdjacentHTML, window.open) AND “wrapper‐sink” calls
        ancestor(
            ast,
            {
                CallExpression(c) {
                    // 4b-1) direct call-sink: eval(x), node.insertAdjacentHTML(x), window.open(x)
                    if (self.sinks.some(test => test(c))) {
                        const arg = c.arguments[0];
                        const argHasTaintedVar = containsTainted(arg, taintedVars);
                        const argHasDirectSource = isDirectSource(arg);
                        const argHasURLParam = isURLParamSource(arg);
                        const argHasCallSource = isCallSource(arg);
                        const argHasWrapperSource = containsWrapperSourceCall(arg, wrapperSources);
                        const argHasParamGetSource = isParamGetSource(arg, taintedVars);
                        const argHasHashSource = containsHashSource(arg);

                        // Always compute sourceName from arg
                        const sourceName = nodeToString(arg);

                        // Compute sinkName from c.callee
                        let sinkName = '';
                        if (c.callee.type === 'MemberExpression') {
                            sinkName = c.callee.property.name; // e.g. "insertAdjacentHTML" or "open"
                        } else if (c.callee.type === 'Identifier') {
                            sinkName = c.callee.name; // e.g. "eval"
                        } else {
                            sinkName = nodeToString(c.callee);
                        }

                        if (
                            argHasTaintedVar    ||
                            argHasDirectSource  ||
                            argHasURLParam      ||
                            argHasCallSource    ||
                            argHasWrapperSource ||
                            argHasParamGetSource ||
                            argHasHashSource
                        ) {
                            // Determine sourceFile/sourceLoc
                            let srcInfo = {};
                            if (argHasTaintedVar) {
                                srcInfo = getFirstTaintedInfo(arg, taintedVars);
                            } else if (argHasWrapperSource) {
                                let info = {};
                                ancestor(
                                    arg,
                                    {
                                        CallExpression(inner) {
                                            if (
                                                inner.callee.type === 'Identifier' &&
                                                wrapperSources.has(inner.callee.name) &&
                                                Object.keys(info).length === 0
                                            ) {
                                                info = wrapperSources.get(inner.callee.name);
                                            }
                                        }
                                    },
                                    base
                                );
                                srcInfo = info;
                            } else {
                                srcInfo = {
                                    loc: arg ? arg.loc : {},
                                    file: arg ? arg.sourceFile : undefined
                                };
                            }

                            const sinkInfo = {
                                loc: c.loc,
                                file: c.callee.sourceFile
                            };

                            issues.push({
                                ruleId:      self.id,
                                description: self.description,
                                severity:    self.severity,
                                type:        'CallExpression',
                                sourceName,
                                sinkName,
                                sourceFile:  srcInfo.file,
                                sourceLoc:   srcInfo.loc,
                                sinkFile:    sinkInfo.file,
                                sinkLoc:     sinkInfo.loc
                            });
                        }
                    }

                    // 4b-2) wrapper-sink call: e.g. runSink(x)
                    if (c.callee.type === 'Identifier' && wrapperSinks.has(c.callee.name)) {
                        const arg = c.arguments[0];
                        const argHasTaintedVar = containsTainted(arg, taintedVars);
                        const argHasDirectSource = isDirectSource(arg);
                        const argHasURLParam = isURLParamSource(arg);
                        const argHasCallSource = isCallSource(arg);
                        const argHasWrapperSource = containsWrapperSourceCall(arg, wrapperSources);
                        const argHasParamGetSource = isParamGetSource(arg, taintedVars);
                        const argHasHashSource = containsHashSource(arg);

                        // Always compute sourceName from arg
                        const sourceName = nodeToString(arg);

                        const sinkName = c.callee.name; // wrapper function name, e.g. "runSink"

                        if (
                            argHasTaintedVar    ||
                            argHasDirectSource  ||
                            argHasURLParam      ||
                            argHasCallSource    ||
                            argHasWrapperSource ||
                            argHasParamGetSource ||
                            argHasHashSource
                        ) {
                            let srcInfo = {};
                            if (argHasTaintedVar) {
                                srcInfo = getFirstTaintedInfo(arg, taintedVars);
                            } else if (argHasWrapperSource) {
                                let info = {};
                                ancestor(
                                    arg,
                                    {
                                        CallExpression(inner) {
                                            if (
                                                inner.callee.type === 'Identifier' &&
                                                wrapperSources.has(inner.callee.name) &&
                                                Object.keys(info).length === 0
                                            ) {
                                                info = wrapperSources.get(inner.callee.name);
                                            }
                                        }
                                    },
                                    base
                                );
                                srcInfo = info;
                            } else {
                                srcInfo = {
                                    loc: arg ? arg.loc : {},
                                    file: arg ? arg.sourceFile : undefined
                                };
                            }

                            const sinkLocObj = wrapperSinks.get(c.callee.name);

                            issues.push({
                                ruleId:      self.id,
                                description: self.description,
                                severity:    self.severity,
                                type:        'CallExpression',
                                sourceName,
                                sinkName,
                                sourceFile:  srcInfo.file,
                                sourceLoc:   srcInfo.loc,
                                sinkFile:    sinkLocObj.file,
                                sinkLoc:     sinkLocObj.loc
                            });
                        }
                    }
                }
            },
            base
        );

        return issues;
    }
};

export default [Taint];
