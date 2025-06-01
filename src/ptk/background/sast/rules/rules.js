const xssRule = {
    id: 'no-innerhtml',
    description: 'Disallow innerHTML assignments to prevent XSS.',
    severity: 'low',
    check(ast, meta, walk) {
        const self = this
        const issues = [];
        walk(ast, {
            AssignmentExpression(node) {
                if (node.left.type === 'MemberExpression' && node.left.property.name === 'innerHTML') {
                    issues.push({
                        ruleId: self.id,
                        description: self.description,
                        severity: self.severity,
                        file: node.sourceFile || meta.fileId,
                        type: node.type,
                        start: node.loc.start,
                        end: node.loc.end,
                        location: node.loc
                    });
                }
            }
        });
        return issues;
    }
};

// rules/noEvalRule.js
const noEvalRule = {
    id: 'no-eval',
    description: 'Disallow use of eval() to prevent remote code execution.',
    severity: 'low',
    check(ast, meta, walk) {
        const self = this
        const issues = [];
        walk(ast, {
            CallExpression(node) {
                if (node.callee.type === 'Identifier' && node.callee.name === 'eval') {
                    issues.push({
                        ruleId: self.id,
                        description: self.description,
                        severity: self.severity,
                        file: node.sourceFile || meta.fileId,
                        type: node.type,
                        start: node.loc.start,
                        end: node.loc.end,
                        location: node.loc
                    });
                }
            }
        });
        return issues;
    }
};

// rules/documentWriteRule.js
const documentWriteRule = {
    id: 'no-document-write',
    description: 'Disallow use of document.write() to prevent XSS.',
    severity: 'low',
    check(ast, meta, walk) {
        const self = this
        const issues = [];
        walk(ast, {
            CallExpression(node) {
                if (
                    node.callee.type === 'MemberExpression' &&
                    node.callee.object.name === 'document' &&
                    node.callee.property.name === 'write'
                ) {
                    issues.push({
                        ruleId: self.id,
                        description: self.description,
                        severity: self.severity,
                        file: node.sourceFile || meta.fileId,
                        type: node.type,
                        start: node.loc.start,
                        end: node.loc.end,
                        location: node.loc
                    });
                }
            }
        });
        return issues;
    }
};

// rules/insertAdjacentHTMLRule.js
const insertAdjacentHTMLRule = {
    id: 'no-insertadjacenthtml',
    description: 'Disallow use of insertAdjacentHTML() to prevent XSS.',
    severity: 'low',
    check(ast, meta, walk) {
        const self = this
        const issues = [];
        walk(ast, {
            CallExpression(node) {
                if (
                    node.callee.type === 'MemberExpression' &&
                    node.callee.property.name &&
                    node.callee.property.name.toLowerCase() === 'insertadjacenthtml'
                ) {
                    issues.push({
                        ruleId: self.id,
                        description: self.description,
                        severity: self.severity,
                        file: node.sourceFile || meta.fileId,
                        type: node.type,
                        start: node.loc.start,
                        end: node.loc.end,
                        location: node.loc
                    });
                }
            }
        });
        return issues;
    }
};

// rules/appendChildRule.js
const appendChildRule = {
    id: 'no-appendchild',
    description: 'Disallow use of appendChild() to prevent DOM-based injection.',
    severity: 'low',
    check(ast, meta, walk) {
        const self = this
        const issues = [];
        walk(ast, {
            CallExpression(node) {
                if (
                    node.callee.type === 'MemberExpression' &&
                    node.callee.property.name &&
                    node.callee.property.name === 'appendChild'
                ) {
                    issues.push({
                        ruleId: self.id,
                        description: self.description,
                        severity: self.severity,
                        file: node.sourceFile || meta.fileId,
                        type: node.type,
                        start: node.loc.start,
                        end: node.loc.end,
                        location: node.loc
                    });
                }
            }
        });
        return issues;
    }
};

// rules/functionConstructorRule.js
const functionConstructorRule = {
    id: 'no-function-constructor',
    description: 'Disallow use of the Function constructor to prevent dynamic code execution.',
    severity: 'low',
    check(ast, meta, walk) {
        const self = this
        const issues = [];
        walk(ast, {
            NewExpression(node) {
                if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
                    issues.push({
                        ruleId: self.id,
                        description: self.description,
                        severity: self.severity,
                        file: node.sourceFile || meta.fileId,
                        type: node.type,
                        start: node.loc.start,
                        end: node.loc.end,
                        location: node.loc
                    });
                }
            }
        });
        return issues;
    }
};

// rules/openRedirectRule.js
const openRedirectRule = {
    id: 'no-open-redirect',
    description: 'Disallow window.open() calls to prevent open redirects.',
    severity: 'low',
    check(ast, meta, walk) {
        const self = this
        const issues = [];
        walk(ast, {
            CallExpression(node) {
                if (
                    node.callee.type === 'MemberExpression' &&
                    ((node.callee.object.name === 'window' && node.callee.property.name === 'open') ||
                        (node.callee.object.name === 'location' && node.callee.property.name === 'assign'))
                ) {
                    issues.push({
                        ruleId: self.id,
                        description: self.description,
                        severity: self.severity,
                        file: node.sourceFile || meta.fileId,
                        type: node.type,
                        start: node.loc.start,
                        end: node.loc.end,
                        location: node.loc
                    });
                }
            }
        });
        return issues;
    }
};

export default [
    xssRule,
    noEvalRule,
    documentWriteRule,
    insertAdjacentHTMLRule,
    appendChildRule,
    functionConstructorRule,
    openRedirectRule
];