/* Author: Denis Podgurskii */

import * as acorn from './acorn/acorn.mjs';
import { simple as walkSimple } from './acorn/walk.mjs';
import * as rules from './rules.js';

export class sastEngine {
    constructor() {
        this.rules = rules.default;
    }

    /**
     * Load an array of rule definitions
     */
    loadRules(rules) {
        this.rules = Array.isArray(rules) ? [...rules] : [];
    }

    /**
     * Add a single rule at runtime
     */
    addRule(rule) {
        this.rules.push(rule);
    }

    /**
     * Scan code string and return an array of issues
     */
    scan(code, meta = {}) {
        let ast;
        try {
            // Use ESM parse
            ast = acorn.parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: true });
        } catch (e) {
            return [{
                ruleId: 'parse-error',
                message: `Parse error: ${e.message}`,
                file: meta.fileId || 'inline',
                line: e.loc?.line || null,
                column: e.loc?.column || null,
                severity: 'error'
            }];
        }

        const issues = [];
        for (const rule of this.rules) {
            if (typeof rule.check === 'function') {
                try {
                    const findings = rule.check(ast, meta, walkSimple) || [];
                    findings.forEach(f => {
                        issues.push({
                            ruleId: rule.id,
                            type: f.type,
                            message: rule.description,
                            file: f.file || meta.fileId || 'inline',
                            start: f.start,
                            end: f.end,
                            severity: rule.severity || 'warning'
                        });
                    });
                } catch (err) {
                    console.log(`Error executing rule ${rule.id}:`, err);
                }
            }
        }

        return this._dedupe(issues);
    }

    /**
     * Deduplicate issues
     */
    _dedupe(issues) {
        const seen = new Set();
        return issues.filter(i => {
            const key = `${i.file}:${i.start}:${i.end}:${i.ruleId}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });
    }
}
