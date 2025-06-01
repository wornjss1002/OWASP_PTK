/* Author: Denis Podgurskii */

import * as acorn from './acorn/acorn.mjs';
import { simple as walkSimple } from './acorn/walk.mjs';
import { Parser } from './acorn/acorn.mjs';
import { full, ancestor, base } from './acorn/walk.mjs';


import * as rules from './rules/rules.js';
import * as taint from './rules/taint.js';

export class sastEngine {
    constructor(policy) {
        if (policy == 1) this.rules = taint.default
        else this.rules = rules.default.concat(taint.default);
    }

    /**
     * Load an array of rule definitions
     */
    async loadRules(rules) {
        let obj = await import(rules);
        if (Array.isArray(obj.default)) {
            this.rules = this.rules.concat(obj.default)
        }
    }

    /**
     * Add a single rule at runtime
     */
    addRule(rule) {
        this.rules.push(rule);
    }

    async buildMergedAST(files) {
        // files: [ { code: string, sourceFile: string }, { … } ]
        // Parse the first file normally:
        let mergedAst = Parser.parse(files[0].code, {
            ecmaVersion: 2020,
            sourceType: 'module',
            locations: true,
            sourceFile: files[0].sourceFile
        });

        // For each subsequent file, parse with `program: mergedAst` so its top‐level nodes append into mergedAst.body
        for (let i = 1; i < files.length; i++) {
            const { code, sourceFile } = files[i];
            mergedAst = Parser.parse(code, {
                ecmaVersion: 2020,
                sourceType: 'module',
                locations: true,
                sourceFile,
                program: mergedAst
            });
        }

        return mergedAst; // this is a Program node, with `mergedAst.body = […]`
    }

    extractInlineHandlers(htmlText) {
        const patterns = [
            'onclick', 'ondblclick', 'onmousedown', 'onmouseup',
            'onmouseover', 'onmouseout', 'onmousemove', 'onmouseenter',
            'onmouseleave', 'onkeydown', 'onkeyup', 'onkeypress',
            'oninput', 'onchange', 'onfocus', 'onblur',
            'onsubmit', 'onreset', 'onselect', 'oncontextmenu',
            'onwheel', 'ondrag', 'ondrop', 'onload',
            'onunload', 'onabort', 'onerror', 'onresize',
            'onscroll'
        ];

        const snippets = [];
        for (const attr of patterns) {
            // Use [\s\S]*? instead of .*
            const re = new RegExp(
                `\\b${attr}\\s*=\\s*"(?:[\\s\\S]*?)"|\\b${attr}\\s*=\\s*'(?:[\\s\\S]*?)'`,
                'gi'
            );
            let match;
            while ((match = re.exec(htmlText))) {
                // match[0] contains the entire `onclick="…"` including quotes
                // We need to strip off `onclick="` and the trailing `"`
                const full = match[0];
                // Find the opening quote character:
                const quote = full.includes(`=${attr}=`) ? '"' : "'";
                // But simpler: split on first quote itself:
                const inner = full.replace(new RegExp(`^\\s*${attr}\\s*=\\s*["']`), '')
                    .replace(/["']\s*$/, '');
                snippets.push(inner);
            }
        }
        return snippets;
    }


    async scanCode(scripts, html = '') {
        // ----------------------------------------------------------
        // A) We want to keep codeByFile[fileId] = raw JavaScript text
        //    so that, later, we can extract the snippet by location.
        // ----------------------------------------------------------
        const codeByFile = Object.create(null);
        const allBodies = [];

        // ----------------------------------------------------------
        // Step 0: If you already have the full HTML text in
        //         `this.rawHtml`, extract all inline-event snippets.
        // ----------------------------------------------------------
        const inlineSnippets = this.extractInlineHandlers(html);

        // (0a) Parse each inline‐onclick snippet and tag it as "inline‐onclick[#i]"
        for (let i = 0; i < inlineSnippets.length; i++) {
            const snippet = inlineSnippets[i];
            let snippetAST = null;

            try {
                snippetAST = acorn.parse(snippet, {
                    ecmaVersion: 'latest',
                    sourceType: 'script',
                    locations: true
                });
            } catch (e) {
                console.warn('Failed to parse inline onclick snippet:', snippet, e);
                continue;
            }

            // (0b) Use `full(...)` to assign sourceFile = `inline‐onclick[#i]` to every node:
            full(snippetAST, (node) => {
                node.sourceFile = `inline‐onclick[#${i}]`;
            });

            // (0c) Collect its top-level statements into allBodies:
            allBodies.push(snippetAST.body);

            // (0d) Remember raw text under that synthetic fileId:
            codeByFile[`inline‐onclick[#${i}]`] = snippet;
        }

        // ----------------------------------------------------------
        // B) Now process each <script> block, exactly as before.
        // ----------------------------------------------------------
        for (const script of scripts) {
            const fileId = script.src || `inline-script[#${allBodies.length}]`;

            let code = script.code;
            if (script.src) {
                try {
                    const res = await fetch(script.src);
                    code = await res.text();
                } catch {
                    code = '';
                }
            }
            codeByFile[fileId] = code;

            // B1) Parse the script into its own AST
            let thisAST = null;
            try {
                thisAST = acorn.parse(code, {
                    ecmaVersion: 'latest',
                    sourceType: 'module',
                    locations: true
                });
            } catch (e) {
                console.warn(`Failed to parse <script> ${fileId}:`, e);
                continue;
            }

            // B2) Annotate *every* node in thisAST with sourceFile = fileId
            full(thisAST, (node) => {
                node.sourceFile = fileId;
            });

            // B3) Push its top‐level statements into allBodies:
            allBodies.push(thisAST.body);
        }

        // ----------------------------------------------------------
        // If nothing was parsed at all, bail out.
        // ----------------------------------------------------------
        if (allBodies.length === 0) {
            return [];
        }

        // ----------------------------------------------------------
        // C) Build a "masterAST" by reusing the first file as a template
        //    and then replacing its .body with allBodies.flat().
        // ----------------------------------------------------------
        const firstFileId = Object.keys(codeByFile)[0] || 'inline‐first';
        const firstCode = codeByFile[firstFileId] || '';
        const templateAST = acorn.parse(firstCode, {
            ecmaVersion: 'latest',
            sourceType: 'module',
            locations: true
        });

        // C1) Make sure any node in templateAST that has no sourceFile 
        //     gets sourceFile = firstFileId:
        full(templateAST, (node) => {
            if (!node.sourceFile) {
                node.sourceFile = firstFileId;
            }
        });

        // C2) Replace `templateAST.body` with the flattened array of all top‐level statements:
        templateAST.body = allBodies.flat();
        const masterAST = templateAST;

        // ----------------------------------------------------------
        // D) (Optional) Debug: list all top‐level FunctionDeclaration names
        // ----------------------------------------------------------
        const topFuncs = masterAST.body
            .filter(n => n.type === 'FunctionDeclaration')
            .map(fn => fn.id.name);
        console.log('Top‐level functions in merged AST:', topFuncs);

        // ----------------------------------------------------------
        // E) Run each taint rule’s `check(...)` on masterAST.
        //    Each rule can refer to node.sourceFile and node.loc to fill
        //    issue.sourceFile, issue.sourceLoc, issue.sinkFile, issue.sinkLoc.
        // ----------------------------------------------------------
        const rawFindings = [];
        for (const rule of this.rules) {
            // Pass masterAST; the rule can read node.sourceFile if it wants.
            const findings = rule.check.call(rule, masterAST, {}, ancestor) || [];
            rawFindings.push(...findings);
        }

        // ----------------------------------------------------------
        // F) Post‐process each finding so that code snippets come
        //    from the correct file.  Now `issue.sourceFile` and `issue.sinkFile`
        //    should be populated (not undefined), because every AST node had one.
        // ----------------------------------------------------------
        const issues = [];
        for (const issue of rawFindings) {
            const { sourceFile, sourceLoc, sinkFile, sinkLoc } = issue;
            let snippetExt = '';

            // 1) Attach source snippet if available
            if (sourceFile && sourceLoc) {
                const text = codeByFile[sourceFile] || '';
                // sourceLoc is a full { start:{line,col}, end:{line,col} } object
                issue.sourceSnippet = this.getCodeSnippet(text, sourceLoc);
                snippetExt += `Source in file: ${sourceFile}\r\n`;
                snippetExt += this.getCodeSnippetExt(text, sourceLoc);
                snippetExt += `\r\n\r\n`;
            }

            // 2) Attach sink snippet if available
            if (sinkFile && sinkLoc) {
                const text = codeByFile[sinkFile] || '';
                issue.sinkSnippet = this.getCodeSnippet(text, sinkLoc);
                snippetExt += `Sink in file: ${sinkFile}\r\n`;
                snippetExt += this.getCodeSnippetExt(text, sinkLoc);
                snippetExt += `\r\n\r\n`;
            }

            // 3) If we have either source or sink context, set codeSnippet to snippetExt
            if (snippetExt !== '') {
                issue.codeSnippet = snippetExt;
            }
            // 4) Otherwise (legacy), fall back to issue.location + issue.file
            else if (issue.location && issue.file) {
                const text = codeByFile[issue.file] || '';
                issue.codeSnippet = this.getCodeSnippetExt(text, issue.location);
            }

            issues.push(issue);
        }

        return issues;
    }

    getCodeSnippet(code, loc) {
        if (!code || !loc || typeof loc.start.line !== 'number') return '';
        const lines = code.split('\n');
        const idx = loc.start.line - 1; // zero‐based
        if (idx < 0 || idx >= lines.length) return '';
        return lines[idx].trim();
    }

    getCodeSnippetExt(code, location) {
        let lines = code.split(/\r\n|\r|\n/)
        let startLine = location.start.line
        let endLine = location.end.line
        let snippet = ''
        if (lines.length > 3 && (startLine - 1) <= lines.length) {
            snippet = "...\r\n"
            snippet += (startLine - 2) >= 0 ? lines[startLine - 2] + "\r\n" : ''
            snippet += (startLine - 1) >= 0 ? lines[startLine - 1] + "\r\n" : ''
            snippet += startLine < lines.length ? lines[startLine] + "\r\n" : ''
            if ((endLine - 2) <= lines.length && endLine > startLine) {
                snippet += "...\r\n"
                snippet += lines[endLine - 2] + "\r\n"
                snippet += "...\r\n"
            } else {
                snippet += "...\r\n"
            }
        } else {
            snippet = code
        }
        return snippet
    }

}
