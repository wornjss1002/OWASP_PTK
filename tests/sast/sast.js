/* Author: Denis Podgurskii */

import { sastEngine } from '../../src/ptk/background/sast/sastEngine.js';
import * as fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);


async function runInlineTest() {
    const engine = new sastEngine()
    let findings = []
    let scripts = []
    let code = fs.readFileSync(path.resolve(__dirname, 'examples.js'));
    scripts = [
        {
            "src": null,
            "code": code
        }
    ]
    findings = await engine.scanCode(scripts)
    console.log(findings)



}


async function runExternalInlineTest() {
    const engine = new sastEngine()
    let findings = []
    let scripts = []
    scripts =
        [
            {
                "src": "http://127.0.0.1:8080/js/lib.js",
                "code": null
            },
            {
                "src": "http://127.0.0.1:8080/js/inner_html.js",
                "code": null
            },
            {
                "src": null,
                "code": "\n    document.addEventListener('DOMContentLoaded', () => {\n      // 1) Clear storage so each test is fresh\n      localStorage.clear();\n      sessionStorage.clear();\n\n      // Set cookie\n      document.cookie = '';\n      const cs = 'payload=cVal' + Date.now() + ';path=/';\n      document.cookie = cs;\n      document.getElementById('cookieVal').textContent = cs;\n\n\n      // 2) Prepopulate storage & window.name with unique values\n      const ls = 'ls-' + Date.now();\n      localStorage.setItem('payload', ls);\n      document.getElementById('lsVal').textContent = ls;\n\n      const ss = 'ss-' + Date.now();\n      sessionStorage.setItem('payload', ss);\n      document.getElementById('ssVal').textContent = ss;\n\n      const wn = 'wn-' + Date.now();\n      window.name = wn;\n      document.getElementById('wnVal').textContent = wn;\n\n      // 3) Show document.referrer\n      document.getElementById('refVal').textContent = document.referrer || '(none)';\n\n      // 4) Auto‐run on load for query/hash (so Reload and Hash buttons work)\n      const params = new URLSearchParams(location.search);\n      if (params.has('payload')) {\n        runSink(params.get('payload'));\n      }\n      if (location.hash) {\n        runSink(decodeURIComponent(location.hash.slice(1)));\n      }\n    });\n\n    // Also catch hash changes without reload\n    window.addEventListener('hashchange', () => {\n      runSink(location.hash.slice(1));\n    });\n  "
            }
        ]
        let html = `
        <!DOCTYPE html>
<html>

<head>
  <meta charset="utf-8">
  <title>Test: innerHTML Sink</title>
  <style>
    table {
      border-collapse: collapse;
      width: 100%;
    }

    th,
    td {
      border: 1px solid #ccc;
      padding: 8px;
    }

    th {
      background: #f0f0f0;
      text-align: left;
    }
  </style>
</head>

<body>
  <h1>innerHTML Sink Test</h1>
  <h3><a href="/">Back to all test cases</a></h3>
  <table>
    <tr>
      <th>Source</th>
      <th>Action</th>
    </tr>

    <!-- Inline -->
    <tr>
      <td>Inline</td>
      <td>
        <input id="inlineVal" placeholder="Enter payload">
        <button onclick="runSink(document.getElementById('inlineVal').value)">
          Run
        </button>
      </td>
    </tr>

    <!-- Query Param -->
    <tr>
      <td>Query Param</td>
      <td>
        <input id="queryVal" placeholder="Enter payload">
        <button onclick="
          const queryV = document.getElementById('queryVal').value;
          location.search = '?payload=' + encodeURIComponent(queryV);
        ">Set & Reload</button>
      </td>
    </tr>

    <!-- Hash -->
    <tr>
      <td>Hash</td>
      <td>
        <input id="hashVal" placeholder="Enter payload">
        <button onclick="
          const hashV = document.getElementById('hashVal').value;
          location.hash = encodeURIComponent(hashV);
        ">Set Hash</button>
      </td>
    </tr>

    <!-- Cookie -->
    <tr>
      <td>Cookie</td>
      <td>
        <span id="cookieVal"></span>
        <button onclick="
          runSink(getCookie('payload'));
        ">Run</button>
      </td>
    </tr>

    <!-- Local Storage -->
    <tr>
      <td>Local Storage</td>
      <td>
        <span id="lsVal"></span>
        <button onclick="runSink(localStorage.getItem('payload'))">
          Run
        </button>
      </td>
    </tr>

    <!-- Session Storage -->
    <tr>
      <td>Session Storage</td>
      <td>
        <span id="ssVal"></span>
        <button onclick="runSink(sessionStorage.getItem('payload'))">
          Run
        </button>
      </td>
    </tr>

    <!-- window.name -->
    <tr>
      <td>window.name</td>
      <td>
        <span id="wnVal"></span>
        <button onclick="runSink(window.name)">
          Run
        </button>
      </td>
    </tr>

    <!-- Referrer -->
    <tr>
      <td>Referrer</td>
      <td>
        <span id="refVal"></span>
        <button onclick="runSink(document.referrer)">
          Run
        </button>
      </td>
    </tr>
  </table>

  <script src="js/lib.js"></script>
  <script src="js/inner_html.js"></script>
  <script>
    document.addEventListener('DOMContentLoaded', () => {
      // 1) Clear storage so each test is fresh
      localStorage.clear();
      sessionStorage.clear();

      // Set cookie
      document.cookie = '';
      const cs = 'payload=cVal' + Date.now() + ';path=/';
      document.cookie = cs;
      document.getElementById('cookieVal').textContent = cs;


      // 2) Prepopulate storage & window.name with unique values
      const ls = 'ls-' + Date.now();
      localStorage.setItem('payload', ls);
      document.getElementById('lsVal').textContent = ls;

      const ss = 'ss-' + Date.now();
      sessionStorage.setItem('payload', ss);
      document.getElementById('ssVal').textContent = ss;

      const wn = 'wn-' + Date.now();
      window.name = wn;
      document.getElementById('wnVal').textContent = wn;

      // 3) Show document.referrer
      document.getElementById('refVal').textContent = document.referrer || '(none)';

      // 4) Auto‐run on load for query/hash (so Reload and Hash buttons work)
      const params = new URLSearchParams(location.search);
      if (params.has('payload')) {
        runSink(params.get('payload'));
      }
      if (location.hash) {
        runSink(decodeURIComponent(location.hash.slice(1)));
      }
    });
    runSink(getCookie('payload'));
    // Also catch hash changes without reload
    window.addEventListener('hashchange', () => {
      runSink(decodeURIComponent(location.hash.slice(1)));
    });
  </script>
</body>

</html>
        `

    findings = await engine.scanCode(scripts, html)
    console.log(findings)

}

runExternalInlineTest()





