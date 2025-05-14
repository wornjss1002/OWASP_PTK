# pentestkit

The Penetration Testing Kit (PTK) browser extension is your all-in-one solution for streamlining your daily tasks in the realm of application security. Whether you’re a penetration tester, a Red Team member, or an AppSec practitioner, PTK enhances your efficiency and provides deep insights into your target application.

Key Features:

In-Browser IAST (Interactive Application Security Testing):
PTK’s built-in IAST engine instruments your app at runtime—right in the browser—tracking taint flows and code execution to flag vulnerabilities as they occur. Catch issues like DOM-based XSS, unsafe eval/innerHTML usage, open-redirects, and more without leaving your dev tools.

Runtime Scanning (DAST & SCA):
Perform Dynamic Application Security Testing and Software Composition Analysis on the fly. Identify SQL injection, command injection, reflected/stored XSS, SQL auth bypass, XPath injections, JWT attacks, and other complex threats.

JWT Inspector:
Analyze, craft, and tamper with JSON Web Tokens. Generate keys, test null signatures, brute-force HMAC secrets, and inject malicious JWK, JKU or kid parameters.

Insightful Application Info:
One-click visibility into tech stacks, WAFs, security headers, crawled links, and authentication flows.

Built-in Proxy & Traffic Log:
Capture all HTTP(S) traffic, replay requests in R-Builder or R-Attacker, and automate XSS, SQLi, and OS command injection.

R-Builder for Request Tampering & Smuggling:
Craft and manipulate HTTP requests, including complex request-smuggling techniques. Now with cURL import/export.

Cookie Management:
Add, edit, remove, block, protect, export, and import cookies from a powerful in-browser editor.

Decoder/Encoder Utility:
Instantly convert between UTF-8, Base64, MD5, URL-encode/decode, and more formats.

Swagger.IO Integration:
Browse and interact with API endpoints directly from your Swagger documentation.

Selenium Integration:
Shift left security by running automated Selenium tests with built-in vulnerability checks.

Enhance your AppSec practice with PTK—the extension that makes your browser smarter and your testing faster. Install today and start uncovering vulnerabilities in real time!
## Development
```
git clone git@github.com:DenisPodgurskii/pentestkit.git
cd pentestkit
npm install
npm run build
```
Chrome/Edge/Brave -> Extensions -> Load unpacked -> select pentestkit/src directory

Or run 
```
npm run build_pkg
```
This will create zip arhives in pentestkit/dist folder

On Windows build it's a chance you can expect an error during build process. In this case try to execute the following command first.
```
npm install --ignore-scripts fomantic-ui
```

## Installation

[Firefox](https://addons.mozilla.org/en-US/firefox/addon/penetration-testing-kit/) 

[Chrome](https://chrome.google.com/webstore/detail/penetration-testing-kit/ojkchikaholjmcnefhjlbohackpeeknd) 

[MS Edge](https://microsoftedge.microsoft.com/addons/detail/penetration-testing-kit/knjnghhnhcpcglfdjppffbpfndeebkdm) 


## Documentation / How To

[Website](https://pentestkit.co.uk/howto.html) 


## Youtube channel

[Youtube channel](https://www.youtube.com/channel/UCbEcTounPkV1aitE1egXfqw) 




