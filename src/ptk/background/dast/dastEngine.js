// dastEngine.js
import { ptk_module } from "../../modules/module.js"
import { ptk_request } from "../rbuilder.js"
import { ptk_utils, ptk_queue, ptk_ruleManager } from "../utils.js"


export class dastEngine {
    /**
     * settings: { maxRequestsPerSecond, concurrency, modulesUrl, ... }
     */
    constructor(settings = {}) {
        this.settings = settings
        this.maxRequestsPerSecond = settings.maxRequestsPerSecond || 10
        this.concurrency = settings.concurrency || 2 // 1=sequential
        this.reset()

        this.loadModules()
        this.loadProModules()
    }

    reset() {
        this.isRunning = false
        this.result = this.getEmptyScanResult()
        this.tokens = this.maxRequestsPerSecond
        this.lastRefill = Date.now()
        this.tokenRefillInterval = 1000
        this.activeCount = 0
        this.scanResult = this.getEmptyScanResult()
    }

    async loadModules() {
        const resp = await fetch(browser.runtime.getURL('ptk/modules/modules.json'))
        const json = await resp.json()
        this.modules = Object.values(json.modules).map(m => new ptk_module(m))
    }


    async loadProModules() {
        // let self = this
        // this.pro_modules = []
        // let apiKey = worker.ptk_app?.settings?.profile?.api_key
        // let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.attacks_endpoint
        // if (apiKey) {
        //     return await fetch(url, { headers: { 'Authorization': apiKey }, cache: "no-cache" })
        //         .then(response => response.json())
        //         .then(json => {
        //             let modules = JSON.parse(json.rules.modules.json).modules
        //             Object.values(modules).forEach(module => {
        //                 self.pro_modules.push(new ptk_module(module))
        //             })
        //         }).catch(e => {
        //             console.log(e)
        //             return { "success": false, "json": { "message": e.message } }
        //         })
        // }
    }

    getEmptyScanResult() {
        return {
            type: "dast",
            scanId: null,
            date: new Date().toISOString(),
            tabId: null,
            host: null,
            uniqueRequestQueue: new ptk_queue(),
            requestQueue: new ptk_queue(),
            items: [],
            stats: {
                vulnsCount: 0,
                high: 0,
                medium: 0,
                low: 0,
                attacksCount: 0
            },
            settings: {}
        }
    }

    canSendRequest() {
        const now = Date.now()
        if (now - this.lastRefill > this.tokenRefillInterval) {
            this.tokens = this.maxRequestsPerSecond
            this.lastRefill = now
        }
        if (this.tokens > 0) {
            this.tokens--
            return true
        }
        return false
    }

    enqueue(rawRequest, response) {
        if (this.isAllowed(response)) {
            let url = rawRequest.split('\n')[0]
            if (!this.scanResult.uniqueRequestQueue.has(url)) {
                this.scanResult.uniqueRequestQueue.enqueue(url)
                this.scanResult.requestQueue.enqueue(rawRequest)
            }
        }
    }

    isAllowed(response) {
        let allowed = true
        let url = new URL(response.url)
        if (this.settings.blacklist.includes(response.type) && !url.search) {
            allowed = false
        } else {
            if (!url.host.includes(this.host)) allowed = false
            if (this.domains.findIndex(i => url.host.includes(i)) > 0) allowed = true
        }

        return allowed
    }

    updateScanResult(result, data) {
        if (result) {
            this.scanResult.items.push(result)
        }

        this.scanResult.stats = {
            vulnsCount: 0,
            high: 0,
            medium: 0,
            low: 0,
            attacksCount: 0
        }

        for (let r in this.scanResult.items) {
            let item = this.scanResult.items[r]

            if (data) {
                let i = item.attacks.findIndex(a => (a.metadata.action?.random == data.attackValue.ptk && !a.success))
                if (i > -1) {
                    item.attacks[i].success = true
                    item.attacks[i].proof = 'Confirmed by code execution on ' + data.location + '. Attack parameter value is: ' + data.attackValue.ptk
                }
            }

            for (let i in item.attacks) {
                this.scanResult.stats.attacksCount++
                if (item.attacks[i].success) {
                    this.scanResult.stats.vulnsCount++
                    if (item.attacks[i].metadata.severity == 'High') this.scanResult.stats.high++
                    if (item.attacks[i].metadata.severity == 'Medium') this.scanResult.stats.medium++
                    if (item.attacks[i].metadata.severity == 'Low') this.scanResult.stats.low++
                }

            }
        }
        if (result)
            browser.runtime.sendMessage({
                channel: "ptk_background2popup_rattacker",
                type: "all attacks completed",
                info: result,
                scanResult: JSON.parse(JSON.stringify(this.scanResult))
            }).catch(e => console.log(e));
    }

    async start(tabId, host, domains) {
        this.reset()
        this.tabId = tabId
        this.host = host
        this.domains = domains
        this.isRunning = true
        this.scanId = ptk_utils.UUID()

        this.inProgress = false
        this.run()
    }

    stop() {
        this.isRunning = false
    }

    async run() {
        if (!this.isRunning) return
       
        const self = this
        if (!this.inProgress) {
            if (this.concurrency === 1) {
                this.runSequential()
            } else {
                this.runParallel()
            }
        }
        setTimeout(function () { self.run() }, 200)
    }

    async runSequential() {
        const self = this
        this.inProgress = true
        while (this.isRunning && this.scanResult.requestQueue.size()) {
            const raw = this.scanResult.requestQueue.dequeue()
            const result = await this.scanRequest(raw)
            if (result) {
                this.updateScanResult(result)
            }
        }
        this.inProgress = false
    }

    async runParallel() {
        const self = this;
        const workers = [];
        self.inProgress = true
        while (this.isRunning && this.scanResult.requestQueue.size()) {
            while (workers.length < this.concurrency && this.scanResult.requestQueue.size()) {
                const raw = this.scanResult.requestQueue.dequeue();
                // Capture the Promise in a variable so we can reference it
                const workerPromise = this.scanRequest(raw).then(result => {
                    if (result) {
                        this.updateScanResult(result);
                    }
                }).finally(() => {
                    // Remove this specific promise
                    workers.splice(workers.indexOf(workerPromise), 1);
                });

                workers.push(workerPromise);
            }
            if (workers.length) {
                await Promise.race(workers);
            }
        }
        await Promise.all(workers);
        self.inProgress = false
    }


    async scanRequest(raw) {
        const schema = ptk_request.parseRawRequest(raw)
        const original = await this.executeOriginal(schema)
        const attacks = []
        if (!original) return null

        const self = this

        // For each module, run attacks
        for (const module of this.modules) {
            for (const attackDef of module.attacks) {

                while (!this.canSendRequest() && this.isRunning) {
                    await this._sleep(20);
                }
                const attack = module.prepareAttack(attackDef)
                if (attack.condition) {
                    const _a = { metadata: Object.assign({}, attack, module.metadata) }
                    if (!module.validateAttackConditions(_a, original)) continue
                }
                if (module.type === 'active') {
                    const _schema = ptk_request.parseRawRequest(original.request.raw, attack.action.options)
                    const attackRequests = module.buildAttacks(_schema, attack)
                    for (const req of attackRequests) {
                        const _s = ptk_request.updateRawRequest(req, null, attack.action.options)
                        _s.metadata = Object.assign({}, module.metadata, attack)
                        const executed = await this.activeAttack(_s)
                        if (executed && attack.validation) {
                            const res = module.validateAttack(executed, original)
                            attacks.push(Object.assign(executed, res))
                        }
                    }
                } else if (module.type === 'passive') {
                    const _s = { metadata: Object.assign({}, attack, module.metadata) }
                    const res = module.validateAttack(_s, original)
                    if (res.success) attacks.push(Object.assign(_s, res))
                }
                browser.runtime.sendMessage({
                    channel: "ptk_background2popup_rattacker",
                    type: "attack completed",
                    info: attack,
                    scanResult: JSON.parse(JSON.stringify(self.scanResult))
                }).catch(e => console.log(e))
            }
        }
        // summarize stats, etc.
        return { original, attacks }
    }

    async activeAttack(schema) {
        try {
            let request = new ptk_request()
            return request.sendRequest(schema)
        } catch (e) {
            // optionally: log or handle
        }
    }

    async executeOriginal(schema) {
        let _schema = JSON.parse(JSON.stringify(schema))
        let request = new ptk_request()
        _schema.opts.override_headers = false
        _schema.opts.follow_redirect = true
        return Promise.resolve(request.sendRequest(_schema))
    }

    _sleep(ms) {
        return new Promise(r => setTimeout(r, ms))
    }
}
