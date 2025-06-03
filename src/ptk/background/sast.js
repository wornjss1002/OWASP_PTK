/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"

import { sastEngine } from './sast/sastEngine.js';
import * as acorn from './sast/acorn/acorn.mjs';
import { simple as walkSimple } from './sast/acorn/walk.mjs';

const worker = self

export class ptk_sast {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_sast"
        this.resetScanResult()

        this.addMessageListeners()
    }

    async init() {

        if (!this.isScanRunning) {
            this.storage = await ptk_storage.getItem(this.storageKey)
            if (Object.keys(this.storage).length > 0) {
                this.scanResult = this.storage
            }
        }
    }

    resetScanResult() {
        this.isScanRunning = false
        this.scanResult = this.getScanResultSchema()
    }

    getScanResultSchema() {
        return {
            type: "sast",
            scanId: null,
            date: new Date().toISOString(),
            tabId: null,
            host: null,
            items: [],
            stats: {
                findingsCount: 0,
                high: 0,
                medium: 0,
                low: 0
            },
            settings: {}
        }
    }

    async reset() {
        ptk_storage.setItem(this.storageKey, {})
        this.resetScanResult()
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onUpdated = this.onUpdated.bind(this)
        browser.tabs.onUpdated.addListener(this.onUpdated)

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )
    }

    async onUpdated(tabId, info, tab) {

    }

    removeListeners() {
        browser.tabs.onRemoved.removeListener(this.onRemoved)
        browser.tabs.onUpdated.removeListener(this.onUpdated)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
    }

    onRemoved(tabId, info) {
        if (this.scanResult?.tabId == tabId) {
            this.scanResult.tabId = null
            this.isScanRunning = false
        }
    }

    onCompleted(response) {

    }

    onMessage(message, sender, sendResponse) {

        if (message.channel == "ptk_popup2background_sast") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_content_sast2background_sast") {
            if (message.type == 'scripts_collected') {
                if (this.isScanRunning && this.scanResult.tabId == sender.tab.id) {
                    this.scanCode(message.scripts, message.html, message.file).then((findings) => {
                        findings = this.removeDuplicates(findings)
                        if (findings.length > 0) {
                            this.scanResult.items.push(...findings)
                            this.updateScanResult()
                            ptk_storage.setItem(this.storageKey, this.scanResult)
                        }
                    })
                }
            }
        }
    }

    updateScanResult() {

        this.scanResult.stats = {
            findingsCount: 0,
            high: 0,
            medium: 0,
            low: 0
        }

        for (let r in this.scanResult.items) {
            let item = this.scanResult.items[r]
            this.scanResult.stats.findingsCount++
            if (item.severity == 'high') this.scanResult.stats.high++
            if (item.severity == 'medium') this.scanResult.stats.medium++
            if (item.severity == 'low') this.scanResult.stats.low++
        }

        ptk_storage.setItem(this.storageKey, this.scanResult)
    }

    removeDuplicates(issues) {

        return issues.filter(i => {
            console.log(i)
            let ind = 0
            if (i.location) {
                ind = this.scanResult.items.findIndex(e =>
                    e.ruleId == i.ruleId &&
                    e.severity == i.severity &&
                    JSON.stringify(e.location) == JSON.stringify(i.location) &&
                    e.file == i.file
                )
            } else if (i.sourceLoc && i.sinkLoc) {
                ind = this.scanResult.items.findIndex(e =>
                    e.ruleId == i.ruleId &&
                    e.severity == i.severity &&
                    JSON.stringify(e.sourceLoc) == JSON.stringify(i.sourceLoc) &&
                    JSON.stringify(e.sinkLoc) == JSON.stringify(i.sinkLoc) &&
                    e.sourceFileFull == i.sourceFileFull &&
                    e.sinkFileFull == i.sinkFileFull
                )
            }
            if (ind > -1) return false;
            return true;
        });

    }

    // async scanCode(scripts) {
    //     const engine = new sastEngine()
    //     const issues = [];
    //     for (const script of scripts) {
    //         let code = script.code;
    //         if (script.src) {
    //             try {
    //                 const res = await fetch(script.src);
    //                 code = await res.text();
    //             } catch {
    //                 code = '';
    //             }
    //         }
    //         const findings = engine.scan(code, { fileId: script.src || 'inline' });
    //         findings.forEach(element => {
    //             if(element.location)
    //                 element.snippet = this.getCodeSnippet(code, element.location)
    //             else if(element.source && element.sink){
    //                 element.source = this.getCodeSnippet(code, element.source)
    //                 element.sink = this.getCodeSnippet(code, element.sink)
    //             }
    //         });
    //         issues.push(...findings);
    //     }
    //     return issues
    // }


    async scanCode(scripts, html, file) {
        const engine = new sastEngine(this.scanResult.policy);
        return await engine.scanCode(scripts, html, file)
    }

    async msg_init(message) {
        await this.init()
        return Promise.resolve({
            scanResult: JSON.parse(JSON.stringify(this.scanResult)),
            isScanRunning: this.isScanRunning,
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }


    msg_reset(message) {
        this.reset()
        return Promise.resolve({
            scanResult: JSON.parse(JSON.stringify(this.scanResult)),
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    async msg_loadfile(message) {
        this.reset()
        //await this.init()

        return new Promise((resolve, reject) => {
            var fr = new FileReader()
            fr.onload = () => {

                resolve(this.msg_save(fr.result))
            }
            fr.onerror = reject
            fr.readAsText(message.file)
        })

    }

    async msg_save(message) {
        let res = JSON.parse(message.json)
        if (res.type == 'iast' && Object.keys(res?.items).length > 0) {
            this.reset()
            ptk_storage.setItem(this.storageKey, JSON.parse(message.json))
            await this.init()
            return Promise.resolve({
                scanResult: JSON.parse(JSON.stringify(this.scanResult)),
                isScanRunning: this.isScanRunning,
                activeTab: worker.ptk_app.proxy.activeTab
            })
        } else {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
    }

    msg_run_bg_scan(message) {
        this.runBackroungScan(message.tabId, message.host, message.policy)
        return Promise.resolve({ isScanRunning: this.isScanRunning, scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    msg_stop_bg_scan(message) {
        this.stopBackroungScan()
        return Promise.resolve({ scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    runBackroungScan(tabId, host, policy) {
        this.reset()
        this.isScanRunning = true
        this.scanningRequest = false
        this.scanResult.scanId = ptk_utils.UUID()
        this.scanResult.tabId = tabId
        this.scanResult.host = host
        this.scanResult.policy = policy
        this.addListeners()
    }

    stopBackroungScan() {
        this.isScanRunning = false
        this.scanResult.tabId = null
        ptk_storage.setItem(this.storageKey, this.scanResult)
        this.removeListeners()
    }

}