/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"


const worker = self

export class ptk_iast {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_iast"
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
        this.unregisterScript()
        this.isScanRunning = false
        this.scanResult = this.getScanResultSchema()
    }

    getScanResultSchema() {
        return {
            type: "iast",
            scanId: null,
            date: new Date().toISOString(),
            tabId: null,
            host: null,
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

        if (message.channel == "ptk_popup2background_iast") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_content2iast") {

            if (message.type == 'check') {
                console.log('check iast')
                if (this.isScanRunning && this.scanResult.tabId == sender.tab.id)
                    return Promise.resolve({ loadAgent: true })
                else
                    return Promise.resolve({ loadAgent: false })
            }
        }

        if (message.channel == "ptk_content_iast2background_iast") {

            if (message.type == 'finding_report') {
                if (this.isScanRunning && this.scanResult.tabId == sender.tab.id) {
                    let i = this.scanResult.items.findIndex(a => (a.timestamp == message.finding.timestamp))
                    if (i == -1) {
                        this.scanResult.items.push(message.finding)
                        ptk_storage.setItem(this.storageKey, this.scanResult)
                    }
                }
            }
        }
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
        this.runBackroungScan(message.tabId, message.host)
        return Promise.resolve({ isScanRunning: this.isScanRunning, scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    msg_stop_bg_scan(message) {
        this.stopBackroungScan()
        return Promise.resolve({ scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    runBackroungScan(tabId, host) {
        this.reset()
        this.isScanRunning = true
        this.scanningRequest = false
        this.scanResult.scanId = ptk_utils.UUID()
        this.scanResult.tabId = tabId
        this.scanResult.host = host
        this.registerScript()
        this.addListeners()
    }

    stopBackroungScan() {
        this.isScanRunning = false
        this.scanResult.tabId = null
        ptk_storage.setItem(this.storageKey, this.scanResult)
        this.unregisterScript()
        this.removeListeners()
    }

    registerScript() {
        let file = !worker.isFirefox ? 'ptk/content/iast.js' : 'content/iast.js'
        try {
            browser.scripting.registerContentScripts([{
                id: 'iast-agent',
                js: [file],
                matches: ['<all_urls>'],
                runAt: 'document_start',
                world: 'MAIN'
            }]).then(s => {
                console.log(s)
            });
        } catch (e) {
            console.log('Failed to register IAST script:', e);
        }
    }

    async unregisterScript() {
        try {
            await browser.scripting.unregisterContentScripts({
                ids: ["iast-agent"],
            });
        } catch (err) {
            //console.log(`failed to unregister content scripts: ${err}`);
        }

    }

}