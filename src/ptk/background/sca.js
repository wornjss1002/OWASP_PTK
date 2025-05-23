/* Author: Denis Podgurskii */
import { ptk_utils, ptk_logger, ptk_queue, ptk_storage, ptk_ruleManager } from "../background/utils.js"
import retire from '../packages/retire/retire.js';
import CryptoES from '../packages/crypto-es/index.js';

const worker = self

export class ptk_sca {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_sca"
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

    async initRepo() {
        await fetch(browser.runtime.getURL('ptk/packages/retire/jsrepository.json'))
            .then(response => response.text())
            .then(data => {
                this.repo = JSON.parse(retire.replaceVersion(data))
            })
    }

    resetScanResult() {
        this.urls = []
        this.repo = {}
        this.initRepo()
        this.hasher = {
            sha1: function (data) {
                return CryptoES.SHA1(data).toString(CryptoES.enc.Hex)
            }
        }
        this.isScanRunning = false
        this.scanResult = this.getScanResultSchema()
    }

    getScanResultSchema() {
        return {
            type: "sca",
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
        let self = this
        if (this.isScanRunning && this.scanResult.tabId == response.tabId && ptk_utils.isURL(response?.url)) {
            if (!this.urls.includes(response.url)) {
                self.urls.push(response.url)
                self.scan(response.url).then(result => {
                    if (result.vulns.length > 0) {
                        let finding = {
                            file: result.vulns[0][0],
                            component: result.vulns[0][1][0]['component'],
                            version: result.vulns[0][1][0]['version'],
                            findings: result.vulns[0][1][0].vulnerabilities
                        }
                        self.scanResult.items.push(finding)
                        self.updateScanResult()
                    }
                })
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
            for (let f in item.findings) {
                let finding = item.findings[f]
                this.scanResult.stats.findingsCount++
                if (finding.severity.toLowerCase() == 'high') this.scanResult.stats.high++
                if (finding.severity.toLowerCase() == 'medium') this.scanResult.stats.medium++
                if (finding.severity.toLowerCase() == 'low') this.scanResult.stats.low++
            }

        }

        ptk_storage.setItem(this.storageKey, this.scanResult)
    }

    getFileName(url) {
        var a = new URL(url)//document.createElement("a");
        //a.href = url;
        return (a.pathname.match(/\/([^\/?#]+)$/i) || [, ""])[1];
    }

    async scan(url) {
        let dt = new Array()
        let fetches = []

        let results = retire.scanUri(url, this.repo)
        if (results.length > 0) {
            let hash = url + results[0].component + results[0].version
            if (dt.findIndex(u => u[2] == hash) == -1) {
                dt.push([url, results, hash])
            }
        }

        results = retire.scanFileName(this.getFileName(url), this.repo)
        if (results.length > 0) {
            let hash = url + results[0].component + results[0].version
            if (dt.findIndex(u => u[2] == hash) == -1) {
                dt.push([url, results, hash])
            }
        }

        fetches.push(
            fetch(url)
                .then(response => response.text())
                .then(content => {
                    var results = retire.scanFileContent(content, this.repo, this.hasher);
                    if (results.length > 0) {
                        let hash = url + results[0].component + results[0].version
                        if (dt.findIndex(u => u[2] == hash) == -1) {
                            dt.push([url, results, hash])
                        }
                    }
                })
                .catch(function (error) {
                    console.log(error);
                })
        )

        if (fetches.length) {
            await Promise.all(fetches).then()
        }
        return Promise.resolve({ "vulns": dt })
    }


    onMessage(message, sender, sendResponse) {
        if (message.channel == "ptk_popup2background_sca") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
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
        if (res.type == 'sca' && Object.keys(res?.items).length > 0) {
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
        this.addListeners()
    }

    stopBackroungScan() {
        this.isScanRunning = false
        this.scanResult.tabId = null
        ptk_storage.setItem(this.storageKey, this.scanResult)
        this.removeListeners()
    }

}