/* Author: Denis Podgurskii */
import { dastEngine } from "./dast/dastEngine.js"
import { ptk_utils, ptk_logger, ptk_storage } from "../background/utils.js"


const worker = self

export class ptk_rattacker {

    constructor(settings) {
        this.settings = settings
        this.storageKey = "ptk_rattacker"

        this.engine = new dastEngine(this.settings)
        this.addMessageListeners()
    }


    async init() {
        this.storage = await ptk_storage.getItem(this.storageKey)
        if (!this.engine.isRunning && Object.keys(this.storage).length > 0) {
            this.scanResult = this.storage
        } else {
            this.scanResult = this.engine.scanResult
        }
    }

    async reset() {
        this.engine.reset()
        this.scanResult = this.engine.scanResult
        ptk_storage.setItem(this.storageKey, {})
    }

    addMessageListeners() {
        this.onMessage = this.onMessage.bind(this)
        browser.runtime.onMessage.addListener(this.onMessage)
    }

    addListeners() {
        this.onRemoved = this.onRemoved.bind(this)
        browser.tabs.onRemoved.addListener(this.onRemoved)

        this.onCompleted = this.onCompleted.bind(this)
        browser.webRequest.onCompleted.addListener(
            this.onCompleted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )

        this.onResponseStarted = this.onResponseStarted.bind(this)
        browser.webRequest.onResponseStarted.addListener(
            this.onResponseStarted,
            { urls: ["<all_urls>"], types: ptk_utils.requestFilters },
            ["responseHeaders"].concat(ptk_utils.extraInfoSpec)
        )


    }

    removeListeners() {
        browser.tabs.onRemoved.removeListener(this.onRemoved)
        browser.webRequest.onCompleted.removeListener(this.onCompleted)
        browser.webRequest.onResponseStarted.removeListener(this.onResponseStarted)
    }

    onRemoved(tabId, info) {
        if (this.engine.isRunning && this.engine.tabId == tabId) {
            this.engine.stop()
        }
    }


    onResponseStarted(response) {
        if (this.engine.isRunning && this.engine.tabId == response.tabId) {
            try {
                let rawRequest = worker.ptk_app.proxy.getRawRequest(worker.ptk_app.proxy.getTab(response.tabId), response.frameId, response.requestId)
                this.engine.enqueue(rawRequest, response)
            } catch (e) { }
        }
    }


    parseDomains(domains) {
        let d = []
        domains.split(",").forEach(function (item) {
            if (item.startsWith('*')) {
                d.push(item.replace('*.', ''))
            }
            else {
                d.push(item)
            }
        })
        return d
    }

    onCompleted(response) {
        // if (this.engine.isRunning && this.engine.tabId == response.tabId) {
        //     try {
        //         let rawRequest = worker.ptk_app.proxy.getRawRequest(worker.ptk_app.proxy.getTab(response.tabId), response.frameId, response.requestId)
        //         this.engine.enqueue(rawRequest, response)
        //     } catch (e) { }
        // }
    }

    onMessage(message, sender, sendResponse) {

        if (message.channel == "ptk_popup2background_rattacker") {
            if (this["msg_" + message.type]) {
                return this["msg_" + message.type](message)
            }
            return Promise.resolve({ result: false })
        }

        if (message.channel == "ptk_content2rattacker") {

            if (message.type == 'xss_confirmed' && this.scanResult.host == (new URL(message.data.origin)).host) {
                this.checkConfirmedAttack(message.data)
            }

            if (message.type == 'start') {
                console.log('start scan')
                this.runBackroungScan(sender.tab.id, new URL(sender.origin).host)
                return Promise.resolve({ success: true, scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
            }

            if (message.type == 'stop') {
                this.stopBackroungScan()
                let result = { attacks: this.scanResult.attacks, stats: this.scanResult.stats }
                return Promise.resolve({ scanResult: JSON.parse(JSON.stringify(result)) })
            }
        }
    }

    async msg_init(message) {
        await this.init()
        return Promise.resolve({
            scanResult: JSON.parse(JSON.stringify(this.scanResult)),
            isScanRunning: this.engine.isRunning,
            default_modules: JSON.parse(JSON.stringify(this.engine.modules)),
            activeTab: worker.ptk_app.proxy.activeTab,
            settings: this.settings
        })
    }

    async msg_check_apikey(message) {
        let self = this
        let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.attacks_endpoint
        let response = await fetch(url, { headers: { 'Authorization': message.key }, cache: "no-cache" })
            .then(response => response.text())
            .then(text => {
                try {
                    return JSON.parse(text)
                } catch (err) {
                    return { "success": false, "json": { "message": text } }
                }
            }).catch(e => {
                return { "success": false, "json": { "message": e.message } }
            })
        return response
    }

    async msg_save_report(message) {
        let apiKey = worker.ptk_app.settings.profile?.api_key
        if (apiKey && Object.keys(this.scanResult?.items)) {
            let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.storage_endpoint
            let response = await fetch(url, {
                method: "POST",
                headers: {
                    'Authorization': apiKey,
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                cache: "no-cache",
                body: JSON.stringify(this.scanResult)
            })
                .then(response => {
                    if (response.status == 201)
                        return { "success": true }
                    else {
                        return response.json().then(json => {
                            return { "success": false, json }
                        })
                    }
                })
                .catch(e => { return { "success": false, "json": { "message": "Error while saving report: " + e.message } } })
            return response
        } else {
            return { "success": false, "json": { "message": "No API key found" } }
        }
    }

    async msg_download_scans(message) {
        let apiKey = worker.ptk_app.settings.profile?.api_key
        if (apiKey) {
            let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.scans_endpoint
            let response = await fetch(url, {
                headers: {
                    'Authorization': apiKey,
                },
                cache: "no-cache"
            })
                .then(response => response.json())
                .then(json => {
                    return { "success": true, json }
                }).catch(e => {
                    return { "success": false, "json": { "message": e.message } }
                })
            return response
        } else return { "success": false, "json": { "message": "No API key found" } }
    }

    async msg_download_scan_by_id(message) {
        let apiKey = worker.ptk_app.settings.profile?.api_key
        if (apiKey) {
            let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.scans_endpoint + "/" + message.scanId
            let response = await fetch(url, {
                headers: {
                    'Authorization': apiKey,
                },
                cache: "no-cache"
            })
                .then(response => response.json())
                .then(json => {
                    ptk_storage.setItem(this.storageKey, json)
                    return json
                }).catch(e => e)
            return response
        }
    }

    async msg_delete_scan_by_id(message) {
        let apiKey = worker.ptk_app.settings.profile?.api_key
        if (apiKey) {
            let url = worker.ptk_app.settings.profile.api_url + worker.ptk_app.settings.profile.storage_endpoint + "/" + message.scanId
            let response = await fetch(url, {
                method: "DELETE",
                headers: {
                    'Authorization': apiKey,
                },
                cache: "no-cache"
            })
                .then(response => response.json())
                .then(json => {
                    this.scanResult = json
                    return json
                }).catch(e => e)
            return response
        }
    }

    msg_reset(message) {
        this.reset()
        return Promise.resolve({
            scanResult: JSON.parse(JSON.stringify(this.scanResult)),
            default_modules: JSON.parse(JSON.stringify(this.engine.modules)),
            activeTab: worker.ptk_app.proxy.activeTab
        })
    }

    async msg_loadfile(message) {
        this.reset()

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
        if ((!res.type || res.type == 'dast') && Object.keys(res?.items).length > 0) {
            this.reset()
            ptk_storage.setItem(this.storageKey, JSON.parse(message.json))
            await this.init()
            return Promise.resolve({
                scanResult: JSON.parse(JSON.stringify(this.scanResult)),
                isScanRunning: this.engine.isRunning,
                default_modules: JSON.parse(JSON.stringify(this.engine.modules)),
                activeTab: worker.ptk_app.proxy.activeTab
            })
        } else {
            return Promise.reject(new Error("Wrong format or empty scan result"))
        }
    }

    msg_run_bg_scan(message) {
        this.runBackroungScan(message.tabId, message.host, message.domains, message.settings)
        return Promise.resolve({ isScanRunning: this.engine.isRunning, scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    msg_stop_bg_scan(message) {
        this.stopBackroungScan()
        return Promise.resolve({ scanResult: JSON.parse(JSON.stringify(this.scanResult)) })
    }

    runBackroungScan(tabId, host, domains, settings) {
        this.reset()
        this.addListeners()
        this.engine.start(tabId, host, this.parseDomains(domains), settings)
    }

    stopBackroungScan() {
        this.engine.stop()
        this.scanResult = this.engine.scanResult
        ptk_storage.setItem(this.storageKey, this.scanResult)
        this.removeListeners()
    }


    checkConfirmedAttack(data) {
        this.updateScanResult(null, data)
    }

}