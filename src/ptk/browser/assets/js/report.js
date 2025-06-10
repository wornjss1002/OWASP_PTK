/* Author: Denis Podgurskii */
import { ptk_controller_index } from "../../../controller/index.js"
import { ptk_controller_sca } from "../../../controller/sca.js"
import { ptk_controller_rattacker } from "../../../controller/rattacker.js"
import { ptk_controller_iast } from "../../../controller/iast.js"
import { ptk_controller_sast } from "../../../controller/sast.js"
import { ptk_utils, ptk_jwtHelper } from "../../../background/utils.js"
import { ptk_decoder } from "../../../background/decoder.js"
import * as rutils from "../js/rutils.js"

const jwtHelper = new ptk_jwtHelper()
const decoder = new ptk_decoder()

var tokens = new Array()
var tokenAdded = false

jQuery(function () {
    // -- Dashboard -- //
    const index_controller = new ptk_controller_index()
    const sca_controller = new ptk_controller_sca()
    const rattacker_controller = new ptk_controller_rattacker()
    const iast_controller = new ptk_controller_iast()
    const sast_controller = new ptk_controller_sast()


    $('#filter_all').on("click", function () {
        $('.attack_info').show()
        $('#filter_vuln').removeClass('active')
        $('#filter_all').addClass('active')
    })

    $('#filter_vuln').on("click", function () {
        $('.attack_info.nonvuln').hide()
        $('#filter_all').removeClass('active')
        $('#filter_vuln').addClass('active')
    })

    $('#print').on("click", function () {
        window.print()
    })

    $('.icon.hideshowreport').on("click", function () {
        if ($(this).hasClass('minus')) {
            $(this).removeClass('minus')
            $(this).addClass('plus')
            $(this).parent().next().hide()
        } else {
            $(this).removeClass('plus')
            $(this).addClass('minus')
            $(this).parent().next().show()
        }
    })

    async function bindInfo(host) {
        if (host) {
            $('#dashboard_message_text').html('<h2>OWASP PTK report:</h2>  ' + host)
        } else {
            $('#dashboard_message_text').html(`Reload the tab to activate tracking &nbsp;<i class="exclamation red  circle  icon"></i>`)
        }
    }

    async function bindOWASP() {
        let dt = index_controller.tab.findings ? index_controller.tab.findings : new Array()
        let params = { "data": dt, "columns": [{ width: "30%" }, { width: "70%" }] }
        let table = bindTable('#tbl_owasp', params)
        table.columns.adjust().draw()
        $('.loader.owasp').hide()
    }

    async function bindWAF() {
        //let dt = index_controller.tab.waf ? index_controller.tab.waf : new Array()
        let dt = new Array()
        Object.values(index_controller.tab.waf).forEach(waf => {
            dt.push([waf.name, waf.version])
        })
        let params = { "data": dt, "columns": [{ width: "60%" }, { width: "40%" }] }
        let table = bindTable('#tbl_waf', params)
        table.columns.adjust().draw()
        $('.loader.waf').hide()
    }

    async function bindTechnologies() {
        let dt = new Array()
        if (index_controller.tab.technologies)
            Object.values(index_controller.tab.technologies).forEach(item => {
                dt.push([item.name, item.version])
            })
        let params = { "data": dt, "columns": [{ width: "60%" }, { width: "40%" }] }
        bindTable('#tbl_technologies', params)
        $('.loader.technologies').hide()
    }


    function bindCookies() {
        if (Object.keys(index_controller.tab.cookies).length) {
            $("a[data-tab='cookie']").show()
            $('#tbl_storage').DataTable().row.add(['Cookie', `<a href="#" class="storage_auth_link" data="cookie">View</a>`]).draw()


            let dt = new Array()
            Object.values(index_controller.tab.cookies).forEach(item => {
                //Object.values(domain).forEach(item => {
                dt.push([item.domain, item.name, item.value, item.httpOnly])
                //})
            })
            dt.sort(function (a, b) {
                if (a[0] === b[0]) { return 0; }
                else { return (a[0] < b[0]) ? -1 : 1; }
            })
            var groupColumn = 0;
            let params = {
                data: dt,
                columnDefs: [{
                    "visible": false, "targets": groupColumn
                }],
                "order": [[groupColumn, 'asc']],
                "drawCallback": function (settings) {
                    var api = this.api();
                    var rows = api.rows({ page: 'current' }).nodes();
                    var last = null;

                    api.column(groupColumn, { page: 'current' }).data().each(function (group, i) {
                        if (last !== group) {
                            $(rows).eq(i).before(
                                '<tr class="group" ><td colspan="3"><div class="ui grey ribbon label">' + group + '</div></td></tr>'
                            );
                            last = group;
                        }
                    });
                }
            }

            bindTable('#tbl_cookie', params)

            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.sessionRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['cookie', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
        }
        $('.loader.storage').hide()
        bindTokens()
    }

    async function bindTokens(data) {
        if (tokens.length > 0) {
            $("div[data-tab='tokens']").show()
            if (!tokenAdded) {
                $('#tbl_storage').DataTable().row.add(['Tokens', `<a href="#" class="storage_auth_link" data="tokens">View</a>`]).draw()
                tokenAdded = true
            }
            $("a[data-tab='tokens']").show()
            bindTable('#tbl_tokens', { data: tokens })
        }
    }

    function bindStorage() {
        let dt = new Array()
        Object.keys(index_controller.tab.storage).forEach(key => {
            let item = JSON.parse(index_controller.tab.storage[key])
            if (Object.keys(item).length > 0 && item[key] != "") {
                $(document).trigger("bind_" + key, item)
                $("a[data-tab='" + key + "']").show()
                let link = `<a href="#" class="storage_auth_link" data="${key}">View</a>`
                dt.push([key, link])
            }
        })
        for (let i = 0; i < dt.length; i++) {
            $('#tbl_storage').DataTable().row.add([dt[i][0], dt[i][1]]).draw()
        }
        $('.loader.storage').hide()

        bindTokens()
    }

    function bindHeaders() {
        if (Object.keys(index_controller.tab.requestHeaders).length) {
            let dt = new Array()
            Object.keys(index_controller.tab.requestHeaders).forEach(name => {
                if (name.startsWith('x-') || name == 'authorization' || name == 'cookie') {
                    dt.push([name, index_controller.tab.requestHeaders[name][0]])
                }
            })
            let params = {
                data: dt
            }

            bindTable('#tbl_headers', params)

            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(dt), jwtHelper.headersRegex)
            if (jwtToken) {
                try {
                    let jwt = JSON.parse(decodedToken)
                    tokens.push(['headers', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
                } catch (e) { }
            }
            bindTokens()
        }
    }


    $(document).on("bind_localStorage", function (e, item) {
        if (Object.keys(item).length > 0) {
            $("div[data-tab='localStorage']").show()
            let output = JSON.stringify(item, null, 4)
            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
            $('#localStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
        }
    })

    $(document).on("bind_sessionStorage", function (e, item) {
        if (Object.keys(item).length > 0) {
            $("div[data-tab='sessionStorage']").show()
            let output = JSON.stringify(item, null, 4)
            let { jwtToken, decodedToken } = jwtHelper.checkJWT(JSON.stringify(item), jwtHelper.storageRegex)
            if (jwtToken) {
                let jwt = JSON.parse(decodedToken)
                tokens.push(['localStorage', '<pre>' + JSON.stringify(jwt["payload"], null, 2) + '</pre>', jwtToken[1]])
            }
            $('#sessionStorageText').text(output.replace(/\\r?\\n/g, '<br/>'))
        }
    })

    // -- IAST -- //

    function generateIAST(result) {
        if (!result.scanResult?.items?.length) return
        $('#iast_report').show()

        let report = ""
        result.scanResult.items.forEach(item => {
            $("#iast_report_items").append(rutils.bindIASTAttack(item))
        })
        $('#iast_report #vulns_count').text(result.scanResult.stats.findingsCount)
        $('#iast_report #high_count').text(result.scanResult.stats.high)
        $('#iast_report #medium_count').text(result.scanResult.stats.medium)
        $('#iast_report #low_count').text(result.scanResult.stats.low)

        $(".content.stacktrace").show()
        $('.loader.iast').hide()
    }

    // -- SAST -- //

    function generateSAST(result) {
        if (!result.scanResult?.items?.length) return
        $('#sast_report').show()

        let report = ""
        result.scanResult.items.forEach(item => {
            $("#sast_report_items").append(rutils.bindSASTAttack(item))
        })

        $('#sast_report #vulns_count').text(result.scanResult.stats.findingsCount)
        $('#sast_report #high_count').text(result.scanResult.stats.high)
        $('#sast_report #medium_count').text(result.scanResult.stats.medium)
        $('#sast_report #low_count').text(result.scanResult.stats.low)

        $(".content.stacktrace").show()
        $('.loader.sast').hide()
    }


    // -- SCA -- //

    function generateSCA(result) {
        if (!result.scanResult?.items?.length) return
        $('#sca_report').show()

        let stats = {
            findingsCount: 0,
            high: 0,
            medium: 0,
            low: 0
        }
        result.scanResult.items.forEach(item => {
            $("#sca_report_items").append(rutils.bindSCAAttack(item))
            try {
                let vulns = item[0][1][0]['vulnerabilities']
                for (let i = 0; i < vulns.length; i++) {
                    stats.findingsCount++
                    if (vulns[i].severity == 'high') stats.high++
                    if (vulns[i].severity == 'medium') stats.medium++
                    if (vulns[i].severity == 'low') stats.low++
                }
            } catch (e) { }
        })
        $('#sca_report #vulns_count').text(result.scanResult.stats.findingsCount)
        $('#sca_report #high_count').text(result.scanResult.stats.high)
        $('#sca_report #medium_count').text(result.scanResult.stats.medium)
        $('#sca_report #low_count').text(result.scanResult.stats.low)

        $('.loader.sca').hide()
    }

    // -- R-Attacker -- //

    function generateRattacker(result) {

        if (!result.scanResult?.items?.length) return


        $('#rattacker_report').show()

        let report = ""

        //result.scanResult.items.filter((item) => item.stats.high > 0)
        result.scanResult.items.filter(item => item.attacks.some(a => a.success == true && a.metadata.severity.toLowerCase() == 'high')).forEach(item => {
            for (let y in item.attacks) {
                if (item.attacks[y].success && item.attacks[y].metadata.severity == 'High')
                    $("#rattacker_content").append(bindReportItem(item.attacks[y], item.original))
            }
        })

        //result.scanResult.items.filter((item) => item.stats.medium > 0)
        result.scanResult.items.filter(item => item.attacks.some(a => a.success == true && a.metadata.severity.toLowerCase() == 'medium') ).forEach(item => {
            for (let y in item.attacks) {
                if (item.attacks[y].success && item.attacks[y].metadata.severity == 'Medium')
                    $("#rattacker_content").append(bindReportItem(item.attacks[y], item.original))
            }
        })

        //result.scanResult.items.filter((item) => item.stats.low > 0)
        result.scanResult.items.filter(item => item.attacks.some(a => a.success == true && a.metadata.severity.toLowerCase() == 'low') ).forEach(item => {
            for (let y in item.attacks) {
                if (item.attacks[y].success && item.attacks[y].metadata.severity == 'Low')
                    $("#rattacker_content").append(bindReportItem(item.attacks[y], item.original))
            }
        })

        // for (let i in result.scanResult.items) {
        //     let item = result.scanResult.items[i]
        //     for (let y in item.attacks) {
        //         if (item.attacks[y].success)
        //             $("#rattacker_content").append(bindReportItem(item.attacks[y], item.original))
        //     }
        // }
        $('#rattacker_report #attacks_count').text(result.scanResult.stats.attacksCount)
        $('#rattacker_report #vulns_count').text(result.scanResult.stats.vulnsCount)
        $('#rattacker_report #high_count').text(result.scanResult.stats.high)
        $('#rattacker_report #medium_count').text(result.scanResult.stats.medium)
        $('#rattacker_report #low_count').text(result.scanResult.stats.low)
        $('.loader.rattacker').hide()


        $(".codemirror_area").each(function (index) {
            let editor = CodeMirror.fromTextArea($(this)[0], {
                lineNumbers: false, lineWrapping: true, mode: "message/http",
                scrollbarStyle: 'native'
            })
            editor.setSize('auto', '400px')
        })
        $(".codemirror_area_html").each(function (index) {
            let editor = CodeMirror.fromTextArea($(this)[0], {
                lineNumbers: false, lineWrapping: true, mode: "text/html",
                scrollbarStyle: 'native'
            })
            editor.setSize('auto', '400px')
        })

    }


    function bindReportItem(info, original) {
        //let icon = '', proof = '', attackClass = 'nonvuln', color = ''
        let proof = '', color = ''

        let misc = rutils.getMisc(info)
        let icon = misc.icon, order = misc.order, attackClass = misc.attackClass

        if (info.proof)
            proof = `<div class="description"><p>Proof: <b><i name="proof">${ptk_utils.escapeHtml((info.proof))}</i></b></p></div>`
        //let headers = info.response.statusLine + '\n' + info.response.headers.map(x => x.name + ": " + x.value).join('\n')
        if (info.success) {

            if (info.metadata.severity == 'High') color = "red"
            if (info.metadata.severity == 'Medium') color = "orange"
            if (info.metadata.severity == 'Low') color = "yellow"

        }
        let target = original?.request?.url ? original.request.url : ""
        let request = info.request?.raw ? info.request.raw : original.request.raw
        let response = info.response?.raw ? info.response.raw : original.response?.raw ? original.response.raw : ''
        let item = `<div class="attack_info ${attackClass} ui segment">
                        <div class="ui ${color} message" style="margin-bottom: 0px;">
                            <div class="content">
                                <div class="header">
                                    ${icon}
                                    <a href="${target}" target="_blank">${target}</a>
                                </div>
                                <p>Attack: ${ptk_utils.escapeHtml(info.metadata.name)} </p>
                                ${proof}
                            </div>
                        </div>
                    <div class="two fields" >
                        <div class="one field" style="min-width: 50% !important;">
                            <textarea class="codemirror_area" style="width:100%;  border: solid 1px #cecece; padding: 1px;">${ptk_utils.escapeHtml(request)}</textarea>
                        </div>
                        <div class="one field" style="min-width: 50% !important;">
                            <textarea class="codemirror_area_html" style="width:100%;  border: solid 1px #cecece; padding: 1px;">${ptk_utils.escapeHtml(response)}</textarea>
                        </div>
                    </div></div>`

        return item
    }

    let params = new URLSearchParams(window.location.search)
    if (params.has('rattacker_report')) {
        $('#main').hide()
        $('#rattacker_report').show()
        rattacker_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateRattacker(result)
        })
    } else if (params.has('iast_report')) {
        $('#main').hide()
        $('#iast_report').show()
        iast_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateIAST(result)
        })
    } else if (params.has('sast_report')) {
        $('#main').hide()
        $('#sast_report').show()
        sast_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateSAST(result)
        })
    } else if (params.has('sca_report')) {
        $('#main').hide()
        $('#sca_report').show()
        sca_controller.init().then(function (result) {
            bindInfo(result?.scanResult?.host)
            generateSCA(result)
        })
    } else if (params.has('full_report')) {
        index_controller.get().then(() => {
            let host = new URL(index_controller.url).host
            $('#main').show()
            bindInfo(host)
            bindOWASP()
            bindWAF()
            browser.storage.local.get('tab_full_info').then(function (result) {
                index_controller.tab.technologies = result.tab_full_info.technologies
                index_controller.tab.waf = result.tab_full_info.waf
                bindTechnologies()
                bindCookies()
                browser.storage.local.remove('tab_full_info')
            })
            bindStorage()
            bindHeaders()
            rattacker_controller.init().then(function (result) {
                if (host == result?.scanResult?.host)
                    generateRattacker(result)
            })
            iast_controller.init().then(function (result) {
                if (host == result?.scanResult?.host)
                    generateIAST(result)
            })

            sast_controller.init().then(function (result) {
                if (host == result?.scanResult?.host)
                    generateSAST(result)
            })

            sca_controller.init().then(function (result) {
                if (host == result?.scanResult?.host)
                    generateSCA(result)
            })
        })
    }


})