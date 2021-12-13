Log4Shell scanner for Burp Suite
================================

![screenshot](screenshot.png)

Detailed description can be found [in our blog post about this plugin][1].

Comparison
----------

| Feature | Log4Shell scanner (this one) | ActiveScan++ (PortSwigger/active-scan-plus-plus@b485a07) |
| --- | :---: | :---: |
| Synchronous detection | ✔️ | ✔️ |
| Asynchronous detection | ✔️ | ❌ |
| Hostname detection | ✔️ | ❌ |
| Username detection | ✔️ | ❌ |
| Ability for single-issue scan (see below) | ✔️ | ❌ |

Single-issue scan
-----------------

If you'd like to scan only for Log4j (and not other things such as XSS or SQLi),
this plugin makes it possible.

1. Create a new `Scan Configuration`
2. Expand `Issues Reported`
3. Uncheck every single one of them except the last called `Extension generated issue`
4. Disable every other extension (if applicable) that have an active scan check registered (such as ActiveScan++, Backslash powered scanning, Burp Bounty, etc.) so that only the Log4Shell scanner runs

This way the `Do active scan` context menu item will only perform Log4Shell
checks on all insertion points if the scan configuration created above is used.

Building
--------

Execute `./gradlew build` and you'll have the plugin ready in
`build/libs/burp-log4shell.jar`

License
-------

The whole project is available under the GNU General Public License v3.0,
see `LICENSE.md`.

[1]: https://blog.silentsignal.eu/2021/12/12/our-new-tool-for-enumerating-hidden-log4shell-affected-hosts/
