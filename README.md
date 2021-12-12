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

Building
--------

Execute `./gradlew build` and you'll have the plugin ready in
`build/libs/burp-log4shell.jar`

License
-------

The whole project is available under the GNU General Public License v3.0,
see `LICENSE.md`.

[1]: https://blog.silentsignal.eu/2021/12/12/our-new-tool-for-enumerating-hidden-log4shell-affected-hosts/
