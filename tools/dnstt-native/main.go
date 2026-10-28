package main

import (
	dnsttclient "www.bamsoftware.com/git/dnstt.git/dnstt-client/lib"
)

// DNSTT is built as an executable PT, like libobfs4proxy.so. Keeping it as a
// process avoids loading a second Go runtime beside Psiphon's libgojni.so.
func main() {
	dnsttclient.Start("127.0.0.1:0", nil)
}
