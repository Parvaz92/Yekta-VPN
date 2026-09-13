package proxy

import (
	"net"
	"time"
)

var SystemDialer = &net.Dialer{
	Timeout: time.Second * 5,
}
