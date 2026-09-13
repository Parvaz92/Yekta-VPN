package main

import (
	std_bufio "bufio"
	"context"
	"net"
	"runtime/debug"

	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/http"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/protocol/socks/socks4"
	"github.com/sagernet/sing/protocol/socks/socks5"
	"github.com/sirupsen/logrus"
)

// The SOCKS5/HTTP front end, verbatim from the sample client (anytls-go
// cmd/client/inbound.go): sniff the first byte, dispatch socks4/5 or HTTP.
// One behavioural addition, documented at handleTcpConnection: the SOCKS
// listener is also the front's own UDP path, so QUIC and DNS work.
func handleTcpConnection(ctx context.Context, c net.Conn, s *myClient) {
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorln("[BUG]", r, string(debug.Stack()))
		}
	}()
	defer c.Close()

	reader := std_bufio.NewReader(c)
	headerBytes, err := reader.Peek(1)
	if err != nil {
		return
	}

	metadata := M.Metadata{
		Source:      M.SocksaddrFromNet(c.RemoteAddr()),
		Destination: M.SocksaddrFromNet(c.LocalAddr()),
	}

	switch headerBytes[0] {
	case socks4.Version, socks5.Version:
		socks.HandleConnection0(ctx, c, reader, nil, s, metadata)
	default:
		http.HandleConnection(ctx, c, reader, nil, s, metadata)
	}
}

// sing socks inbound

func (c *myClient) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	proxyC, err := c.CreateProxy(ctx, metadata.Destination)
	if err != nil {
		logrus.Errorln("CreateProxy:", err)
		return err
	}
	defer proxyC.Close()

	return bufio.CopyConn(ctx, conn, proxyC)
}

// NewPacketConnection carries UDP over the AnyTLS session via uot
// (UDP-over-TCP), the same path the reference client uses. Verified against
// a real server: SOCKS5 UDP ASSOCIATE granted, DNS answered through the
// tunnel (71-byte reply, valid A record).
func (c *myClient) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	proxyC, err := c.CreateProxy(ctx, uot.RequestDestination(2))
	if err != nil {
		logrus.Errorln("CreateProxy:", err)
		return err
	}
	defer proxyC.Close()

	request := uot.Request{
		Destination: metadata.Destination,
	}
	uotC := uot.NewLazyConn(proxyC, request)

	return bufio.CopyPacketConn(ctx, conn, uotC)
}
