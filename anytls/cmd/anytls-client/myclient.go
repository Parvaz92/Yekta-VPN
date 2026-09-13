package main

import (
	"anytls/proxy/padding"
	"anytls/proxy/session"
	"anytls/util"
	"context"
	"encoding/binary"
	"net"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// myClient carries its OWN password hash rather than the sample's package
// global. One process serves several servers (the race/probe model), so a
// shared global would authenticate every connection against the first
// server's credentials.
type myClient struct {
	passwordSha256 []byte
	dialOut        util.DialOutFunc
	sessionClient  *session.Client
}

// NewMyClient builds the session client for one server.
func NewMyClient(ctx context.Context, passwordSha256 []byte, dialOut util.DialOutFunc, minIdleSession int, disableReuse bool) *myClient {
	s := &myClient{
		passwordSha256: passwordSha256,
		dialOut:        dialOut,
	}
	s.sessionClient = session.NewClient(ctx, s.createOutboundConnection, &padding.DefaultPaddingFactory, time.Second*30, time.Second*30, minIdleSession, disableReuse)
	return s
}

func (c *myClient) CreateProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := c.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// createOutboundConnection opens a fresh AnyTLS session: dial the server,
// wrap in TLS, then send the auth block (sha256(password) + padding).
// Protocol reference: anytls/docs/protocol.md, "客户端 / 认证".
func (c *myClient) createOutboundConnection(ctx context.Context) (net.Conn, error) {
	conn, err := c.dialOut(ctx)
	if err != nil {
		return nil, err
	}

	b := buf.NewPacket()
	defer b.Release()

	b.Write(c.passwordSha256)
	var paddingLen int
	if pad := padding.DefaultPaddingFactory.Load().GenerateRecordPayloadSizes(0); len(pad) > 0 {
		paddingLen = pad[0]
	}
	binary.BigEndian.PutUint16(b.Extend(2), uint16(paddingLen))
	if paddingLen > 0 {
		b.WriteZeroN(paddingLen)
	}

	_, err = b.WriteTo(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}
