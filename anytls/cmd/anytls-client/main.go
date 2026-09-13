package main

import (
	"anytls/util"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

// Sidecar client for the AnyTLS protocol, purpose-built for MSN-GUARD's
// SHARD transport. It is a hardened rewrite of anytls-go's sample
// cmd/client, not the sample itself:
//
//   - TLS verification is REAL. The sample hardcodes
//     InsecureSkipVerify: true, which makes every node MITM-able by the
//     carrier — the exact threat this transport exists to defeat. On
//     Android, Go loads the system trust store from
//     /system/etc/security/cacerts automatically, so verification works
//     against real certificates. Insecure remains available per node only
//     because free anytls nodes routinely ship self-signed certificates
//     (insecure=1 in the URI); it is opt-in from the node's own URL,
//     never a default.
//   - One process can serve N servers on N listeners (the probe/race
//     model this app already uses for its other engine: bind one
//     inbound per candidate, so a request sent to a given port can only
//     leave through that port's node — that is what makes a race
//     attributable).
//   - A -c config file replaces -s/-p flag pairs, so credentials never
//     appear in `ps` output during node rotation.
//   - No key log writer: a shipped client must never be one flag away
//     from dumping its own session keys.
//
// SNI/cert-name rule (matches the URI spec, docs/uri_scheme.md): the
// certificate is verified against the SNI param when given, else against
// the server host. Go sends no SNI for IP-literal names and verifies
// against IP SANs instead — both correct — so no special case is needed
// for either shape.

// ServerEntry is one anytls node plus the loopback listener it serves.
type ServerEntry struct {
	Listen   string `json:"listen"`
	Server   string `json:"server"`
	Password string `json:"password"`
	SNI      string `json:"sni"`
	Insecure bool   `json:"insecure"`
	MinIdle  int    `json:"min_idle_session"`
}

// Config is the whole process. The app writes it as a JSON file.
type Config struct {
	LogLevel   string        `json:"log_level"`
	HTTPListen string        `json:"http_listen"`
	Servers    []ServerEntry `json:"servers"`
}

func main() {
	configPath := flag.String("c", "", "config file (json; required for multi-server mode)")
	listen := flag.String("l", "", "socks5 listen address (single-server mode)")
	serverArg := flag.String("s", "", "server address or anytls:// link (single-server mode)")
	password := flag.String("p", "", "password (single-server mode)")
	minIdle := flag.Int("m", 5, "reserved minimum idle sessions per server")
	flag.Parse()

	cfg := Config{}
	if *configPath != "" {
		b, err := os.ReadFile(*configPath)
		if err != nil {
			logrus.Fatalln("read config:", err)
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			logrus.Fatalln("parse config:", err)
		}
	} else {
		// Single-server mode, for manual testing: -s accepts both a bare
		// host:port and the anytls:// URI form.
		entry := ServerEntry{MinIdle: *minIdle}
		if *serverArg == "" {
			logrus.Fatalln("no config file and no -s server")
		}
		if serverURL, err := url.Parse(*serverArg); err == nil && serverURL.Scheme == "anytls" {
			entry.Server = serverURL.Host
			if serverURL.User != nil {
				entry.Password = serverURL.User.String()
			}
			q := serverURL.Query()
			entry.SNI = q.Get("sni")
			entry.Insecure = q.Get("insecure") == "1" || q.Get("insecure") == "true"
		} else {
			entry.Server = *serverArg
		}
		if *password != "" {
			entry.Password = *password
		}
		if *listen != "" {
			entry.Listen = *listen
		} else {
			entry.Listen = "127.0.0.1:1080"
		}
		cfg.Servers = append(cfg.Servers, entry)
	}

	if len(cfg.Servers) == 0 {
		logrus.Fatalln("no servers configured")
	}
	for i, s := range cfg.Servers {
		if s.Server == "" {
			logrus.Fatalf("server %d: no address", i)
		}
		if s.Password == "" {
			logrus.Fatalf("server %d: no password", i)
		}
		if _, _, err := net.SplitHostPort(s.Server); err != nil {
			logrus.Fatalf("server %d: bad address %q: %v", i, s.Server, err)
		}
		if s.Listen == "" {
			logrus.Fatalf("server %d: no listen address", i)
		}
		if _, _, err := net.SplitHostPort(s.Listen); err != nil {
			logrus.Fatalf("server %d: bad listen %q: %v", i, s.Listen, err)
		}
	}

	logLevel, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logLevel = logrus.InfoLevel
	}
	logrus.SetLevel(logLevel)

	logrus.Infoln("[Client]", util.ProgramVersionName)

	ctx := context.Background()
	for _, s := range cfg.Servers {
		if err := serveServer(ctx, s); err != nil {
			logrus.Fatalln("serve:", err)
		}
	}

	// Optional HTTP CONNECT front end, bound only when the app asks for it
	// (LAN sharing). The SOCKS/HTTP auto-detection below is the sample
	// client's proven front end, so the second listener costs nothing.
	if cfg.HTTPListen != "" {
		if err := serveServer(ctx, ServerEntry{
			Listen:   cfg.HTTPListen,
			Server:   cfg.Servers[0].Server,
			Password: cfg.Servers[0].Password,
			SNI:      cfg.Servers[0].SNI,
			Insecure: cfg.Servers[0].Insecure,
			MinIdle:  cfg.Servers[0].MinIdle,
		}); err != nil {
			logrus.Fatalln("serve http:", err)
		}
	}

	logrus.Infoln("[Client] started")
	select {}
}

// serveServer binds one listener and hands every connection to the shared
// SOCKS/HTTP front end, backed by its own AnyTLS session client.
func serveServer(ctx context.Context, s ServerEntry) error {
	sum := sha256.Sum256([]byte(s.Password))

	// The verification name: the SNI param if the node gave one, else the
	// server host. See the SNI/cert-name rule in the file comment.
	verifyName := s.SNI
	if verifyName == "" {
		verifyName = hostOf(s.Server)
	}
	tlsConfig := &tls.Config{
		ServerName:         verifyName,
		InsecureSkipVerify: s.Insecure, // opt-in per node; see file comment
		MinVersion:         tls.VersionTLS12,
	}

	client := NewMyClient(ctx, sum[:], func(ctx context.Context) (net.Conn, error) {
		d := net.Dialer{Timeout: 15 * time.Second}
		conn, err := d.DialContext(ctx, "tcp", s.Server)
		if err != nil {
			return nil, err
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetNoDelay(true)
		}
		return tls.Client(conn, tlsConfig), nil
	}, s.MinIdle, false)

	listener, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.Listen, err)
	}
	logrus.Infoln("[Client] socks5/http", s.Listen, "=>", s.Server)

	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				logrus.Fatalln("accept:", err)
			}
			go handleTcpConnection(ctx, c, client)
		}
	}()
	return nil
}

// hostOf strips the port, keeping IPv6 brackets.
func hostOf(server string) string {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return server
	}
	return host
}
