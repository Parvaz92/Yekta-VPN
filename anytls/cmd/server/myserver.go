package main

import (
	"crypto/tls"
)

type myServer struct {
	tlsConfig *tls.Config
}

func NewMyServer(tlsConfig *tls.Config) *myServer {
	s := &myServer{
		tlsConfig: tlsConfig,
	}
	return s
}
