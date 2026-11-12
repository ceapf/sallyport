// Command verify checks a server certificate chain the way a Go TLS client does, with
// crypto/x509 (RT-SEC-10, Task 9a-2, architect Q46).
//
// Usage: verify <ca.pem> <chain.pem> <name>
//
// ca.pem holds the only trust anchor; chain.pem holds the leaf first, then any intermediates;
// name is a DNS name or an IP address. Exit 0: verified; 1: refused (the reason on stderr);
// 2: usage or input error. Standard library only; built and run offline
// (GOTOOLCHAIN=local GOPROXY=off GOTELEMETRY=off).
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func certs(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no certificate", path)
	}
	return out, nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: verify <ca.pem> <chain.pem> <name>")
		os.Exit(2)
	}
	cas, err := certs(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	chain, err := certs(os.Args[2])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	roots := x509.NewCertPool()
	for _, c := range cas {
		roots.AddCert(c)
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	_, err = chain[0].Verify(x509.VerifyOptions{
		DNSName:       os.Args[3],
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
