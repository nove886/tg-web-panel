// HTTPS origin for one allocated panel port. The WEB protocol lives upstream.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type Config struct {
	Domain       string   `json:"domain"`
	Listen       string   `json:"listen"`
	Target       string   `json:"target"`
	CertFile     string   `json:"cert_file"`
	KeyFile      string   `json:"key_file"`
	SelfSigned   bool     `json:"self_signed"`
	TrustedCIDRs []string `json:"trusted_cidrs"`
	HealthToken  string   `json:"health_token"`
}

func parsePrefixes(cidrs []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range cidrs {
		p, err := netip.ParsePrefix(s)
		if err != nil { return nil, err }
		out = append(out, p)
	}
	return out, nil
}

func isTrusted(addr netip.Addr, ranges []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, p := range ranges { if p.Contains(addr) { return true } }
	return false
}

func handler(c Config) (http.Handler, error) {
	target, err := url.Parse(c.Target)
	if err != nil || target.Scheme != "http" || target.Path != "" || target.RawQuery != "" {
		return nil, errors.New("invalid loopback target")
	}
	addr, err := netip.ParseAddr(target.Hostname())
	if err != nil || !addr.IsLoopback() || target.Port() == "" {
		return nil, errors.New("target must be numeric loopback with a port")
	}
	ranges, err := parsePrefixes(c.TrustedCIDRs)
	if err != nil { return nil, err }
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 45 * time.Second
	transport.MaxIdleConnsPerHost = 64
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = c.Domain
			// Do not normalise credential-bearing query strings.
			pr.Out.URL.RawQuery = pr.In.URL.RawQuery
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Set("X-Forwarded-For", pr.In.Header.Get("X-Panel-Client-IP"))
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
			pr.Out.Header.Del("X-Panel-Client-IP")
		},
		Transport: transport,
		FlushInterval: -1,
		ErrorLog: log.New(io.Discard, "", 0),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, _, e := net.SplitHostPort(host); e == nil { host = h }
		if host != c.Domain { http.NotFound(w, r); return }
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil { http.NotFound(w, r); return }
		peerIP, err := netip.ParseAddr(peer)
		if err != nil { http.NotFound(w, r); return }
		var clientIP netip.Addr
		if peerIP.IsLoopback() {
			clientIP = peerIP.Unmap()
		} else if isTrusted(peerIP, ranges) {
			// Only trust this header when the TCP peer is a Cloudflare address.
			values := r.Header.Values("CF-Connecting-IP")
			if len(values) != 1 { http.NotFound(w, r); return }
			clientIP, err = netip.ParseAddr(values[0])
			if err != nil { http.NotFound(w, r); return }
			clientIP = clientIP.Unmap()
		} else {
			http.NotFound(w, r); return
		}
		if r.Method == "GET" && r.URL.Path == "/.well-known/panel-check/"+c.HealthToken && r.URL.RawQuery == "" {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, c.HealthToken)
			return
		}
		r.Header.Set("X-Panel-Client-IP", clientIP.String())
		r.Body = http.MaxBytesReader(w, r.Body, 2097152)
		proxy.ServeHTTP(w, r)
	}), nil
}

func ensureCertificate(c Config) error {
	if !c.SelfSigned {
		_, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
		return err
	}
	if pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile); err == nil {
		if crt, e := x509.ParseCertificate(pair.Certificate[0]); e == nil &&
			crt.VerifyHostname(c.Domain) == nil && time.Until(crt.NotAfter) > 30*24*time.Hour {
			return nil
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { return err }
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil { return err }
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: c.Domain},
		DNSNames: []string{c.Domain}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(365*24*time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil { return err }
	priv, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil { return err }
	if err = os.MkdirAll(filepath.Dir(c.KeyFile), 0700); err != nil { return err }
	if err = os.MkdirAll(filepath.Dir(c.CertFile), 0700); err != nil { return err }
	if err = os.WriteFile(c.KeyFile, pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY", Bytes:priv}), 0600); err != nil { return err }
	return os.WriteFile(c.CertFile, pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE", Bytes:der}), 0600)
}

func main() {
	log.SetFlags(log.LstdFlags)
	if len(os.Args) != 2 { log.Fatal("usage: panel-front config.json") }
	data, err := os.ReadFile(os.Args[1]); if err != nil { log.Fatal(err) }
	var c Config
	if err = json.Unmarshal(data, &c); err != nil { log.Fatal(err) }
	h, err := handler(c); if err != nil { log.Fatal(err) }
	if err = ensureCertificate(c); err != nil { log.Fatal(err) }
	server := &http.Server{
		Addr: c.Listen, Handler: h, ReadHeaderTimeout: 10*time.Second,
		ReadTimeout: 90*time.Second, IdleTimeout: 90*time.Second,
		MaxHeaderBytes: 16384,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog: log.New(io.Discard, "", 0),
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	fmt.Printf("HTTPS origin listening on %s; public entry still needs verification\n", c.Listen)
	if err = server.ListenAndServeTLS(c.CertFile, c.KeyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
