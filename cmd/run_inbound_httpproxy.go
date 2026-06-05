package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func runHTTPProxyInbound(ctx context.Context, fc *config.FullConfig, ob *outboundBundle) error {
	settings, err := fc.ParseHTTPProxySettings()
	if err != nil {
		return err
	}

	if settings.MTU != 1280 {
		log.Println("Warning: MTU is not the default 1280. Packet loss and other issues may occur.")
	}

	var localAddresses []netip.Addr
	v4, err := netip.ParseAddr(fc.Account.IPv4)
	if err == nil {
		localAddresses = append(localAddresses, v4)
	}
	v6, err := netip.ParseAddr(fc.Account.IPv6)
	if err == nil {
		localAddresses = append(localAddresses, v6)
	}

	var dnsAddrs []netip.Addr
	for _, dns := range settings.DNS {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return err
		}
		dnsAddrs = append(dnsAddrs, addr)
	}

	dnsTimeout := config.ParseDuration(settings.DNSTimeout, 2*time.Second)

	hookEnv := map[string]string{
		"USQUE_MODE": "http-proxy",
		"USQUE_IPV4": fc.Account.IPv4,
		"USQUE_IPV6": fc.Account.IPv6,
	}

	var authHeader string
	if settings.Username != "" && settings.Password != "" {
		authHeader = "Basic " + internal.LoginToBase64(settings.Username, settings.Password)
	}

	tunDev, tunNet, err := netstack.CreateNetTUN(localAddresses, dnsAddrs, settings.MTU)
	if err != nil {
		return err
	}
	defer func() { _ = tunDev.Close() }()

	resolver := internal.GetProxyResolver(settings.LocalDNS, settings.SystemDNS, tunNet, dnsAddrs, dnsTimeout)

	ob.maintainCfg.Device = api.NewNetstackAdapter(tunDev)
	ob.maintainCfg.MTU = settings.MTU
	ob.maintainCfg.HookEnv = hookEnv

	go api.MaintainTunnel(ctx, ob.maintainCfg)

	server := &http.Server{
		Addr: settings.Listen,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authHeader != "" && r.Header.Get("Proxy-Authorization") != authHeader {
				w.Header().Set("Proxy-Authenticate", `Basic realm="Proxy"`)
				http.Error(w, "Proxy authentication required", http.StatusProxyAuthRequired)
				return
			}
			if r.Method == http.MethodConnect {
				handleHTTPSConnect(w, r, tunNet, resolver)
			} else {
				handleHTTPProxy(w, r, tunNet, resolver)
			}
		}),
	}

	log.Printf("HTTP proxy listening on %s", settings.Listen)
	return server.ListenAndServe()
}

func handleHTTPSConnect(w http.ResponseWriter, r *http.Request, tunNet *netstack.Net, resolver *net.Resolver) {
	ctx := r.Context()
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "Invalid host", http.StatusBadRequest)
		return
	}

	var destAddr string
	if resolver != nil {
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			http.Error(w, "DNS resolution failed", http.StatusServiceUnavailable)
			return
		}
		destAddr = net.JoinHostPort(ips[0].String(), port)
	} else {
		destAddr = r.Host
	}

	destConn, err := tunNet.DialContext(ctx, "tcp", destAddr)
	if err != nil {
		http.Error(w, "Unable to connect to destination", http.StatusServiceUnavailable)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		_ = destConn.Close()
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed", http.StatusInternalServerError)
		_ = destConn.Close()
		return
	}

	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go func() {
		defer func() { _ = destConn.Close() }()
		defer func() { _ = clientConn.Close() }()
		_, _ = io.Copy(destConn, clientConn)
	}()
	_, _ = io.Copy(clientConn, destConn)
}

func handleHTTPProxy(w http.ResponseWriter, r *http.Request, tunNet *netstack.Net, resolver *net.Resolver) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address: %w", err)
				}
				var dialAddr string
				if resolver != nil {
					ips, err := resolver.LookupIP(ctx, "ip", host)
					if err != nil || len(ips) == 0 {
						return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, err)
					}
					dialAddr = net.JoinHostPort(ips[0].String(), port)
				} else {
					dialAddr = addr
				}
				return tunNet.DialContext(ctx, network, dialAddr)
			},
		},
	}

	req, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	req.Header = r.Header.Clone()

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Failed to reach destination", http.StatusServiceUnavailable)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
