# TUN proxy and path MTU

## Packet path

```
OS / Android VpnService TUN (default MTU 9000)
    -> local gVisor TCP/UDP endpoints
    -> stream / datagram relay
    -> outbound gVisor endpoints with WARP-assigned addresses
    -> CONNECT-IP -> QUIC/HTTP3 -> WARP
```

Native and Android entry points use `api.MaintainTUN`. SOCKS, HTTP proxy and
port-forwarding already originate connections in a user-space stack and retain
their stack-to-CONNECT-IP path. Native TUN traffic has no transparent-forwarding
fallback. The TUN proxy handles outgoing TCP, UDP and ICMP echo; it is not a
general-purpose IP router (unsolicited inbound connections and other IP
protocols are not forwarded).

The local TUN MTU and the inner IP packet budget of the WARP tunnel are different
settings. Existing explicit `inbound.settings.mtu` values are honored. Missing
or zero TUN MTUs default to 9000; allowed values are 1280–65535. Packet read
buffers accommodate the full local MTU instead of truncating packets to the
current tunnel budget. A larger buffer alone does not batch TUN reads.

## TCP

The local connection ends in gVisor. Its outbound peer is a separate TCP socket
in a second gVisor stack; it never dials a host TCP socket. A tunnel budget
decrease updates that stack's link MTU **and notifies existing TCP endpoints**,
allowing queued data to be resegmented and retransmitted. Local application
segments can therefore be much larger than packets on the tunnel.

The receive MSS advertised on the tunnel side is conservatively bounded by an
1120-byte inner IP packet, including IP/TCP headers. This fits the minimum QUIC
packet budget with WARP's 20-byte connection IDs and leaves room for framing.
It avoids negotiating large remote TCP segments that cannot be renegotiated
after an outer-path shrink. Sending can use the larger measured budget.

## Datagram semantics

UDP payloads are not split into independent UDP messages. Oversized local
UDP and echo requests receive IPv4 Fragmentation Needed or IPv6 Packet Too Big
with the original local addresses/ports quoted. This works for established
flows too; a jumbo TUN must not turn oversized UDP into a silent tunnel drop.
IPv6 feedback never advertises a link MTU below 1280.

The egress stack handles IP reassembly and source fragmentation. Its IPv6 NIC
must remain at least 1280; originated packets can be source-fragmented to a
smaller wire budget. This does **not** imply arbitrary WARP peers accept
fragments. In local live testing, 900-byte echoes worked but 2700-byte echoes
through WARP timed out, while direct fragmented ping worked. Thus the default
proxy returns explicit MTU feedback for oversized datagrams instead of relying
on fragmentation. A path with too little space for an application's minimum
datagram still needs a transport that can carry it (e.g. configured HTTP/2);
gVisor cannot remove that constraint.

## Discovery

* The pinned `apernet/quic-go` returns inconsistent units in its local
  `DatagramTooLargeError` estimate: initially payload bytes, later a QUIC packet
  budget. A size rejected locally is not evidence of delivery. The conservative
  fallback accounts for a maximum short header, AEAD and DATAGRAM framing
  (44 bytes), plus the actual HTTP stream-ID and CONNECT-IP context-ID lengths.
* `Conn.ProbePathMTU` sends real IPv4 DF / IPv6 echo packets inside the existing
  CONNECT-IP session. It matches source/destination, random cookie, sequence and
  full reply length. Probes are consumed by the normal receive pump and cannot
  steal application replies. There are no raw sockets, subprocess pings or
  extra physical routes, including on Android.
* A size search retries lost probes, verifies a small control packet, and
  binary-searches for an echoed size. Failure of the control echo means
  **unknown**, not a successful minimum MTU. Cancellation/failure retains the
  last good measurement. Searches bypass the cached IP limit so a previously
  lowered budget can recover.
* Runtime discovery first confirms a useful baseline up to 1280, then searches
  higher during warmup. It checks the working size every 30 seconds, tries
  growth every five minutes and restarts discovery after reconnect. The local
  QUIC bound can further limit the verified budget.
* `outbound.settings.pmtu_target` optionally selects an inner echo responder IP.
  Empty chooses `1.1.1.1`, or `2606:4700:4700::1111` for IPv6-only TUNs. `"off"`
  disables wire probes while keeping conservative local bounds. A measurement
  includes the route to that responder and its return path; it is not a promise
  about every destination on the Internet. Destination ICMP errors are delivered
  to the outbound stack for per-flow handling.

## Reproduce

```sh
go build -o usque .
./usque register --accept-tos -c config.test.json
./usque pmtu -c config.test.json --max 1500
./usque pmtu -c config.test.json --target 2606:4700:4700::1111
go test -race ./...
(cd connect-ip && go test -race ./...)
USQUE_E2E_CONFIG="$PWD/config.test.json" go test -tags e2e \
  -run '^TestE2E_GVisorTUN$' -v -count=1 -timeout 120s ./api
```

Configuration credentials are ignored by Git. Live tests are opt-in and use an
already registered account. They check both inner IP families: UDP DNS, HTTPS
with `warp=on`/`warp=plus`, ICMP echo and HTTP/3 carried by proxied UDP.
The local integration test uses real gVisor stacks at both ends, a 9000-byte
local link, and a 1400 -> 1150-byte tunnel-budget decrease on the same TCP
connection. It also checks datagram boundaries and original-flow MTU feedback.

On the development host, direct outer-path probes to WARP passed at 1500 IP
bytes and failed at 1501. Native TUN discovery converged to **1397 inner IP
bytes**. With local MTU 9000, IPv4/IPv6 pings and a 56,614-byte HTTPS download
worked; a 2728-byte IPv4 echo request received ICMP reporting MTU 1397. These
are measurements of that host/path, not hard-coded WARP MTUs or throughput
benchmarks.

## Windows validation

Place the official architecture-matched [Wintun DLL](https://www.wintun.net/)
next to `usque.exe`. Start from a local or VM console, not a remote session
that depends on the default route.

1. Run `.\usque.exe pmtu -c config.json --max 1500` before creating a TUN.
2. Use `inbound.type: "tun"` and `inbound.settings.auto_route: true`, then run
   `.\usque.exe run -c config.json` from elevated PowerShell.
3. Check `Get-NetIPInterface -InterfaceAlias usque | Format-Table AddressFamily,NlMtu`.
   Enabled families should show the configured local MTU (9000 in new configs).
   The wire MTU in the log is independent and must not change `NlMtu`.
4. Run `curl.exe https://cloudflare.com/cdn-cgi/trace` and check for `warp=on`
   or `warp=plus`. To test the IPv6 **outer** transport, use a network with
   IPv6 and set `outbound.settings.use_ipv6` to `true`. Inner IPv6 is separate:
   test it with `pmtu --target 2606:4700:4700::1111`.
5. Press Ctrl+C and verify that the Wintun adapter and routes created by
   usque disappear. Any pre-existing host route should remain. Egress is
   reselected on reconnect, not migrated on a live bound QUIC socket.

Automatic endpoint binding covers QUIC and direct HTTP/2. Single-stack TUN
configs require direct HTTP/2 (no environment proxy), so the firewall exception
is limited to the actual WARP endpoint.

Windows CI tests route selection and socket binding, plus Wintun shutdown
with native event handles and a test ring. To exercise the actual driver
without changing default routes, run from elevated PowerShell with
`wintun.dll` next to the test executable:

```powershell
go test -c -o .\usque-wintun.test.exe ./cmd
$env:USQUE_TEST_WINTUN = '1'
.\usque-wintun.test.exe -test.run '^TestWintunDriverSmoke$' -test.v
```

### Verify IPv6-only TUN does not leak IPv4

Set `inbound.settings.ipv4` to `false` and `ipv6` to `true`. Windows installs
the dynamic WFP family guard before opening the TUN. It blocks non-loopback
IPv4, including IPv4-mapped Winsock sockets and packets using a more specific
physical-interface route. There is no placeholder IPv4 address or default
IPv4 route on Wintun. Failure to install the guard is a startup error, not a
warning. This also applies with `auto_route: false` and across reconnects.

- With `outbound.settings.use_ipv6: true` and a working IPv6 uplink, there is
  no IPv4 WARP exception.
- If the WARP underlay is IPv4, only the usque executable's traffic to the
  configured IPv4 endpoint, port and protocol is allowed. Ordinary IPv4 and
  IPv4 DHCP traffic remain blocked; a long session may lose an IPv4 DHCP lease.
- Local loopback still works. The guard is removed after shutdown or when
  Windows closes the process's dynamic WFP session. It does not disable an
  address family permanently or guarantee that the *enabled* family is routed
  through Wintun when automatic routing is disabled.

From a local Windows console, establish an IPv4 baseline before starting usque.
Then repeat while the IPv6-only TUN is active. Both IPv4 commands below should
fail; binding `curl.exe` to the physical IPv4 source address should also fail.
With auto-route on, IPv6 HTTPS should still report `warp=on` or `warp=plus`:

```powershell
ping.exe -4 1.1.1.1
curl.exe -4 --noproxy '*' --connect-timeout 4 --resolve 'one.one.one.one:443:1.1.1.1' 'https://one.one.one.one/cdn-cgi/trace'
curl.exe -6 --noproxy '*' --connect-timeout 4 --resolve 'one.one.one.one:443:[2606:4700:4700::1111]' 'https://one.one.one.one/cdn-cgi/trace'
```

The opt-in `TestWindowsFamilyGuardWFP` checks real WFP installation, blocked
source-bound IPv4 TCP, the exact endpoint exception (including denial for a
different executable), loopback and cleanup.
Run it elevated in a disposable Windows VM with
`USQUE_TEST_WFP_PEER` set to a reachable IPv4 TCP `IP:port`.
