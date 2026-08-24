package connectip

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

type CloseError struct {
	Remote bool
}

func (e *CloseError) Error() string        { return net.ErrClosed.Error() }
func (e *CloseError) Is(target error) bool { return target == net.ErrClosed }

type appendable interface{ append([]byte) []byte }

type writeCapsule struct {
	capsule appendable
	result  chan error
}

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

type http3Stream interface {
	io.ReadWriteCloser
	ReceiveDatagram(context.Context) ([]byte, error)
	SendDatagram([]byte) error
	CancelRead(quic.StreamErrorCode)
}

var (
	_ http3Stream = &http3.Stream{}
	_ http3Stream = &http3.RequestStream{}
)

const (
	datagramSizeProbe = 2048
	// quic-go reports its initial estimate as a datagram payload, but reports
	// acknowledged PMTU probes as the outer QUIC packet size. Keep the larger
	// outer-packet overhead separate from the HTTP/3 and CONNECT-IP framing.
	quicDatagramOverhead = 40
	// QUIC's minimum InitialPacketSize is 1200. This is the conservative raw
	// payload bound used until a PMTU observation has been confirmed.
	conservativeInitialDatagramPayload = 1200
	// A higher limit is only adopted after two refreshes. quic-go already
	// validates increases with acknowledged PMTU probes, but keeping this small
	// hysteresis here prevents an out-of-order observation from expanding the
	// IP-side limit for a single refresh interval.
	pmtuIncreaseConfirmations = 2
)

var datagramProbePayload = make([]byte, datagramSizeProbe)

// Conn is a connection that proxies IP packets over HTTP/3.
type Conn struct {
	str    http3Stream
	writes chan writeCapsule

	supportsControlCapsules bool

	assignedAddressNotify chan struct{}
	availableRoutesNotify chan struct{}

	mu                sync.Mutex
	peerAddresses     []netip.Prefix // IP prefixes that we assigned to the peer
	localRoutes       []IPRoute      // IP routes that we advertised to the peer
	assignedAddresses []netip.Prefix
	availableRoutes   []IPRoute

	usesQUICDatagrams    bool
	httpDatagramOverhead int
	maxDatagramPayload   atomic.Int64
	pmtuMu               sync.Mutex
	pmtuIncrease         int64
	pmtuIncreaseCount    int

	closeChan chan struct{}
	closeErr  error
}

func newProxiedConn(str http3Stream) *Conn {
	c := newConn(str, true)
	c.usesQUICDatagrams = true
	// HTTP/3 prepends the quarter stream ID before passing the payload to
	// QUIC. Request streams expose their stream ID, so account for its exact
	// varint length instead of assuming this is always the first stream.
	c.httpDatagramOverhead = quicvarint.Len(0)
	if s, ok := str.(interface{ StreamID() quic.StreamID }); ok {
		c.httpDatagramOverhead = quicvarint.Len(uint64(s.StreamID() / 4))
	}
	c.maxDatagramPayload.Store(conservativeInitialDatagramPayload)
	return c
}

func newDatagramOnlyConn(str http3Stream) *Conn {
	return newConn(str, false)
}

func newConn(str http3Stream, supportsControlCapsules bool) *Conn {
	c := &Conn{
		str:                     str,
		writes:                  make(chan writeCapsule),
		supportsControlCapsules: supportsControlCapsules,
		assignedAddressNotify:   make(chan struct{}, 1),
		availableRoutesNotify:   make(chan struct{}, 1),
		closeChan:               make(chan struct{}),
	}
	if supportsControlCapsules {
		go func() {
			if err := c.readFromStream(); err != nil {
				log.Printf("handling stream failed: %v", err)
				c.mu.Lock()
				if c.closeErr == nil {
					c.closeErr = &CloseError{Remote: true}
					close(c.closeChan)
				}
				c.mu.Unlock()
			}
		}()
		go func() {
			if err := c.writeToStream(); err != nil {
				log.Printf("writing to stream failed: %v", err)
				c.mu.Lock()
				if c.closeErr == nil {
					c.closeErr = &CloseError{Remote: true}
					close(c.closeChan)
				}
				c.mu.Unlock()
			}
		}()
	}
	return c
}

// AdvertiseRoute informs the peer about available routes.
// This function can be called multiple times, but only the routes from the most recent call will be active.
// Previous route advertisements are overwritten by each new call to this function.
func (c *Conn) AdvertiseRoute(ctx context.Context, routes []IPRoute) error {
	for _, route := range routes {
		if route.StartIP.Compare(route.EndIP) == 1 {
			return fmt.Errorf("invalid route advertising start_ip: %s larger than %s", route.StartIP, route.EndIP)
		}
	}
	c.mu.Lock()
	c.localRoutes = slices.Clone(routes)
	c.mu.Unlock()
	return c.sendCapsule(ctx, &routeAdvertisementCapsule{IPAddressRanges: routes})
}

// AssignAddresses assigned address prefixes to the peer.
// This function can be called multiple times, but only the addresses from the most recent call will be active.
// Previous address assignments are overwritten by each new call to this function.
func (c *Conn) AssignAddresses(ctx context.Context, prefixes []netip.Prefix) error {
	c.mu.Lock()
	c.peerAddresses = slices.Clone(prefixes)
	c.mu.Unlock()
	capsule := &addressAssignCapsule{AssignedAddresses: make([]AssignedAddress, 0, len(prefixes))}
	for _, p := range prefixes {
		capsule.AssignedAddresses = append(capsule.AssignedAddresses, AssignedAddress{IPPrefix: p})
	}
	return c.sendCapsule(ctx, capsule)
}

func (c *Conn) sendCapsule(ctx context.Context, capsule appendable) error {
	if !c.supportsControlCapsules {
		return errors.New("connect-ip: control capsules are not supported by this transport")
	}

	res := make(chan error, 1)
	select {
	case c.writes <- writeCapsule{
		capsule: capsule,
		result:  res,
	}:
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-res:
			return err
		}
	case <-c.closeChan:
		return c.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// LocalPrefixes returns the prefixes that the peer currently assigned.
// Note that at any point during the connection, the peer can change the assignment.
// It is therefore recommended to call this function in a loop.
func (c *Conn) LocalPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case <-c.assignedAddressNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.assignedAddresses, nil
	}
}

// Routes returns the routes that the peer currently advertised.
// Note that at any point during the connection, the peer can change the advertised routes.
// It is therefore recommended to call this function in a loop.
func (c *Conn) Routes(ctx context.Context) ([]IPRoute, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closeChan:
		return nil, c.closeErr
	case <-c.availableRoutesNotify:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.availableRoutes, nil
	}
}

func (c *Conn) readFromStream() error {
	defer c.str.Close()
	r := quicvarint.NewReader(c.str)
	for {
		t, cr, err := http3.ParseCapsule(r)
		if err != nil {
			return err
		}
		switch t {
		case capsuleTypeAddressAssign:
			capsule, err := parseAddressAssignCapsule(cr)
			if err != nil {
				return err
			}
			prefixes := make([]netip.Prefix, 0, len(capsule.AssignedAddresses))
			for _, assigned := range capsule.AssignedAddresses {
				prefixes = append(prefixes, assigned.IPPrefix)
			}
			c.mu.Lock()
			c.assignedAddresses = prefixes
			c.mu.Unlock()
			select {
			case c.assignedAddressNotify <- struct{}{}:
			default:
			}
		case capsuleTypeAddressRequest:
			if _, err := parseAddressRequestCapsule(cr); err != nil {
				return err
			}
			return errors.New("connect-ip: address request not yet supported")
		case capsuleTypeRouteAdvertisement:
			capsule, err := parseRouteAdvertisementCapsule(cr)
			if err != nil {
				return err
			}
			c.mu.Lock()
			c.availableRoutes = capsule.IPAddressRanges
			c.mu.Unlock()
			select {
			case c.availableRoutesNotify <- struct{}{}:
			default:
			}
		default:
			return fmt.Errorf("unknown capsule type: %d", t)
		}
	}
}

func (c *Conn) writeToStream() error {
	buf := make([]byte, 0, 1024)
	for {
		select {
		case <-c.closeChan:
			return c.closeErr
		case req, ok := <-c.writes:
			if !ok {
				return nil
			}
			buf = req.capsule.append(buf[:0])
			_, err := c.str.Write(buf)
			req.result <- err
			if err != nil {
				return err
			}
		}
	}
}

func (c *Conn) ReadPacket(b []byte, allowAny bool) (n int, err error) {
start:
	data, err := c.str.ReceiveDatagram(context.Background())
	if err != nil {
		select {
		case <-c.closeChan:
			return 0, c.closeErr
		default:
			return 0, err
		}
	}
	contextID, n, err := quicvarint.Parse(data)
	if err != nil {
		// TODO: close connection
		return 0, fmt.Errorf("connect-ip: malformed datagram: %w", err)
	}
	if contextID != 0 {
		// Drop this datagram. We currently only support proxying of IP payloads.
		goto start
	}
	if err := c.handleIncomingProxiedPacket(data[n:], allowAny); err != nil {
		log.Printf("dropping proxied packet: %s", err)
		goto start
	}
	return copy(b, data[n:]), nil
}

func (c *Conn) handleIncomingProxiedPacket(data []byte, allowAny bool) error {
	if len(data) == 0 {
		return errors.New("connect-ip: empty packet")
	}
	var src, dst netip.Addr
	var ipProto uint8
	switch v := ipVersion(data); v {
	default:
		return fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(data) < ipv4.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom4([4]byte(data[12:16]))
		dst = netip.AddrFrom4([4]byte(data[16:20]))
		ipProto = data[9]
	case 6:
		if len(data) < ipv6.HeaderLen {
			return fmt.Errorf("connect-ip: malformed datagram: too short")
		}
		src = netip.AddrFrom16([16]byte(data[8:24]))
		dst = netip.AddrFrom16([16]byte(data[24:40]))
		ipProto = data[6]
	}

	c.mu.Lock()
	assignedAddresses := c.assignedAddresses
	localRoutes := c.localRoutes
	peerAddresses := c.peerAddresses
	c.mu.Unlock()

	// We don't necessarily assign any addresses to the peer.
	// For example, in the Remote Access VPN use case (RFC 9484, section 8.1),
	// the client accepts incoming traffic from all IPs.
	if peerAddresses != nil {
		if !slices.ContainsFunc(peerAddresses, func(p netip.Prefix) bool { return p.Contains(src) }) {
			// TODO: send ICMP
			return fmt.Errorf("connect-ip: datagram source address not allowed: %s", src)
		}
	}

	// The destination IP address is valid if it
	// 1. is within one of the ranges assigned to us, or
	// 2. is within one of the ranges that we advertised to the peer.
	var isAllowedDst bool

	if allowAny {
		isAllowedDst = true
	}

	if len(assignedAddresses) > 0 {
		isAllowedDst = slices.ContainsFunc(assignedAddresses, func(p netip.Prefix) bool { return p.Contains(dst) })
	}
	if !isAllowedDst {
		isAllowedDst = slices.ContainsFunc(localRoutes, func(r IPRoute) bool {
			if r.StartIP.Compare(dst) > 0 || dst.Compare(r.EndIP) > 0 {
				return false
			}
			// ICMP is always allowed
			if (ipVersion(data) == 4 && ipProto == ipProtoICMP) || (ipVersion(data) == 6 && ipProto == ipProtoICMPv6) {
				return true
			}
			// TODO: walk the chain of IPv6 extensions
			// See section 4.8 of RFC 9484 for details.
			return r.IPProtocol == 0 || r.IPProtocol == ipProto
		})
	}
	if !isAllowedDst {
		// TODO: send ICMP
		return fmt.Errorf("connect-ip: datagram destination address / protocol not allowed: %s (protocol: %d)", dst, ipProto)
	}
	return nil
}

// WritePacket writes an IP packet to the stream.
// If sending the packet fails, it might return an ICMP packet.
// It is the caller's responsibility to send the ICMP packet to the sender.
func (c *Conn) WritePacket(b []byte) (icmp []byte, err error) {
	if maxPayload := c.maxDatagramPayload.Load(); maxPayload > 0 && len(b) > c.effectiveMTUForPayload(maxPayload) {
		return c.composeTooLargePacket(b, maxPayload)
	}

	data, err := c.composeDatagram(b)
	if err != nil {
		log.Printf("dropping proxied packet (%d bytes) that can't be proxied: %s", len(b), err)
		return nil, nil
	}

	if err := c.str.SendDatagram(data); err != nil {
		var errDTL *quic.DatagramTooLargeError
		if errors.As(err, &errDTL) {
			return c.composeTooLargePacket(b, errDTL.MaxDatagramPayloadSize)
		}
		select {
		case <-c.closeChan:
			return nil, c.closeErr
		default:
			return nil, err
		}
	}
	return nil, nil
}

// EffectiveMTU returns the largest conservatively accepted IP packet size for
// the QUIC DATAGRAM send path. HTTP/2 returns 0; QUIC starts from a conservative
// baseline before a path-specific limit is observed.
func (c *Conn) EffectiveMTU() int {
	maxPayload := c.maxDatagramPayload.Load()
	if maxPayload <= 0 {
		return 0
	}
	return int(maxPayload) - c.datagramOverhead()
}

// RefreshPMTU asks the QUIC send path for its current datagram payload limit.
// The probe is intentionally larger than quic-go's maximum packet buffer, so
// it is rejected synchronously and never placed on the wire.
func (c *Conn) RefreshPMTU() (mtu int, changed bool, err error) {
	if !c.usesQUICDatagrams {
		return 0, false, nil
	}
	err = c.str.SendDatagram(datagramProbePayload)
	var errDTL *quic.DatagramTooLargeError
	if !errors.As(err, &errDTL) {
		if err == nil {
			return 0, false, errors.New("connect-ip: PMTU probe unexpectedly fit in a QUIC datagram")
		}
		return 0, false, fmt.Errorf("connect-ip: PMTU probe failed: %w", err)
	}
	if errDTL.MaxDatagramPayloadSize <= int64(c.datagramOverhead()) {
		return 0, false, fmt.Errorf("connect-ip: invalid QUIC datagram payload limit: %d", errDTL.MaxDatagramPayloadSize)
	}
	changed = c.observePMTU(errDTL.MaxDatagramPayloadSize)
	return c.EffectiveMTU(), changed, nil
}

func (c *Conn) composeTooLargePacket(b []byte, maxPayload int64) ([]byte, error) {
	if maxPayload <= int64(c.datagramOverhead()) {
		return nil, fmt.Errorf("connect-ip: invalid QUIC datagram payload limit: %d", maxPayload)
	}
	// Another writer may have observed a smaller limit after this packet was
	// preflighted. Never advertise a larger MTU than the current lower bound.
	if current := c.maxDatagramPayload.Load(); current > 0 && current < maxPayload {
		maxPayload = current
	}
	c.observePMTU(maxPayload)
	effectiveMTU := c.effectiveMTUForPayload(maxPayload)
	log.Printf("packet too large for QUIC datagram (max payload %d), sending ICMP Packet Too Big with MTU=%d",
		maxPayload, effectiveMTU)
	icmpPacket, err := composeICMPTooLargePacket(b, effectiveMTU)
	if err != nil {
		return nil, fmt.Errorf("connect-ip: failed to compose ICMP too large packet: %w", err)
	}
	return icmpPacket, nil
}

func (c *Conn) datagramOverhead() int {
	return quicDatagramOverhead + c.httpDatagramOverhead + len(contextIDZero)
}

func (c *Conn) observePMTU(maxPayload int64) bool {
	c.pmtuMu.Lock()
	defer c.pmtuMu.Unlock()

	current := c.maxDatagramPayload.Load()
	switch {
	case current <= 0:
		c.maxDatagramPayload.Store(maxPayload)
		c.pmtuIncrease = 0
		c.pmtuIncreaseCount = 0
		return true
	case maxPayload <= current:
		if maxPayload < current {
			c.maxDatagramPayload.Store(maxPayload)
		}
		c.pmtuIncrease = 0
		c.pmtuIncreaseCount = 0
		return maxPayload < current
	case c.pmtuIncrease == maxPayload:
		c.pmtuIncreaseCount++
	default:
		c.pmtuIncrease = maxPayload
		c.pmtuIncreaseCount = 1
	}

	if c.pmtuIncreaseCount < pmtuIncreaseConfirmations {
		return false
	}
	c.maxDatagramPayload.Store(maxPayload)
	c.pmtuIncrease = 0
	c.pmtuIncreaseCount = 0
	return true
}

func (c *Conn) effectiveMTUForPayload(maxPayload int64) int {
	return int(maxPayload) - c.datagramOverhead()
}

func (c *Conn) composeDatagram(b []byte) ([]byte, error) {
	// TODO: implement src, dst and ipproto checks
	if len(b) == 0 {
		return nil, nil
	}
	switch v := ipVersion(b); v {
	default:
		return nil, fmt.Errorf("connect-ip: unknown IP versions: %d", v)
	case 4:
		if len(b) < ipv4.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv4 packet too short")
		}
		ttl := b[8]
		if ttl <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram TTL too small: %d", ttl)
		}
		b[8]-- // decrement TTL
		// recalculate the checksum
		binary.BigEndian.PutUint16(b[10:12], calculateIPv4Checksum(([ipv4.HeaderLen]byte)(b[:ipv4.HeaderLen])))
	case 6:
		if len(b) < ipv6.HeaderLen {
			return nil, fmt.Errorf("connect-ip: IPv6 packet too short")
		}
		hopLimit := b[7]
		if hopLimit <= 1 {
			return nil, fmt.Errorf("connect-ip: datagram Hop Limit too small: %d", hopLimit)
		}
		b[7]-- // Decrement Hop Limit
	}
	data := make([]byte, 0, len(contextIDZero)+len(b))
	data = append(data, contextIDZero...)
	data = append(data, b...)
	return data, nil
}

// SendNoiseDatagram sends an arbitrary payload as a QUIC DATAGRAM frame.
// The server will silently drop datagrams with unknown Context IDs per RFC 9484.
// This is used for traffic obfuscation to make tunnel establishment indistinguishable
// from normal data transfer.
func (c *Conn) SendNoiseDatagram(data []byte) error {
	return c.str.SendDatagram(data)
}

func (c *Conn) Close() error {
	c.mu.Lock()
	if c.closeErr == nil {
		c.closeErr = &CloseError{Remote: false}
		close(c.closeChan)
	}
	c.mu.Unlock()
	c.str.CancelRead(quic.StreamErrorCode(http3.ErrCodeNoError))
	err := c.str.Close()
	return err
}

func ipVersion(b []byte) uint8 { return b[0] >> 4 }
