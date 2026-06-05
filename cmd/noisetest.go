package cmd

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/spf13/cobra"
	"github.com/yosida95/uritemplate/v3"

	connectip "github.com/Diniboy1123/connect-ip-go"
)

var noiseTestCmd = &cobra.Command{
	Use:   "noise-test",
	Short: "Test Cloudflare endpoint tolerance to UDP noise before QUIC handshake",
	Long: `Sends random UDP packets to the Cloudflare MASQUE endpoint before attempting
a QUIC handshake, then reports whether the handshake succeeds and timing details.
Use this to probe the boundary of what the endpoint tolerates.

Examples:
  # Baseline (no noise)
  usque noise-test --skip-noise

  # 5 small noise packets, no delay
  usque noise-test --noise-count 5 --noise-max-size 128 --noise-delay-max 0

  # Escalation test: 20 large packets with delays, 3 rounds
  usque noise-test --noise-count 20 --noise-min-size 64 --noise-max-size 1200 \
    --noise-delay-min 10ms --noise-delay-max 100ms --rounds 3

  # Stress test: 100 packets
  usque noise-test --noise-count 100 --noise-max-size 1200 --rounds 5 --round-pause 10s`,
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		fc, err := config.LoadFullConfig(configPath)
		if err != nil {
			cmd.Printf("Config not loaded: %v\n", err)
			return
		}
		config.AppConfig = fc.Account

		noiseCount, _ := cmd.Flags().GetInt("noise-count")
		noiseMinSize, _ := cmd.Flags().GetInt("noise-min-size")
		noiseMaxSize, _ := cmd.Flags().GetInt("noise-max-size")
		noiseDelayMin, _ := cmd.Flags().GetDuration("noise-delay-min")
		noiseDelayMax, _ := cmd.Flags().GetDuration("noise-delay-max")
		rounds, _ := cmd.Flags().GetInt("rounds")
		roundPause, _ := cmd.Flags().GetDuration("round-pause")
		connectPort, _ := cmd.Flags().GetInt("connect-port")
		useIPv6, _ := cmd.Flags().GetBool("ipv6")
		sni, _ := cmd.Flags().GetString("sni-address")
		insecure, _ := cmd.Flags().GetBool("insecure")
		skipNoise, _ := cmd.Flags().GetBool("skip-noise")
		handshakeTimeout, _ := cmd.Flags().GetDuration("handshake-timeout")

		privKey, err := config.AppConfig.GetEcPrivateKey()
		if err != nil {
			cmd.Printf("Failed to get private key: %v\n", err)
			return
		}
		peerPubKey, err := config.AppConfig.GetEcEndpointPublicKey()
		if err != nil {
			cmd.Printf("Failed to get endpoint public key: %v\n", err)
			return
		}

		cert, err := internal.GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			cmd.Printf("Failed to generate cert: %v\n", err)
			return
		}

		tlsConfig, err := api.PrepareTlsConfig(privKey, peerPubKey, cert, sni, insecure)
		if err != nil {
			cmd.Printf("Failed to prepare TLS config: %v\n", err)
			return
		}

		endpoint, err := config.SelectEndpointFromConfig(false, useIPv6, connectPort)
		if err != nil {
			cmd.Printf("Failed to select endpoint: %v\n", err)
			return
		}
		udpEndpoint := endpoint.(*net.UDPAddr)

		log.Printf("Target endpoint: %s", udpEndpoint)
		log.Printf("Noise config: count=%d, size=[%d,%d], delay=[%s,%s], rounds=%d, pause=%s",
			noiseCount, noiseMinSize, noiseMaxSize, noiseDelayMin, noiseDelayMax, rounds, roundPause)
		if skipNoise {
			log.Println("Noise disabled (--skip-noise), baseline test only")
		}

		successes := 0
		for round := 1; round <= rounds; round++ {
			log.Printf("=== Round %d/%d ===", round, rounds)

			if !skipNoise && noiseCount > 0 {
				sendNoise(udpEndpoint, noiseCount, noiseMinSize, noiseMaxSize, noiseDelayMin, noiseDelayMax)
			}

			ok, elapsed, detail := testHandshake(tlsConfig, udpEndpoint, handshakeTimeout)
			if ok {
				successes++
				log.Printf("Round %d: OK  total=%s  %s", round, elapsed, detail)
			} else {
				log.Printf("Round %d: FAIL  total=%s  %s", round, elapsed, detail)
			}

			if round < rounds {
				log.Printf("Pausing %s before next round...", roundPause)
				time.Sleep(roundPause)
			}
		}

		log.Printf("=== Summary: %d/%d rounds succeeded ===", successes, rounds)
	},
}

func sendNoise(endpoint *net.UDPAddr, count, minSize, maxSize int, delayMin, delayMax time.Duration) {
	udpConn, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		log.Printf("Noise: failed to dial UDP: %v", err)
		return
	}
	defer func() { _ = udpConn.Close() }()

	log.Printf("Noise: sending %d packets (size [%d,%d]) to %s ...", count, minSize, maxSize, endpoint)

	start := time.Now()
	sent := 0
	totalBytes := 0
	for i := 0; i < count; i++ {
		size := minSize
		if maxSize > minSize {
			b := make([]byte, 2)
			_, _ = rand.Read(b)
			size = minSize + int(uint16(b[0])<<8|uint16(b[1]))%(maxSize-minSize+1)
		}

		pkt := make([]byte, size)
		_, _ = rand.Read(pkt)

		n, err := udpConn.Write(pkt)
		if err != nil {
			log.Printf("Noise: write failed at packet %d: %v", i+1, err)
			break
		}
		sent++
		totalBytes += n

		if delayMax > 0 {
			delay := delayMin
			if delayMax > delayMin {
				b := make([]byte, 2)
				_, _ = rand.Read(b)
				delay = delayMin + time.Duration(uint16(b[0])<<8|uint16(b[1]))%(delayMax-delayMin+1)
			}
			time.Sleep(delay)
		}
	}
	log.Printf("Noise: sent %d/%d packets (%d bytes) in %s", sent, count, totalBytes, time.Since(start))
}

func testHandshake(tlsConfig *tls.Config, endpoint *net.UDPAddr, timeout time.Duration) (bool, time.Duration, string) {
	start := time.Now()

	var udpConn *net.UDPConn
	var err error
	if endpoint.IP.To4() == nil {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv6zero, Port: 0})
	} else {
		udpConn, err = net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	}
	if err != nil {
		return false, time.Since(start), fmt.Sprintf("ListenUDP failed: %v", err)
	}
	defer func() { _ = udpConn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	}

	t0 := time.Now()
	conn, err := quic.Dial(ctx, udpConn, endpoint, tlsConfig, quicCfg)
	quicElapsed := time.Since(t0)
	if err != nil {
		return false, time.Since(start), fmt.Sprintf("QUIC dial failed (%s): %v", quicElapsed, err)
	}
	defer func() { _ = conn.CloseWithError(0, "test done") }()

	tr := &http3.Transport{
		EnableDatagrams: true,
		AdditionalSettings: map[uint64]uint64{
			0x276: 1,
		},
		DisableCompression: true,
	}
	defer func() { _ = tr.Close() }()

	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(internal.ConnectURI)
	additionalHeaders := map[string][]string{
		"User-Agent": {""},
	}

	t1 := time.Now()
	ipConn, rsp, err := connectip.Dial(ctx, hconn, template, "cf-connect-ip", additionalHeaders, true)
	connectElapsed := time.Since(t1)
	if err != nil {
		return false, time.Since(start), fmt.Sprintf("QUIC=%s, Connect-IP failed (%s): %v", quicElapsed, connectElapsed, err)
	}
	defer func() { _ = ipConn.Close() }()

	if rsp.StatusCode != 200 {
		return false, time.Since(start), fmt.Sprintf("QUIC=%s, Connect-IP=%s, status=%s", quicElapsed, connectElapsed, rsp.Status)
	}

	return true, time.Since(start), fmt.Sprintf("QUIC=%s, Connect-IP=%s", quicElapsed, connectElapsed)
}

func init() {
	noiseTestCmd.Flags().Int("noise-count", 5, "Number of random UDP noise packets to send before handshake")
	noiseTestCmd.Flags().Int("noise-min-size", 64, "Minimum noise packet size in bytes")
	noiseTestCmd.Flags().Int("noise-max-size", 1200, "Maximum noise packet size in bytes")
	noiseTestCmd.Flags().Duration("noise-delay-min", 0, "Minimum delay between noise packets")
	noiseTestCmd.Flags().Duration("noise-delay-max", 50*time.Millisecond, "Maximum delay between noise packets")
	noiseTestCmd.Flags().Int("rounds", 1, "Number of test rounds to run")
	noiseTestCmd.Flags().Duration("round-pause", 5*time.Second, "Pause between rounds")
	noiseTestCmd.Flags().IntP("connect-port", "P", 443, "MASQUE endpoint port")
	noiseTestCmd.Flags().BoolP("ipv6", "6", false, "Use IPv6 endpoint")
	noiseTestCmd.Flags().StringP("sni-address", "s", internal.ConnectSNI, "SNI address")
	noiseTestCmd.Flags().Bool("insecure", false, "Disable certificate pinning")
	noiseTestCmd.Flags().Bool("skip-noise", false, "Skip noise injection (baseline test)")
	noiseTestCmd.Flags().Duration("handshake-timeout", 15*time.Second, "Timeout for QUIC+Connect-IP handshake")
	rootCmd.AddCommand(noiseTestCmd)
}
