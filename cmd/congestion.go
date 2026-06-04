package cmd

import (
	"log"

	"github.com/Diniboy1123/usque/internal/congestion"
	"github.com/Diniboy1123/usque/internal/congestion/bbr"
	"github.com/apernet/quic-go"
	"github.com/spf13/cobra"
)

func addCongestionFlags(cmd *cobra.Command) {
	cmd.Flags().String("congestion", "reno", "Congestion control algorithm: reno (default), brutal, or bbr")
	cmd.Flags().Uint64("brutal-bps", 0, "Brutal target bitrate in bits per second (required when --congestion=brutal)")
	cmd.Flags().String("bbr-profile", "standard", "BBR profile: conservative, standard (default), or aggressive")
}

func congestionCallback(cmd *cobra.Command) func(*quic.Conn) {
	ctype, _ := cmd.Flags().GetString("congestion")
	bps, _ := cmd.Flags().GetUint64("brutal-bps")
	bbrProfile, _ := cmd.Flags().GetString("bbr-profile")

	switch ctype {
	case "brutal":
		if bps == 0 {
			log.Fatal("--congestion=brutal requires --brutal-bps to be set")
		}
		log.Printf("Using Brutal congestion control (target: %d bps)", bps)
		return func(conn *quic.Conn) {
			conn.SetCongestionControl(congestion.NewBrutalSender(bps))
		}
	case "bbr":
		profile, err := bbr.ParseProfile(bbrProfile)
		if err != nil {
			log.Fatalf("Invalid BBR profile: %v", err)
		}
		log.Printf("Using BBR congestion control (profile: %s)", profile)
		return func(conn *quic.Conn) {
			conn.SetCongestionControl(bbr.NewBbrSender(
				bbr.DefaultClock{},
				bbr.GetInitialPacketSize(conn.RemoteAddr()),
				profile,
			))
		}
	case "reno", "":
		return nil
	default:
		log.Fatalf("Unknown congestion algorithm: %q (use 'reno', 'brutal', or 'bbr')", ctype)
		return nil
	}
}
