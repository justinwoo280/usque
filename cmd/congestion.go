package cmd

import (
	"log"

	"github.com/Diniboy1123/usque/internal/congestion"
	"github.com/apernet/quic-go"
	"github.com/spf13/cobra"
)

func addCongestionFlags(cmd *cobra.Command) {
	cmd.Flags().String("congestion", "reno", "Congestion control algorithm: reno (default) or brutal")
	cmd.Flags().Uint64("brutal-bps", 0, "Brutal target bitrate in bits per second (required when --congestion=brutal)")
}

func congestionCallback(cmd *cobra.Command) func(*quic.Conn) {
	ctype, _ := cmd.Flags().GetString("congestion")
	bps, _ := cmd.Flags().GetUint64("brutal-bps")

	switch ctype {
	case "brutal":
		if bps == 0 {
			log.Fatal("--congestion=brutal requires --brutal-bps to be set")
		}
		log.Printf("Using Brutal congestion control (target: %d bps)", bps)
		return func(conn *quic.Conn) {
			conn.SetCongestionControl(congestion.NewBrutalSender(bps))
		}
	case "reno", "":
		return nil
	default:
		log.Fatalf("Unknown congestion algorithm: %q (use 'reno' or 'brutal')", ctype)
		return nil
	}
}
