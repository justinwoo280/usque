package cmd

import (
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "usque",
	Short: "Usque Warp CLI",
	Long:  "An unofficial Cloudflare Warp CLI that uses the MASQUE protocol and exposes the tunnel as various different services.",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	internal.InstallDefaultLogTZStamp()
	rootCmd.PersistentFlags().StringP("config", "c", "config.json", "config file (default is config.json)")
}
