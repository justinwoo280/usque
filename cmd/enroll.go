package cmd

import (
	"log"

	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Enrolls a MASQUE private key and switches mode",
	Long: "Enrolls a MASQUE private key and switches mode. Useful for ZeroTier where IPv6 address can change." +
		" Or if you just want to deploy a new key.",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		if configPath == "" {
			log.Fatalf("Config path is required")
		}

		fc, err := config.LoadFullConfig(configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}

		_ = fc
		log.Printf("Config at %s loaded successfully. Enrollment placeholder.", configPath)
	},
}

func init() {
	enrollCmd.Flags().StringP("name", "n", "", "Rename device a given name")
	enrollCmd.Flags().BoolP("regen-key", "r", false, "Regenerate the key pair")
	rootCmd.AddCommand(enrollCmd)
}
