package cmd

import (
	"log"

	"github.com/Diniboy1123/usque/config"
	"github.com/spf13/cobra"
)

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Validate a JSON config file without starting",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		fc, err := config.LoadFullConfig(configPath)
		if err != nil {
			log.Fatalf("Config invalid: %v", err)
		}

		if _, err := fc.Account.GetEcPrivateKey(); err != nil {
			log.Fatalf("Invalid private key: %v", err)
		}
		if _, err := fc.Account.GetEcEndpointPublicKey(); err != nil {
			log.Fatalf("Invalid endpoint public key: %v", err)
		}

		switch fc.Inbound.Type {
		case "tun":
			if _, err := fc.ParseTunSettings(); err != nil {
				log.Fatalf("Invalid tun settings: %v", err)
			}
		case "socks":
			if _, err := fc.ParseSocksSettings(); err != nil {
				log.Fatalf("Invalid socks settings: %v", err)
			}
		case "http_proxy":
			if _, err := fc.ParseHTTPProxySettings(); err != nil {
				log.Fatalf("Invalid http_proxy settings: %v", err)
			}
		case "portfw":
			if _, err := fc.ParsePortFwSettings(); err != nil {
				log.Fatalf("Invalid portfw settings: %v", err)
			}
		default:
			log.Fatalf("Unknown inbound type: %q", fc.Inbound.Type)
		}

		if _, err := buildOutbound(fc); err != nil {
			log.Fatalf("Outbound config invalid: %v", err)
		}

		log.Println("Config is valid")
	},
}

func init() {
	rootCmd.AddCommand(checkCmd)
}
