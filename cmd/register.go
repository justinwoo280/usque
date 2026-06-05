package cmd

import (
	"encoding/base64"
	"fmt"
	"log"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a new client and enroll a device key",
	Long: "Registers a new account and enrolls a device key. Also makes sure that it switches to" +
		" MASQUE mode. Saves the config to a file.",
	Run: func(cmd *cobra.Command, args []string) {
		configPath, _ := cmd.Flags().GetString("config")
		if configPath == "" {
			log.Fatalf("Config path is required")
		}

		if existing, err := config.LoadFullConfig(configPath); err == nil && existing.Account.PrivateKey != "" {
			fmt.Printf("You already have a config at %s. Do you want to overwrite it? (y/n) ", configPath)
			var response string
			if _, err := fmt.Scanln(&response); err != nil {
				log.Fatalf("Failed to read response: %v", err)
			}
			if response != "y" {
				return
			}
		}

		deviceName, _ := cmd.Flags().GetString("name")
		locale, _ := cmd.Flags().GetString("locale")
		model, _ := cmd.Flags().GetString("model")
		jwt, _ := cmd.Flags().GetString("jwt")
		acceptTos, _ := cmd.Flags().GetBool("accept-tos")

		if jwt != "" {
			log.Printf("Registering with locale %s and model %s using jwt authentication", locale, model)
		} else {
			log.Printf("Registering with locale %s and model %s", locale, model)
		}

		accountData, err := api.Register(model, locale, jwt, acceptTos)
		if err != nil {
			log.Fatalf("Failed to register: %v", err)
		}

		privKey, pubKey, err := internal.GenerateEcKeyPair()
		if err != nil {
			log.Fatalf("Failed to generate key pair: %v", err)
		}

		log.Printf("Enrolling device key...")

		updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, deviceName)
		if err != nil {
			if apiErr != nil {
				log.Fatalf("Failed to enroll key: %v (API errors: %s)", err, apiErr.ErrorsAsString("; "))
			}
			log.Fatalf("Failed to enroll key: %v", err)
		}

		log.Printf("Successful registration. Saving config...")

		acct := config.AccountConfig{
			PrivateKey:     base64.StdEncoding.EncodeToString(privKey),
			EndpointV4:     updatedAccountData.Config.Peers[0].Endpoint.V4[:len(updatedAccountData.Config.Peers[0].Endpoint.V4)-2],
			EndpointV6:     updatedAccountData.Config.Peers[0].Endpoint.V6[1 : len(updatedAccountData.Config.Peers[0].Endpoint.V6)-3],
			EndpointH2V4:   config.DefaultEndpointH2V4,
			EndpointPubKey: updatedAccountData.Config.Peers[0].PublicKey,
			License:        updatedAccountData.Account.License,
			ID:             updatedAccountData.ID,
			AccessToken:    accountData.Token,
			IPv4:           updatedAccountData.Config.Interface.Addresses.V4,
			IPv6:           updatedAccountData.Config.Interface.Addresses.V6,
		}

		fc := config.NewDefaultFullConfig(acct)
		if err := fc.SaveFullConfig(configPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}

		log.Printf("Config saved to %s", configPath)
	},
}

func init() {
	registerCmd.Flags().StringP("locale", "l", internal.DefaultLocale, "locale")
	registerCmd.Flags().StringP("model", "m", internal.DefaultModel, "model")
	registerCmd.Flags().StringP("name", "n", "", "device name")
	registerCmd.Flags().String("jwt", "", "team token")
	registerCmd.Flags().BoolP("accept-tos", "a", false, "accept Cloudflare TOS (not interactive setup)")
	rootCmd.AddCommand(registerCmd)
}
