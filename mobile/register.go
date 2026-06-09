//go:build android

package mobile

import (
	"encoding/base64"
	"encoding/json"

	"github.com/Diniboy1123/usque/api"
	"github.com/Diniboy1123/usque/config"
	"github.com/Diniboy1123/usque/internal"
)

// RegisterAccount registers a new WARP account and returns a FullConfig JSON string.
//
// Parameters:
//   - jwt: Cloudflare ZeroTrust team token (empty string for regular WARP)
//   - deviceName: name for this device (empty string for auto-generated)
//
// Returns JSON config string on success, or "error: <message>" on failure.
func RegisterAccount(jwt string, deviceName string) string {
	acceptTos := true

	accountData, err := api.Register(internal.DefaultModel, internal.DefaultLocale, jwt, acceptTos)
	if err != nil {
		return "error: register failed: " + err.Error()
	}

	privKey, pubKey, err := internal.GenerateEcKeyPair()
	if err != nil {
		return "error: key generation failed: " + err.Error()
	}

	updatedAccountData, apiErr, err := api.EnrollKey(accountData, pubKey, deviceName)
	if err != nil {
		if apiErr != nil {
			return "error: enroll failed: " + err.Error() + " (" + apiErr.ErrorsAsString("; ") + ")"
		}
		return "error: enroll failed: " + err.Error()
	}

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
	data, err := json.MarshalIndent(fc, "", "  ")
	if err != nil {
		return "error: marshal config failed: " + err.Error()
	}

	return string(data)
}
