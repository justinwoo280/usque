//go:build windows

package internal

import (
	"fmt"
	"log"
	"os/exec"
)

func SetIPv4Address(ifaceName, ipAddr, mask string) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "address",
		fmt.Sprintf("name=\"%s\"", ifaceName),
		"static", ipAddr, mask)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv4 address set successfully:", ipAddr)
	return nil
}

func SetIPv4Peer(ifaceName, peerAddr string) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "add", "route",
		"0.0.0.0/0", fmt.Sprintf("name=\"%s\"", ifaceName), peerAddr, "metric=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", output)
	}
	log.Println("IPv4 peer gateway set successfully:", peerAddr)
	return nil
}

func SetIPv6Address(ifaceName, ipAddr, mask string) error {
	cmd := exec.Command("netsh", "interface", "ipv6", "set", "address",
		fmt.Sprintf("interface=\"%s\"", ifaceName),
		ipAddr+"/"+mask)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv6 address set successfully:", ipAddr)
	return nil
}

func SetIPv6Peer(ifaceName, peerAddr string) error {
	cmd := exec.Command("netsh", "interface", "ipv6", "add", "route",
		"::/0", fmt.Sprintf("interface=\"%s\"", ifaceName), peerAddr, "metric=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s", output)
	}
	log.Println("IPv6 peer gateway set successfully:", peerAddr)
	return nil
}

func SetIPv4MTU(ifaceName string, mtu int) error {
	cmd := exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("\"%s\"", ifaceName),
		fmt.Sprintf("mtu=%d", mtu))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv4 MTU set successfully:", mtu)
	return nil
}

func SetIPv6MTU(ifaceName string, mtu int) error {
	cmd := exec.Command("netsh", "interface", "ipv6", "set", "subinterface",
		fmt.Sprintf("\"%s\"", ifaceName),
		fmt.Sprintf("mtu=%d", mtu))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", output)
	}

	log.Println("IPv6 MTU set successfully:", mtu)
	return nil
}
