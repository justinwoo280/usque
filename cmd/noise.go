package cmd

import (
	"github.com/Diniboy1123/usque/internal"
	"github.com/spf13/cobra"
)

func addNoiseFlags(cmd *cobra.Command) {
	cmd.Flags().Int("noise-count", 0, "Number of DATAGRAM noise frames to inject after tunnel connect (0 = disabled)")
	cmd.Flags().Int("noise-min-size", 64, "Minimum noise frame size in bytes")
	cmd.Flags().Int("noise-max-size", 1200, "Maximum noise frame size in bytes")
	cmd.Flags().Duration("noise-delay-min", 0, "Minimum delay between noise frames")
	cmd.Flags().Duration("noise-delay-max", 0, "Maximum delay between noise frames")

	cmd.Flags().Int("pre-noise-count", 0, "Number of raw UDP noise packets before QUIC handshake (0 = disabled)")
	cmd.Flags().Int("pre-noise-min-size", 64, "Minimum pre-noise packet size in bytes")
	cmd.Flags().Int("pre-noise-max-size", 1200, "Maximum pre-noise packet size in bytes")
	cmd.Flags().Duration("pre-noise-delay-min", 0, "Minimum delay between pre-noise packets")
	cmd.Flags().Duration("pre-noise-delay-max", 0, "Maximum delay between pre-noise packets")
}

func noiseConfig(cmd *cobra.Command) internal.NoiseConfig {
	count, _ := cmd.Flags().GetInt("noise-count")
	if count <= 0 {
		return internal.NoiseConfig{}
	}
	minSize, _ := cmd.Flags().GetInt("noise-min-size")
	maxSize, _ := cmd.Flags().GetInt("noise-max-size")
	delayMin, _ := cmd.Flags().GetDuration("noise-delay-min")
	delayMax, _ := cmd.Flags().GetDuration("noise-delay-max")

	return internal.NoiseConfig{
		Count:    count,
		MinSize:  minSize,
		MaxSize:  maxSize,
		DelayMin: delayMin,
		DelayMax: delayMax,
	}
}

func preNoiseConfig(cmd *cobra.Command) internal.NoiseConfig {
	count, _ := cmd.Flags().GetInt("pre-noise-count")
	if count <= 0 {
		return internal.NoiseConfig{}
	}
	minSize, _ := cmd.Flags().GetInt("pre-noise-min-size")
	maxSize, _ := cmd.Flags().GetInt("pre-noise-max-size")
	delayMin, _ := cmd.Flags().GetDuration("pre-noise-delay-min")
	delayMax, _ := cmd.Flags().GetDuration("pre-noise-delay-max")

	return internal.NoiseConfig{
		Count:    count,
		MinSize:  minSize,
		MaxSize:  maxSize,
		DelayMin: delayMin,
		DelayMax: delayMax,
	}
}
