package main

import (
	"fmt"
	"os"

	"github.com/YsfDev1/SecChain/cmd"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "cc",
		Short: "SecChain (cc) — Package Security Scanner",
		Long: `SecChain (cc) is a CLI tool that automatically scans packages in an isolated sandbox
before they touch the host system. The user installs SecChain once,
enables auto-scan, and every package install is silently screened
from that point on.

Run 'cc help' to get started.`,
		Version: "0.1.5-beta",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				fmt.Println("SecChain (cc) — Package Security Scanner")
				fmt.Println("Run 'cc help' to get started.")
			}
		},
	}

	// Add subcommands
	rootCmd.AddCommand(cmd.ScanCmd)
	rootCmd.AddCommand(cmd.AutoCmd)
	rootCmd.AddCommand(cmd.ReportCmd)
	rootCmd.AddCommand(cmd.ConfigCmd)
	rootCmd.AddCommand(cmd.DoctorCmd)
	rootCmd.AddCommand(cmd.UpdateRulesCmd)
	rootCmd.AddCommand(cmd.VersionCmd)

	// Global flags
	rootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output")
	rootCmd.PersistentFlags().Bool("quiet", false, "Suppress non-error output")
	rootCmd.PersistentFlags().String("config", "", "Config file path (default is ~/.config/secchain/config.toml)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
