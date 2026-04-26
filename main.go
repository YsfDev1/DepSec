package main

import (
	"fmt"
	"os"

	"github.com/YsfDev1/DepSec/cmd"
	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "depsec",
		Short: "CLI Security Tool for Package Scanning",
		Long: `DepSec is a CLI tool that automatically scans packages in an isolated sandbox
before they touch the host system. The user installs DepSec once,
enables auto-scan, and every package install is silently screened
from that point on.

Use "depsec help [command]" for more information about a specific command.`,
		Version: "0.1.0",
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
	rootCmd.PersistentFlags().String("config", "", "Config file path (default is ~/.config/depsec/config.toml)")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
