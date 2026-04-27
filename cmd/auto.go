package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/YsfDev1/SecChain/hooks"
	"github.com/spf13/cobra"
)

var AutoCmd = &cobra.Command{
	Use:   "auto",
	Short: "Manage automatic scanning",
	Long:  `Enable or disable automatic scanning on package installs`,
}

var enableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable automatic scanning",
	Long:  `Inject shell hooks for automatic scanning on package installs`,
	Run: func(cmd *cobra.Command, args []string) {
		shellManager := hooks.NewShellManager()

		// Show what will be added
		hooks := shellManager.PreviewHooks()
		fmt.Printf("The following will be added to %s:\n\n", shellManager.ShellRC)
		fmt.Println(hooks)
		fmt.Println("\n[Y] Confirm  [N] Cancel")

		// Ask for confirmation
		var response string
		fmt.Print("Your choice: ")
		fmt.Scanln(&response)

		if !strings.EqualFold(response, "y") && !strings.EqualFold(response, "yes") {
			fmt.Println("❌ Cancelled")
			return
		}

		if err := shellManager.EnableAutoScan(); err != nil {
			fmt.Fprintf(os.Stderr, "Error enabling auto-scan: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("✅ Auto-scan enabled")
		fmt.Printf("Shell: %s\n", shellManager.ShellType)
		fmt.Printf("Config: %s\n", shellManager.ShellRC)
		fmt.Println("\n📝 Restart your shell or run:")
		fmt.Printf("   source %s\n", shellManager.ShellRC)
	},
}

var disableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable automatic scanning",
	Long:  `Remove shell hooks for automatic scanning`,
	Run: func(cmd *cobra.Command, args []string) {
		shellManager := hooks.NewShellManager()

		// Show what will be removed
		hooks := shellManager.PreviewRemoval()
		if hooks == "" {
			fmt.Println("❌ No SecChain hooks found to remove")
			return
		}

		fmt.Printf("The following will be removed from %s:\n\n", shellManager.ShellRC)
		fmt.Println(hooks)
		fmt.Println("\n[Y] Confirm  [N] Cancel")

		// Ask for confirmation
		var response string
		fmt.Print("Your choice: ")
		fmt.Scanln(&response)

		if !strings.EqualFold(response, "y") && !strings.EqualFold(response, "yes") {
			fmt.Println("❌ Cancelled")
			return
		}

		if err := shellManager.DisableAutoScan(); err != nil {
			fmt.Fprintf(os.Stderr, "Error disabling auto-scan: %v\n", err)
			os.Exit(1)
		}

		fmt.Println("✅ Auto-scan disabled")
		fmt.Println("\n📝 Restart your shell or run:")
		fmt.Printf("   source %s\n", shellManager.ShellRC)
	},
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show auto-scan status",
	Long:  `Show current auto-scan status and active layers`,
	Run: func(cmd *cobra.Command, args []string) {
		shellManager := hooks.NewShellManager()
		status := shellManager.GetStatus()

		fmt.Println("SecChain Auto-Scan Status:")
		fmt.Printf("  Enabled: %t\n", status["enabled"])
		fmt.Printf("  Shell: %s\n", status["shell"])
		fmt.Printf("  Config: %s\n", status["config"])

		if hooks, ok := status["hooks"].([]string); ok {
			fmt.Printf("  Hooks: %s\n", strings.Join(hooks, ", "))
		}
	},
}

func init() {
	AutoCmd.AddCommand(enableCmd)
	AutoCmd.AddCommand(disableCmd)
	AutoCmd.AddCommand(statusCmd)
}
