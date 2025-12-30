package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	version    = "dev"
	configPath string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "kproxy",
	Short: "KProxy - Transparent HTTP/HTTPS interception proxy with DNS server",
	Long: `KProxy is a transparent HTTP/HTTPS interception proxy with embedded DNS
server for home network parental controls. It uses fact-based Open Policy Agent
(OPA) evaluation for access control.`,
	Version: version,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Default to server command when no subcommand is provided
		return runServer(cmd, args)
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/kproxy/config.yaml", "Path to configuration file")
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
