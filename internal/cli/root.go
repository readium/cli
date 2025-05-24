package cli

import (
	"os"

	"github.com/readium/go-toolkit/pkg/util/version"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "readium",
	Short:   "Utilities for Readium Web Publications",
	Version: Version + " (go-toolkit " + version.Version + ")",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		// Error is already printed to stderr by Cobra.
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
