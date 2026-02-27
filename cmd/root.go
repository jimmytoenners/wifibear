package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/wifibear/wifibear/internal/attack"
	"github.com/wifibear/wifibear/internal/config"
	"github.com/wifibear/wifibear/internal/iface"
	"github.com/wifibear/wifibear/internal/result"
	"github.com/wifibear/wifibear/internal/scan"
	"github.com/wifibear/wifibear/internal/tools"
	"github.com/wifibear/wifibear/ui"
)

const banner = `
 __      __ _  __  _  _
 \ \    / /(_)/ _|(_)| |__   ___  __ _  _ _
  \ \/\/ / | |  _|| || '_ \ / -_)/ _' || '_|
   \_/\_/  |_||_|  |_||_.__/ \___|\__,_||_|
`

func Execute(version string) error {
	cfg := config.DefaultConfig()

	rootCmd := &cobra.Command{
		Use:   "wifibear",
		Short: "Fast automated WiFi security auditing tool",
		Long:  banner + "\n  WifiBear v" + version + " - WiFi security auditing tool\n",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMain(cfg, version)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// Global flags
	f := rootCmd.Flags()
	f.StringVarP(&cfg.Interface, "interface", "i", "", "Wireless interface to use")
	f.StringVarP(&cfg.Wordlist, "wordlist", "w", cfg.Wordlist, "Path to wordlist for cracking")
	f.IntVarP(&cfg.Output.Verbose, "verbose", "v", 1, "Verbosity level (0-3)")

	// Scan flags
	f.DurationVar(&cfg.Scan.Timeout, "scan-timeout", cfg.Scan.Timeout, "Scan duration before target selection")
	f.StringVar(&cfg.BSSID, "bssid", "", "Target specific BSSID")
	f.StringVar(&cfg.ESSID, "essid", "", "Target specific ESSID")

	// Attack flags
	f.BoolVar(&cfg.Attack.WPAOnly, "wpa-only", false, "Only use WPA attacks")
	f.BoolVar(&cfg.Attack.WPSOnly, "wps-only", false, "Only use WPS attacks")
	f.BoolVar(&cfg.Attack.WEPOnly, "wep-only", false, "Only use WEP attacks")
	f.BoolVar(&cfg.Attack.NoPMKID, "no-pmkid", false, "Skip PMKID attacks")
	f.BoolVar(&cfg.Attack.NoWPS, "no-wps", false, "Skip WPS attacks")
	f.BoolVar(&cfg.Pillage, "pillage", false, "Attack all targets automatically")

	// WPA flags
	f.DurationVar(&cfg.Attack.WPA.HandshakeTimeout, "hs-timeout", cfg.Attack.WPA.HandshakeTimeout, "Handshake capture timeout")
	f.DurationVar(&cfg.Attack.WPA.DeauthInterval, "deauth-interval", cfg.Attack.WPA.DeauthInterval, "Deauth send interval")
	f.IntVar(&cfg.Attack.WPA.DeauthCount, "deauth-count", cfg.Attack.WPA.DeauthCount, "Deauth frames per round")

	// PMKID flags
	f.DurationVar(&cfg.Attack.PMKID.Timeout, "pmkid-timeout", cfg.Attack.PMKID.Timeout, "PMKID capture timeout")

	// MAC flags
	f.BoolVar(&cfg.MAC.Randomize, "mac-randomize", cfg.MAC.Randomize, "Randomize MAC address")

	// Output flags
	f.StringVarP(&cfg.Output.ResultsFile, "output", "o", cfg.Output.ResultsFile, "Results output file")
	f.StringVar(&cfg.Output.HandshakeDir, "hs-dir", cfg.Output.HandshakeDir, "Handshake output directory")

	// Subcommands
	rootCmd.AddCommand(crackedCmd(cfg))
	rootCmd.AddCommand(checkCmd())
	rootCmd.AddCommand(depsCmd())

	return rootCmd.Execute()
}

func runMain(cfg *config.Config, version string) error {
	fmt.Print(banner)
	fmt.Printf("  WifiBear v%s\n\n", version)

	// Check dependencies
	deps := tools.NewDependencyChecker()
	statuses := deps.CheckAll()
	fmt.Println("  Dependency Check:")
	fmt.Print(tools.FormatStatus(statuses))
	fmt.Println()

	// Platform gate: must be Linux for WiFi attacks
	if !iface.IsLinux() {
		return fmt.Errorf("WiFi attacks require Linux with a monitor-mode capable adapter.\n" +
			"  You can still use these commands on macOS:\n" +
			"    wifibear cracked    - view cracked networks\n" +
			"    wifibear check      - validate handshake captures\n" +
			"    wifibear deps       - check tool availability")
	}

	// Check root (Linux only)
	if os.Geteuid() != 0 {
		return fmt.Errorf("wifibear must be run as root (try: sudo wifibear)")
	}

	missing := deps.MissingRequired()
	if len(missing) > 0 {
		return fmt.Errorf("missing required tools: %v\n  Install with: %s", missing, tools.InstallHint())
	}

	// Show capability summary
	capabilities := []string{"WPA Handshake (native)", "Deauth (native)"}
	if deps.IsAvailable("hcxdumptool") && deps.IsAvailable("hashcat") {
		capabilities = append(capabilities, "PMKID")
	}
	if deps.IsAvailable("reaver") || deps.IsAvailable("bully") {
		capabilities = append(capabilities, "WPS")
	}
	if deps.IsAvailable("aircrack-ng") && deps.IsAvailable("aireplay-ng") {
		capabilities = append(capabilities, "WEP")
	}
	fmt.Printf("  Capabilities: %s\n", strings.Join(capabilities, ", "))

	// Setup signal handling for cleanup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Detect and setup interface
	mgr := iface.NewManager()

	ifaceObj, err := mgr.SelectInterface(cfg.Interface)
	if err != nil {
		return fmt.Errorf("interface selection: %w", err)
	}
	fmt.Printf("  Interface: %s (%s)\n", ifaceObj.Name, ifaceObj.Driver)

	// Enable monitor mode
	fmt.Printf("  Enabling monitor mode on %s...\n", ifaceObj.Name)
	monIface, err := mgr.EnableMonitorMode(ctx, ifaceObj.Name)
	if err != nil {
		return fmt.Errorf("monitor mode: %w", err)
	}
	fmt.Printf("  Monitor interface: %s\n", monIface)

	// Ensure cleanup on exit
	defer func() {
		fmt.Println("\n  Cleaning up...")
		cleanupCtx := context.Background()
		mgr.Cleanup(cleanupCtx)
		fmt.Println("  Done.")
	}()

	// Handle signals for cleanup
	go func() {
		<-sigCh
		cancel()
	}()

	// Randomize MAC if configured
	if cfg.MAC.Randomize {
		newMAC, err := mgr.RandomizeMAC(ctx)
		if err != nil {
			fmt.Printf("  Warning: MAC randomization failed: %v\n", err)
		} else {
			fmt.Printf("  MAC randomized: %s\n", newMAC)
		}
	}

	fmt.Println()

	// Start scanner
	scanner := scan.NewScanner(monIface, cfg.Output.Verbose)
	if err := scanner.Start(ctx); err != nil {
		return fmt.Errorf("start scanner: %w", err)
	}
	defer scanner.Stop()

	// Initialize result store
	store := result.NewStore(cfg.Output.ResultsFile)

	// Initialize attack orchestrator
	statusCh := make(chan attack.StatusUpdate, 100)
	orchestrator := attack.NewOrchestrator(cfg, statusCh)

	// Launch TUI
	app := ui.NewApp(cfg, scanner, orchestrator, store, monIface)
	return ui.Run(app)
}

// crackedCmd shows previously cracked networks.
func crackedCmd(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "cracked",
		Short: "Show previously cracked networks",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := result.NewStore(cfg.Output.ResultsFile)
			fmt.Print(banner)
			fmt.Println("\n  Cracked Networks:")
			fmt.Println()
			fmt.Print(store.FormatCracked())
			return nil
		},
	}
}

// checkCmd validates a handshake capture file.
func checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check [cap-file] [bssid]",
		Short: "Check a capture file for valid handshakes",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			capFile := args[0]
			bssid := args[1]

			fmt.Printf("Checking %s for BSSID %s...\n", capFile, bssid)

			validator := tools.NewTshark()
			if validator.Available() {
				valid, err := validator.HasHandshake(cmd.Context(), capFile, bssid)
				if err != nil {
					return err
				}
				if valid {
					fmt.Println("  Valid handshake found!")
				} else {
					fmt.Println("  No valid handshake found.")
				}
			} else {
				fmt.Println("  tshark not available, using gopacket validator...")
			}

			return nil
		},
	}
}

// depsCmd shows dependency status.
func depsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "deps",
		Short: "Check tool dependencies",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print(banner)
			fmt.Println("\n  Dependency Check:")
			deps := tools.NewDependencyChecker()
			fmt.Print(tools.FormatStatus(deps.CheckAll()))
		},
	}
}
