//go:build darwin

package tools

func platformRequiredTools() []*ExternalTool {
	// No required tools on macOS — monitor mode / injection not supported.
	// Utility commands (cracked, check, deps) work without any dependencies.
	return nil
}

func platformInstallHint() string {
	return "wifibear requires Linux for WiFi attacks. Use 'wifibear deps' to check status."
}
