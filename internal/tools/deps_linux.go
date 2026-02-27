//go:build linux

package tools

func platformRequiredTools() []*ExternalTool {
	return []*ExternalTool{
		{Name: "iw", Required: true, Note: "monitor mode + channel setting"},
		{Name: "ip", Required: true, Note: "interface management"},
	}
}

func platformInstallHint() string {
	return "sudo apt install iw iproute2"
}
