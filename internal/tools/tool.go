package tools

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// ExternalTool represents a dependency on an external system tool.
type ExternalTool struct {
	Name     string
	Required bool
	Note     string // why it's needed
	path     string
	version  string
	checked  bool
}

// ToolStatus holds the result of a dependency check.
type ToolStatus struct {
	Name      string
	Available bool
	Path      string
	Version   string
	Required  bool
	Note      string
}

var versionRe = regexp.MustCompile(`(\d+\.\d+[\.\d]*)`)

// Check verifies if the tool exists and gets its version.
func (t *ExternalTool) Check() ToolStatus {
	if t.checked {
		return ToolStatus{
			Name:      t.Name,
			Available: t.path != "",
			Path:      t.path,
			Version:   t.version,
			Required:  t.Required,
			Note:      t.Note,
		}
	}

	t.checked = true
	path, err := exec.LookPath(t.Name)
	if err != nil {
		return ToolStatus{Name: t.Name, Required: t.Required, Note: t.Note}
	}

	t.path = path
	t.version = getVersion(t.Name)

	return ToolStatus{
		Name:      t.Name,
		Available: true,
		Path:      t.path,
		Version:   t.version,
		Required:  t.Required,
		Note:      t.Note,
	}
}

// Exists returns true if the tool is installed.
func (t *ExternalTool) Exists() bool {
	s := t.Check()
	return s.Available
}

// Path returns the full path to the tool binary.
func (t *ExternalTool) Path() string {
	t.Check()
	return t.path
}

func getVersion(name string) string {
	ctx := context.Background()
	for _, flag := range []string{"--version", "-V", "version"} {
		out, err := RunCapture(ctx, name, flag)
		if err == nil && out != "" {
			if match := versionRe.FindString(out); match != "" {
				return match
			}
		}
	}
	return ""
}

// DependencyChecker manages all external tool dependencies.
type DependencyChecker struct {
	tools []*ExternalTool
}

func NewDependencyChecker() *DependencyChecker {
	var allTools []*ExternalTool

	// Platform-specific required tools (Linux: iw/ip, macOS: none)
	allTools = append(allTools, platformRequiredTools()...)

	// Optional tools (all platforms)
	allTools = append(allTools,
		// WEP attacks (only needed for legacy WEP networks)
		&ExternalTool{Name: "aircrack-ng", Required: false, Note: "WEP cracking"},
		&ExternalTool{Name: "aireplay-ng", Required: false, Note: "WEP replay attacks"},

		// WPS
		&ExternalTool{Name: "reaver", Required: false, Note: "WPS Pixie-Dust + PIN attacks"},
		&ExternalTool{Name: "bully", Required: false, Note: "WPS fallback"},

		// PMKID
		&ExternalTool{Name: "hcxdumptool", Required: false, Note: "PMKID capture"},
		&ExternalTool{Name: "hcxpcaptool", Required: false, Note: "PMKID format conversion"},
		&ExternalTool{Name: "hashcat", Required: false, Note: "GPU-accelerated cracking"},

		// Validation
		&ExternalTool{Name: "tshark", Required: false, Note: "additional handshake validation"},

		// Utility
		&ExternalTool{Name: "macchanger", Required: false, Note: "MAC randomization fallback"},
	)

	return &DependencyChecker{tools: allTools}
}

// InstallHint returns a platform-appropriate install message.
func InstallHint() string {
	return platformInstallHint()
}

// CheckAll verifies all dependencies and returns their status.
func (dc *DependencyChecker) CheckAll() []ToolStatus {
	results := make([]ToolStatus, len(dc.tools))
	for i, tool := range dc.tools {
		results[i] = tool.Check()
	}
	return results
}

// MissingRequired returns required tools that are not installed.
func (dc *DependencyChecker) MissingRequired() []string {
	var missing []string
	for _, tool := range dc.tools {
		s := tool.Check()
		if s.Required && !s.Available {
			missing = append(missing, tool.Name)
		}
	}
	return missing
}

// IsAvailable checks if a specific tool is available.
func (dc *DependencyChecker) IsAvailable(name string) bool {
	for _, tool := range dc.tools {
		if tool.Name == name {
			return tool.Exists()
		}
	}
	return false
}

// FormatStatus returns a formatted dependency report.
func FormatStatus(statuses []ToolStatus) string {
	var sb strings.Builder
	for _, s := range statuses {
		if s.Available {
			ver := s.Version
			if ver == "" {
				ver = "ok"
			}
			fmt.Fprintf(&sb, " [+] %-16s %-10s %s\n", s.Name, ver, s.Path)
		} else {
			label := "(optional)"
			if s.Required {
				label = "(REQUIRED)"
			}
			note := ""
			if s.Note != "" {
				note = " -- " + s.Note
			}
			fmt.Fprintf(&sb, " [-] %-16s %-10s %s%s\n", s.Name, "--", label, note)
		}
	}
	return sb.String()
}
