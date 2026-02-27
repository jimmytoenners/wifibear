package ui

import "github.com/charmbracelet/lipgloss"

var (
	// Colors
	colorBear    = lipgloss.Color("#FF6B35")
	colorGreen   = lipgloss.Color("#00B894")
	colorRed     = lipgloss.Color("#D63031")
	colorYellow  = lipgloss.Color("#FDCB6E")
	colorBlue    = lipgloss.Color("#0984E3")
	colorPurple  = lipgloss.Color("#6C5CE7")
	colorCyan    = lipgloss.Color("#00CEC9")
	colorGray    = lipgloss.Color("#636E72")
	colorDimGray = lipgloss.Color("#2D3436")
	colorWhite   = lipgloss.Color("#DFE6E9")

	// Title bar
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBear).
			PaddingLeft(1)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(colorGray).
			PaddingRight(1)

	// Table styles
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorCyan).
			PaddingLeft(2)

	selectedRowStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorWhite).
				Background(lipgloss.Color("#2D3436"))

	normalRowStyle = lipgloss.NewStyle().
			Foreground(colorWhite).
			PaddingLeft(2)

	// Target encryption colors
	encWPA2Style = lipgloss.NewStyle().Foreground(colorGreen)
	encWPAStyle  = lipgloss.NewStyle().Foreground(colorYellow)
	encWEPStyle  = lipgloss.NewStyle().Foreground(colorRed)
	encOpenStyle = lipgloss.NewStyle().Foreground(colorGray)

	// Attack status
	successStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorGreen)

	failStyle = lipgloss.NewStyle().
			Foreground(colorRed)

	progressStyle = lipgloss.NewStyle().
			Foreground(colorBlue)

	waitingStyle = lipgloss.NewStyle().
			Foreground(colorGray)

	// Key bindings help
	keyStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorYellow)

	helpStyle = lipgloss.NewStyle().
			Foreground(colorGray)

	// Borders
	borderStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorGray)

	// Banner
	bannerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBear)

	// Info text
	infoStyle = lipgloss.NewStyle().
			Foreground(colorCyan)

	dimStyle = lipgloss.NewStyle().
			Foreground(colorGray)
)

// SignalBar returns a visual signal strength indicator.
func SignalBar(power int) string {
	// power is negative dBm, higher (less negative) = stronger
	bars := 0
	switch {
	case power >= -50:
		bars = 4
	case power >= -60:
		bars = 3
	case power >= -70:
		bars = 2
	case power >= -80:
		bars = 1
	default:
		bars = 0
	}

	full := "█"
	empty := "░"
	result := ""
	for i := 0; i < 4; i++ {
		if i < bars {
			result += lipgloss.NewStyle().Foreground(colorGreen).Render(full)
		} else {
			result += lipgloss.NewStyle().Foreground(colorDimGray).Render(empty)
		}
	}
	return result
}

// EncryptionColor returns styled encryption text.
func EncryptionColor(enc string) string {
	switch enc {
	case "WPA2":
		return encWPA2Style.Render(enc)
	case "WPA":
		return encWPAStyle.Render(enc)
	case "WEP":
		return encWEPStyle.Render(enc)
	case "Open":
		return encOpenStyle.Render(enc)
	default:
		return enc
	}
}
