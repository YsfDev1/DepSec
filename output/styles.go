package output

import (
	"github.com/charmbracelet/lipgloss"
)

// Color scheme matching modern CLI aesthetics
var (
	// Base colors
	colorPrimary   = lipgloss.Color("#7C3AED") // Violet
	colorSecondary = lipgloss.Color("#06B6D4") // Cyan
	colorSuccess   = lipgloss.Color("#10B981") // Emerald
	colorWarning   = lipgloss.Color("#F59E0B") // Amber
	colorError     = lipgloss.Color("#EF4444") // Red
	colorInfo      = lipgloss.Color("#3B82F6") // Blue
	colorMuted     = lipgloss.Color("#6B7280") // Gray
	colorDark      = lipgloss.Color("#1F2937") // Dark gray
	colorLight     = lipgloss.Color("#F9FAFB") // Light gray
	colorWhite     = lipgloss.Color("#FFFFFF")

	// Severity colors
	colorCritical = lipgloss.Color("#DC2626") // Red 600
	colorHigh     = lipgloss.Color("#EA580C") // Orange 600
	colorMedium   = lipgloss.Color("#D97706") // Amber 600
	colorLow      = lipgloss.Color("#2563EB") // Blue 600
	colorClean    = lipgloss.Color("#059669") // Green 600
)

// Styles for different UI components
var (
	// Header styles
	HeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			MarginBottom(1)

	SubheaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorSecondary).
			MarginTop(1).
			MarginBottom(1)

	// Severity badge styles
	CriticalStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorCritical).
			Padding(0, 1)

	HighStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorHigh).
			Padding(0, 1)

	MediumStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorMedium).
			Padding(0, 1)

	LowStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorLow).
			Padding(0, 1)

	CleanStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorWhite).
			Background(colorClean).
			Padding(0, 1)

	// Text styles
	TitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorPrimary).
			MarginBottom(1)

	DescriptionStyle = lipgloss.NewStyle().
				Foreground(colorMuted).
				MarginBottom(1)

	SuccessTextStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorSuccess)

	ErrorTextStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorError)

	WarningTextStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorWarning)

	InfoTextStyle = lipgloss.NewStyle().
			Foreground(colorInfo)

	MutedTextStyle = lipgloss.NewStyle().
			Foreground(colorMuted)

	// Table styles
	TableHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colorWhite).
				Background(colorPrimary).
				Padding(0, 1)

	TableCellStyle = lipgloss.NewStyle().
			Foreground(colorLight).
			Padding(0, 1)

	TableBorderStyle = lipgloss.NewStyle().
				Foreground(colorMuted)

	// Box/Panel styles
	BoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorPrimary).
			Padding(1, 2).
			Margin(1, 0)

	InfoBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorInfo).
			Padding(1, 2).
			Margin(1, 0)

	WarningBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorWarning).
			Padding(1, 2).
			Margin(1, 0)

	ErrorBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorError).
			Padding(1, 2).
			Margin(1, 0)

	SuccessBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(colorSuccess).
			Padding(1, 2).
			Margin(1, 0)

	// Progress bar styles
	ProgressBarStyle = lipgloss.NewStyle().
				Foreground(colorPrimary)

	ProgressFillStyle = lipgloss.NewStyle().
				Background(colorPrimary).
				Foreground(colorWhite)

	ProgressEmptyStyle = lipgloss.NewStyle().
				Background(colorMuted).
				Foreground(colorMuted)

	// Layer icon styles
	LayerIconStyle = lipgloss.NewStyle().
			Bold(true).
			Width(2)
)

// GetSeverityStyle returns the appropriate style for a severity level
func GetSeverityStyle(severity string) lipgloss.Style {
	switch severity {
	case "CRITICAL":
		return CriticalStyle
	case "HIGH":
		return HighStyle
	case "MEDIUM":
		return MediumStyle
	case "LOW":
		return LowStyle
	case "CLEAN", "PASS", "OK":
		return CleanStyle
	default:
		return MutedTextStyle
	}
}

// GetSeverityColor returns the color for a severity level
func GetSeverityColor(severity string) lipgloss.Color {
	switch severity {
	case "CRITICAL":
		return colorCritical
	case "HIGH":
		return colorHigh
	case "MEDIUM":
		return colorMedium
	case "LOW":
		return colorLow
	case "CLEAN", "PASS", "OK":
		return colorClean
	default:
		return colorMuted
	}
}

// Layer icons as emoji
const (
	IconCVE      = "🔍"
	IconMetadata = "📦"
	IconSandbox  = "🏗️"
	IconYARA     = "🎯"
	IconClamAV   = "🛡️"
	IconDoctor   = "🏥"
	IconConfig   = "⚙️"
	IconScan     = "🔎"
	IconAuto     = "🤖"
	IconReport   = "📊"
	IconSuccess  = "✅"
	IconError    = "❌"
	IconWarning  = "⚠️"
	IconInfo     = "ℹ️"
	IconArrow    = "→"
	IconBullet   = "•"
	IconCheck    = "✓"
	IconCross    = "✗"
)

// GetLayerIcon returns the appropriate icon for a scan layer
func GetLayerIcon(layer string) string {
	switch layer {
	case "CVE":
		return IconCVE
	case "Metadata":
		return IconMetadata
	case "Sandbox":
		return IconSandbox
	case "YARA":
		return IconYARA
	case "ClamAV":
		return IconClamAV
	case "Doctor":
		return IconDoctor
	default:
		return IconBullet
	}
}

// RenderSeverityBadge renders a severity string as a styled badge
func RenderSeverityBadge(severity string) string {
	return GetSeverityStyle(severity).Render(severity)
}

// Width calculations for table alignment
const (
	PackageNameWidth = 25
	VersionWidth     = 15
	EcosystemWidth   = 12
	SeverityWidth    = 10
	LayerWidth       = 12
	ReasonWidth      = 40
)
