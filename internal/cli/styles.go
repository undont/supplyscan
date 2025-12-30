// Package cli provides the command-line interface for supplyscan.
package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// Colour palette for severity levels and UI elements.
//
//nolint:misspell // lipgloss uses American spelling (Color) for its API
var (
	// Severity colours
	criticalStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true) // Bright red
	highStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true) // Orange
	moderateStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))            // Yellow
	lowStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))             // Blue

	// Status colours
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))             // Green
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")).Bold(true) // Red
	warnStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))            // Yellow

	// UI elements
	headerStyle  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
	labelStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("245")) // Grey
	valueStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("255")) // White
	mutedStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("240")) // Dark grey
	packageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("81"))  // Cyan
	versionStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("141")) // Purple
	sectionStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39")).MarginTop(1)
	dividerStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	checkStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))  // Green checkmark
	crossStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196")) // Red cross
)

// Symbols for output.
const (
	checkMark = "✓"
	crossMark = "✗"
	bullet    = "•"
	arrow     = "→"
)

// severityStyle returns the appropriate style for a severity level.
func severityStyle(severity string) lipgloss.Style {
	switch severity {
	case "critical":
		return criticalStyle
	case "high":
		return highStyle
	case "moderate", "medium":
		return moderateStyle
	case "low":
		return lowStyle
	default:
		return valueStyle
	}
}

// formatSeverity returns a styled severity string.
func formatSeverity(severity string) string {
	return severityStyle(severity).Render(severity)
}

// formatPackage returns a styled package name.
func formatPackage(name string) string {
	return packageStyle.Render(name)
}

// formatVersion returns a styled version string.
func formatVersion(version string) string {
	return versionStyle.Render(version)
}

// formatPackageVersion returns a styled package@version string.
func formatPackageVersion(name, version string) string {
	return fmt.Sprintf("%s@%s", formatPackage(name), formatVersion(version))
}

// formatSuccess returns a styled success message.
func formatSuccess(msg string) string {
	return successStyle.Render(checkMark+" ") + msg
}

// formatError returns a styled error message.
func formatError(msg string) string {
	return errorStyle.Render(crossMark+" ") + msg
}

// formatWarning returns a styled warning message.
func formatWarning(msg string) string {
	return warnStyle.Render("! ") + msg
}

// formatLabel returns a styled label (for key-value pairs).
func formatLabel(label string) string {
	return labelStyle.Render(label + ":")
}

// formatHeader returns a styled header.
func formatHeader(text string) string {
	return headerStyle.Render(text)
}

// formatSection returns a styled section header.
func formatSection(text string) string {
	return sectionStyle.Render(text)
}

// formatDivider returns a styled divider line.
func formatDivider(width int) string {
	line := ""
	for i := 0; i < width; i++ {
		line += "─"
	}
	return dividerStyle.Render(line)
}

// formatMuted returns muted/dimmed text.
func formatMuted(text string) string {
	return mutedStyle.Render(text)
}

// printStyledError prints a styled error to stderr.
func printStyledError(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	_, _ = fmt.Fprintln(os.Stderr, formatError(msg))
}

// formatTimeAgo returns a human-readable relative time string.
func formatTimeAgo(timestamp string) string {
	t, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return timestamp
	}

	duration := time.Since(t)

	switch {
	case duration < time.Minute:
		return "just now"
	case duration < time.Hour:
		mins := int(duration.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	case duration < 24*time.Hour:
		hours := int(duration.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	default:
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}
