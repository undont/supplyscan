// Package jsonc provides utilities for handling JSON with comments (JSONC).
package jsonc

import (
	"bytes"
)

// StripComments removes JavaScript-style comments from JSONC content.
// Handles both single-line (//) and multi-line (/* */) comments.
// Preserves strings that contain comment-like sequences.
func StripComments(data []byte) []byte {
	var result bytes.Buffer
	inString := false
	inSingleComment := false
	inMultiComment := false
	i := 0

	for i < len(data) {
		// Handle escape sequences in strings
		if inString && data[i] == '\\' && i+1 < len(data) {
			result.WriteByte(data[i])
			result.WriteByte(data[i+1])
			i += 2
			continue
		}

		// Toggle string state
		if data[i] == '"' && !inSingleComment && !inMultiComment {
			inString = !inString
			result.WriteByte(data[i])
			i++
			continue
		}

		// Skip content while in comments
		if inSingleComment {
			if data[i] == '\n' {
				inSingleComment = false
				result.WriteByte('\n') // Preserve line breaks
			}
			i++
			continue
		}

		if inMultiComment {
			if i+1 < len(data) && data[i] == '*' && data[i+1] == '/' {
				inMultiComment = false
				i += 2
			} else {
				i++
			}
			continue
		}

		// Detect comment starts (only outside strings)
		if !inString && i+1 < len(data) {
			if data[i] == '/' && data[i+1] == '/' {
				inSingleComment = true
				i += 2
				continue
			}
			if data[i] == '/' && data[i+1] == '*' {
				inMultiComment = true
				i += 2
				continue
			}
		}

		// Regular character
		result.WriteByte(data[i])
		i++
	}

	return result.Bytes()
}