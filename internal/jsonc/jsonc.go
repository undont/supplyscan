// Package jsonc provides utilities for handling JSON with comments (JSONC).
package jsonc

import (
	"bytes"
)

// StripComments removes JavaScript-style comments and trailing commas from JSONC content.
// Handles both single-line (//) and multi-line (/* */) comments.
// Also removes trailing commas (commas followed only by whitespace before ] or }) which are valid in JSONC but not JSON.
// Preserves strings that contain comment-like sequences.
func StripComments(data []byte) []byte {
	p := &jsoncParser{data: data, result: &bytes.Buffer{}}
	p.parse()
	return stripTrailingCommas(p.result.Bytes())
}

// stripTrailingCommas removes trailing commas before ] and }.
// A trailing comma is a comma followed only by whitespace before a closing bracket.
func stripTrailingCommas(data []byte) []byte {
	result := make([]byte, 0, len(data))
	inString := false

	for i := 0; i < len(data); i++ {
		c := data[i]

		if c == '"' && !isEscaped(data, i) {
			inString = !inString
		}

		if !inString && c == ',' && isTrailingComma(data, i) {
			continue
		}

		result = append(result, c)
	}

	return result
}

// isTrailingComma checks if the comma at position i is followed only by whitespace
// before a closing bracket.
func isTrailingComma(data []byte, i int) bool {
	for j := i + 1; j < len(data); j++ {
		c := data[j]
		if isWhitespace(c) {
			continue
		}
		return c == ']' || c == '}'
	}
	return false
}

// isWhitespace returns true for space, tab, newline, or carriage return.
func isWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// isEscaped checks if the character at position i is escaped by a backslash.
func isEscaped(data []byte, i int) bool {
	if i == 0 {
		return false
	}
	// Count consecutive backslashes before position i
	count := 0
	for j := i - 1; j >= 0 && data[j] == '\\'; j-- {
		count++
	}
	// Odd number of backslashes means the character is escaped
	return count%2 == 1
}

type parserState int

const (
	stateNormal parserState = iota
	stateString
	stateSingleComment
	stateMultiComment
)

type jsoncParser struct {
	data   []byte
	result *bytes.Buffer
	pos    int
	state  parserState
}

func (p *jsoncParser) parse() {
	for p.pos < len(p.data) {
		switch p.state {
		case stateString:
			p.handleString()
		case stateSingleComment:
			p.handleSingleComment()
		case stateMultiComment:
			p.handleMultiComment()
		default:
			p.handleNormal()
		}
	}
}

func (p *jsoncParser) handleNormal() {
	c := p.data[p.pos]

	// Check for string start
	if c == '"' {
		p.state = stateString
		p.result.WriteByte(c)
		p.pos++
		return
	}

	// Check for comment start
	if p.hasNext() && c == '/' {
		next := p.data[p.pos+1]
		if next == '/' {
			p.state = stateSingleComment
			p.pos += 2
			return
		}
		if next == '*' {
			p.state = stateMultiComment
			p.pos += 2
			return
		}
	}

	p.result.WriteByte(c)
	p.pos++
}

func (p *jsoncParser) handleString() {
	c := p.data[p.pos]

	// Handle escape sequences
	if c == '\\' && p.hasNext() {
		p.result.WriteByte(c)
		p.result.WriteByte(p.data[p.pos+1])
		p.pos += 2
		return
	}

	// End of string
	if c == '"' {
		p.state = stateNormal
	}

	p.result.WriteByte(c)
	p.pos++
}

func (p *jsoncParser) handleSingleComment() {
	if p.data[p.pos] == '\n' {
		p.state = stateNormal
		p.result.WriteByte('\n')
	}
	p.pos++
}

func (p *jsoncParser) handleMultiComment() {
	if p.hasNext() && p.data[p.pos] == '*' && p.data[p.pos+1] == '/' {
		p.state = stateNormal
		p.pos += 2
		return
	}
	p.pos++
}

func (p *jsoncParser) hasNext() bool {
	return p.pos+1 < len(p.data)
}
