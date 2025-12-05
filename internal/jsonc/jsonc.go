// Package jsonc provides utilities for handling JSON with comments (JSONC).
package jsonc

import (
	"bytes"
)

// StripComments removes JavaScript-style comments from JSONC content.
// Handles both single-line (//) and multi-line (/* */) comments.
// Preserves strings that contain comment-like sequences.
func StripComments(data []byte) []byte {
	p := &jsoncParser{data: data, result: &bytes.Buffer{}}
	p.parse()
	return p.result.Bytes()
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
