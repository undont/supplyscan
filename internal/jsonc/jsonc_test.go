package jsonc

import (
	"encoding/json"
	"testing"
)

func TestStripComments_SingleLineComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "comment at end of line",
			input: `{"key": "value"} // comment`,
			want:  `{"key": "value"} `,
		},
		{
			name:  "comment on own line",
			input: "{\n// this is a comment\n\"key\": \"value\"\n}",
			want:  "{\n\n\"key\": \"value\"\n}",
		},
		{
			name:  "multiple single-line comments",
			input: "{\n// comment 1\n\"a\": 1,\n// comment 2\n\"b\": 2\n}",
			want:  "{\n\n\"a\": 1,\n\n\"b\": 2\n}",
		},
		{
			name:  "no comments",
			input: `{"key": "value"}`,
			want:  `{"key": "value"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripComments([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("StripComments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripComments_MultiLineComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "multi-line comment",
			input: `{"key": /* comment */ "value"}`,
			want:  `{"key":  "value"}`,
		},
		{
			name:  "multi-line comment spanning lines",
			input: "{\n/* multi\nline\ncomment */\n\"key\": \"value\"\n}",
			want:  "{\n\n\"key\": \"value\"\n}",
		},
		{
			name:  "multiple multi-line comments",
			input: `{"a": /* first */ 1, "b": /* second */ 2}`,
			want:  `{"a":  1, "b":  2}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripComments([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("StripComments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripComments_MixedComments(t *testing.T) {
	input := `{
		// single line comment
		"key1": "value1", /* inline comment */
		/* multi
		   line
		   comment */
		"key2": "value2" // trailing comment
	}`

	got := StripComments([]byte(input))

	// Result should be valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(got, &result); err != nil {
		t.Errorf("Result is not valid JSON: %v\nResult: %s", err, got)
	}

	// Verify values
	if result["key1"] != "value1" {
		t.Errorf("key1 = %v, want value1", result["key1"])
	}
	if result["key2"] != "value2" {
		t.Errorf("key2 = %v, want value2", result["key2"])
	}
}

func TestStripComments_PreservesStrings(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "// in string preserved",
			input: `{"url": "http://example.com"}`,
			want:  `{"url": "http://example.com"}`,
		},
		{
			name:  "/* in string preserved",
			input: `{"comment": "/* not a comment */"}`,
			want:  `{"comment": "/* not a comment */"}`,
		},
		{
			name:  "complex URL in string",
			input: `{"api": "https://api.example.com/v1/users"}`,
			want:  `{"api": "https://api.example.com/v1/users"}`,
		},
		{
			name:  "comment-like in string then real comment",
			input: `{"url": "http://test.com"} // real comment`,
			want:  `{"url": "http://test.com"} `,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripComments([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("StripComments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripComments_EscapedQuotes(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "escaped quote in string",
			input: `{"key": "value with \"quotes\""}`,
			want:  `{"key": "value with \"quotes\""}`,
		},
		{
			name:  "escaped quote then comment",
			input: `{"key": "val\"ue"} // comment`,
			want:  `{"key": "val\"ue"} `,
		},
		{
			name:  "backslash not before quote",
			input: `{"path": "C:\\path\\to\\file"}`,
			want:  `{"path": "C:\\path\\to\\file"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripComments([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("StripComments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripComments_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "only comment",
			input: "// just a comment",
			want:  "",
		},
		{
			name:  "empty object",
			input: "{}",
			want:  "{}",
		},
		{
			name:  "consecutive slashes not comment start",
			input: `{"a": 1/2}`,
			want:  `{"a": 1/2}`,
		},
		{
			name:  "slash at end of input",
			input: `{"a": 1}/`,
			want:  `{"a": 1}/`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(StripComments([]byte(tt.input)))
			if got != tt.want {
				t.Errorf("StripComments() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStripComments_ValidJSON(t *testing.T) {
	// Test with realistic bun.lock content
	input := `{
		// This is a bun lockfile with comments
		"lockfileVersion": 0,
		"workspaces": {
			"": {
				"name": "test-project",
				/* Multi-line comment
				   that spans multiple lines */
				"dependencies": {
					"lodash": "^4.17.21",
					"express": "^4.18.2"
				}
			}
		},
		"packages": {
			"lodash": ["lodash@4.17.21", "", {}, "sha512-..."],
			"express": ["express@4.18.2", "", {}, "sha512-..."]
		}
	}`

	got := StripComments([]byte(input))

	// Result should be valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal(got, &result); err != nil {
		t.Errorf("Result is not valid JSON: %v\nResult: %s", err, got)
	}

	// Verify structure
	if result["lockfileVersion"] != float64(0) {
		t.Errorf("lockfileVersion = %v, want 0", result["lockfileVersion"])
	}

	packages, ok := result["packages"].(map[string]interface{})
	if !ok {
		t.Fatal("packages is not a map")
	}

	if _, ok := packages["lodash"]; !ok {
		t.Error("Expected lodash in packages")
	}
	if _, ok := packages["express"]; !ok {
		t.Error("Expected express in packages")
	}
}

func TestStripComments_NestedStructures(t *testing.T) {
	input := `{
		"level1": {
			// comment at level 2
			"level2": {
				/* comment at level 3 */
				"level3": "value"
			}
		}
	}`

	got := StripComments([]byte(input))

	var result map[string]interface{}
	if err := json.Unmarshal(got, &result); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	// Navigate to nested value
	level1 := result["level1"].(map[string]interface{})
	level2 := level1["level2"].(map[string]interface{})
	if level2["level3"] != "value" {
		t.Errorf("level3 = %v, want value", level2["level3"])
	}
}

func TestStripComments_Arrays(t *testing.T) {
	input := `{
		"array": [
			// comment in array
			"item1",
			/* another comment */
			"item2"
		]
	}`

	got := StripComments([]byte(input))

	var result map[string]interface{}
	if err := json.Unmarshal(got, &result); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}

	arr := result["array"].([]interface{})
	if len(arr) != 2 {
		t.Errorf("array length = %d, want 2", len(arr))
	}
	if arr[0] != "item1" || arr[1] != "item2" {
		t.Errorf("array = %v, want [item1, item2]", arr)
	}
}

func TestStripComments_Unicode(t *testing.T) {
	input := `{
		// Unicode comment: \u4e2d\u6587
		"key": "\u4e2d\u6587"
	}`

	got := StripComments([]byte(input))

	var result map[string]interface{}
	if err := json.Unmarshal(got, &result); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}
}

func TestStripComments_LargeInput(t *testing.T) {
	// Generate a large JSONC input
	var input string
	input = "{\n"
	for i := 0; i < 1000; i++ {
		input += `  // comment ` + "\n"
		input += `  "key` + string(rune('0'+i%10)) + `": "value",` + "\n"
	}
	input += `  "last": "value"` + "\n"
	input += "}"

	got := StripComments([]byte(input))

	var result map[string]interface{}
	if err := json.Unmarshal(got, &result); err != nil {
		t.Errorf("Result is not valid JSON: %v", err)
	}
}

func BenchmarkStripComments(b *testing.B) {
	input := []byte(`{
		// This is a comment
		"key1": "value1", /* inline */
		/* multi
		   line */
		"key2": "http://example.com/path",
		"key3": "/* not a comment */"
	}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		StripComments(input)
	}
}

func BenchmarkStripComments_NoComments(b *testing.B) {
	input := []byte(`{"key1": "value1", "key2": "value2", "key3": "value3"}`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		StripComments(input)
	}
}