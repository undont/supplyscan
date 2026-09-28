package types

import "testing"

func TestParseEcosystem(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "npm", false},
		{"npm", "npm", false},
		{"NPM", "npm", false},
		{"pypi", "pypi", false},
		{" python ", "pypi", false},
		{"pip", "pypi", false},
		{"pypy", "", true},
		{"rubygems", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseEcosystem(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseEcosystem(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("ParseEcosystem(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
