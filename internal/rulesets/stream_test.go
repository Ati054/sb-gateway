package rulesets

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

type trackedSource struct {
	io.Reader
	closed bool
	close  func()
}

func (s *trackedSource) Close() error {
	if !s.closed {
		s.closed = true
		s.close()
	}
	return nil
}

func TestDomainStreamClosesParentsBeforeIncludes(t *testing.T) {
	files := map[string]string{"root": "# comment\ninclude:child\ninclude:child\nfull:Exact.Example\n", "child": "domain:Suffix.Example\nkeyword:video\nregexp:^img[0-9]+\\.example$\ninclude:root\n"}
	legacy, err := CompileDomainList("root", func(name string) (string, error) { return files[name], nil })
	if err != nil {
		t.Fatal(err)
	}
	open, peak := 0, 0
	streamed, err := CompileDomainListStream("root", func(name string) (io.ReadCloser, error) {
		open++
		if open > peak {
			peak = open
		}
		return &trackedSource{Reader: strings.NewReader(files[name]), close: func() { open-- }}, nil
	})
	if err != nil || !reflect.DeepEqual(legacy, streamed) || open != 0 || peak != 1 {
		t.Fatalf("stream changed rules/resources: %v open=%d peak=%d", err, open, peak)
	}
}

func TestDomainStreamRejectsMalformedAndOversizedSources(t *testing.T) {
	for _, source := range []string{"full:good.example\n# bad \xff\n", strings.Repeat("#\n", maxSourceBytes/2+1), "regexp:\n", "include:\n"} {
		closed := false
		_, err := CompileDomainListStream("root", func(string) (io.ReadCloser, error) {
			return &trackedSource{Reader: strings.NewReader(source), close: func() { closed = true }}, nil
		})
		if err == nil || !closed {
			t.Fatalf("invalid source accepted or leaked: error=%v closed=%t", err, closed)
		}
	}
}
