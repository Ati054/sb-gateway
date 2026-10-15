package runtimeconfig

import (
	"errors"
	"io"
	"sort"
	"strconv"
)

// UpgradeNginxCapacity changes only global nofile and events connection limits.
// Larger saved limits and all listeners, paths and guards are preserved.
func UpgradeNginxCapacity(config string) (string, error) {
	type edit struct {
		start, end int
		value      string
	}
	var edits []edit
	var blocks, directive []string
	start, eventsAt := 0, -1
	eventsCount, connectionsCount, nofileCount := 0, 0, 0
	lexer := nginxLimitLexer{input: config}
	for {
		token, syntax, err := lexer.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return config, err
		}
		if !syntax {
			if len(directive) == 0 {
				start = lexer.start
			}
			directive = append(directive, token)
			continue
		}
		switch token {
		case "{":
			if len(directive) == 0 || len(blocks) >= 128 {
				return config, errors.New("cannot upgrade Nginx capacity blocks")
			}
			if len(blocks) == 0 && directive[0] == "events" {
				eventsAt = lexer.at
				eventsCount++
			}
			blocks = append(blocks, directive[0])
		case "}":
			if len(blocks) == 0 || len(directive) != 0 {
				return config, errors.New("cannot upgrade Nginx capacity blocks")
			}
			blocks = blocks[:len(blocks)-1]
		case ";":
			if len(directive) == 0 {
				return config, errors.New("cannot upgrade Nginx capacity directives")
			}
			if directive[0] == "include" && (len(blocks) == 0 || len(blocks) == 1 && blocks[0] == "events") {
				return config, errors.New("cannot safely upgrade Nginx capacity declared through an external include")
			}
			minimum := 0
			if len(blocks) == 0 && directive[0] == "worker_rlimit_nofile" {
				nofileCount++
				minimum = 16384
			}
			if len(blocks) == 1 && blocks[0] == "events" && directive[0] == "worker_connections" {
				connectionsCount++
				minimum = 8192
			}
			if minimum != 0 {
				if len(directive) != 2 {
					return config, errors.New("cannot upgrade Nginx capacity value")
				}
				value, err := strconv.ParseUint(directive[1], 10, 64)
				if err != nil {
					return config, errors.New("cannot upgrade Nginx capacity value")
				}
				if value < uint64(minimum) {
					edits = append(edits, edit{start, lexer.at, directive[0] + " " + strconv.Itoa(minimum) + ";"})
				}
			}
		}
		directive = nil
	}
	if len(blocks) != 0 || len(directive) != 0 || eventsCount > 1 || connectionsCount > 1 || nofileCount > 1 {
		return config, errors.New("cannot upgrade ambiguous Nginx capacity configuration")
	}
	if eventsAt < 0 {
		return config, nil
	}
	if nofileCount == 0 {
		// Insert outside events without disturbing the schema header.
		lexer := nginxLimitLexer{input: config}
		_, _, _ = lexer.next()
		edits = append(edits, edit{lexer.start, lexer.start, "worker_rlimit_nofile 16384;\n"})
	}
	if connectionsCount == 0 {
		edits = append(edits, edit{eventsAt, eventsAt, "\n    worker_connections 8192;"})
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, e := range edits {
		config = config[:e.start] + e.value + config[e.end:]
	}
	return config, nil
}
