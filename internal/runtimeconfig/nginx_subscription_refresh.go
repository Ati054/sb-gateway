package runtimeconfig

import (
	"errors"
	"io"
	"strings"
)

const nginxSubscriptionRefreshPattern = "^/api/v1/subscriptions/[^/]+/refresh$"

type nginxRefreshDirective struct {
	words      []string
	start, end int
}
type nginxRefreshBlock struct {
	parent, start, body, end int
	words                    []string
	directives               []nginxRefreshDirective
}

// UpgradeNginxSubscriptionRefreshTimeout gives only the authenticated refresh
// endpoint a 180s response budget. It copies the saved generic API policy rather
// than regenerating listeners or injecting the bootstrap appliance bearer.
// Ambiguous/custom routing is left unchanged with a content-free error.
func UpgradeNginxSubscriptionRefreshTimeout(config string) (string, error) {
	blocks, err := nginxRefreshBlocks(config)
	if err != nil {
		return config, err
	}
	management := -1
	for index, block := range blocks {
		if len(block.words) != 1 || block.words[0] != "server" {
			continue
		}
		if block.parent < 1 || len(blocks[block.parent].words) != 1 || blocks[block.parent].words[0] != "http" {
			continue
		}
		for _, directive := range block.directives {
			if len(directive.words) >= 2 && directive.words[0] == "listen" && (directive.words[1] == "9443" || strings.HasSuffix(directive.words[1], ":9443")) {
				if management >= 0 && management != index {
					return config, errors.New("cannot upgrade ambiguous Nginx management servers")
				}
				management = index
			}
		}
	}
	if management < 0 {
		return config, nil
	}
	for _, directive := range blocks[management].directives {
		if directive.words[0] == "include" {
			return config, errors.New("cannot upgrade Nginx management routing from an external include")
		}
	}
	api, refresh := -1, -1
	for index, block := range blocks {
		if block.parent != management || len(block.words) < 2 || block.words[0] != "location" {
			continue
		}
		words := block.words
		if len(words) == 2 && words[1] == "/api/" {
			if api >= 0 {
				return config, errors.New("cannot upgrade ambiguous Nginx API locations")
			}
			api = index
			continue
		}
		if len(words) == 3 && (words[1] == "~" || words[1] == "~*") {
			if words[1] == "~" && words[2] == nginxSubscriptionRefreshPattern {
				if refresh >= 0 {
					return config, errors.New("cannot upgrade duplicate Nginx refresh locations")
				}
				refresh = index
				continue
			}
			// Other managed regexes are disjoint. Unknown regex precedence or
			// guards must not be silently superseded by a new API location.
			if words[2] != "^/api/v1/drafts/(apply|rollback)$" {
				return config, errors.New("cannot upgrade custom Nginx API regex precedence")
			}
		}
		path := words[len(words)-1]
		if strings.HasPrefix(path, "/api/v1/subscriptions/") || len(words) == 3 && words[1] == "^~" && strings.HasPrefix("/api/v1/subscriptions/", path) {
			return config, errors.New("cannot upgrade overlapping Nginx subscription locations")
		}
	}
	if api < 0 {
		return config, nil
	} // Partial configurations may have no API.
	selected := api
	if refresh >= 0 {
		selected = refresh
	}
	block := blocks[selected]
	upstream, authorization, timeouts := 0, 0, 0
	var timeout nginxRefreshDirective
	for _, directive := range block.directives {
		words := directive.words
		switch words[0] {
		case "include":
			return config, errors.New("cannot upgrade Nginx API policy from an external include")
		case "proxy_pass":
			if len(words) == 2 && words[1] == "http://127.0.0.1:8080" {
				upstream++
			}
		case "proxy_set_header":
			if len(words) == 3 && strings.EqualFold(words[1], "Authorization") {
				if words[2] != "$http_authorization" {
					return config, errors.New("cannot upgrade custom Nginx API authentication")
				}
				authorization++
			}
		case "proxy_read_timeout":
			timeouts++
			timeout = directive
		}
	}
	if upstream != 1 || authorization != 1 || timeouts > 1 {
		return config, errors.New("cannot verify Nginx API refresh policy")
	}
	if refresh >= 0 {
		if timeouts == 1 {
			if len(timeout.words) != 2 {
				return config, errors.New("cannot upgrade Nginx refresh timeout")
			}
			if timeout.words[1] == "180s" {
				return config, nil
			}
			return config[:timeout.start] + "proxy_read_timeout 180s;" + config[timeout.end:], nil
		}
		return config[:block.body] + "\n            proxy_read_timeout 180s;" + config[block.body:], nil
	}
	body := config[block.body : block.end-1]
	if timeouts == 1 {
		body = config[block.body:timeout.start] + "proxy_read_timeout 180s;" + config[timeout.end:block.end-1]
	} else {
		body = "\n            proxy_read_timeout 180s;" + body
	}
	location := "location ~ " + nginxSubscriptionRefreshPattern + " {" + body + "}\n\n        "
	return config[:block.start] + location + config[block.start:], nil
}

func nginxRefreshBlocks(config string) ([]nginxRefreshBlock, error) {
	blocks := []nginxRefreshBlock{{parent: -1}}
	current, start := 0, 0
	var words []string
	lexer := nginxLimitLexer{input: config}
	for {
		token, syntax, err := lexer.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if !syntax {
			if len(words) == 0 {
				start = lexer.start
			}
			words = append(words, token)
			continue
		}
		switch token {
		case "{":
			if len(words) == 0 || len(blocks) >= 16384 {
				return nil, errors.New("cannot upgrade Nginx refresh blocks")
			}
			blocks = append(blocks, nginxRefreshBlock{parent: current, start: start, body: lexer.at, words: words})
			current = len(blocks) - 1
		case "}":
			if current == 0 || len(words) != 0 {
				return nil, errors.New("cannot upgrade Nginx refresh blocks")
			}
			blocks[current].end = lexer.at
			current = blocks[current].parent
		case ";":
			if len(words) == 0 {
				return nil, errors.New("cannot upgrade Nginx refresh directives")
			}
			blocks[current].directives = append(blocks[current].directives, nginxRefreshDirective{words, start, lexer.at})
		}
		words = nil
	}
	if current != 0 || len(words) != 0 {
		return nil, errors.New("cannot upgrade incomplete Nginx refresh configuration")
	}
	return blocks, nil
}
