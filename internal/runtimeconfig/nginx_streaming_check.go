package runtimeconfig

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// CheckNginxStreamingLimits audits inline transport directives without rewriting
// saved configuration. Nginx still owns syntax validation and include expansion.
func CheckNginxStreamingLimits(config string) error {
	type scope struct {
		parent             int
		location, upstream bool
		bodySize, timeout  []string
	}
	scopes := []scope{{parent: -1}}
	current := 0
	depth := 0
	var directive []string
	lexer := nginxLimitLexer{input: config}
	for {
		token, syntax, err := lexer.next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if !syntax {
			directive = append(directive, token)
			continue
		}
		switch token {
		case "{":
			if len(directive) == 0 || len(scopes) >= 16384 || depth >= 128 {
				return errors.New("cannot verify saved Nginx transport blocks")
			}
			scopes = append(scopes, scope{parent: current, location: directive[0] == "location"})
			current = len(scopes) - 1
			depth++
		case "}":
			if current == 0 || len(directive) != 0 {
				return errors.New("cannot verify saved Nginx transport blocks")
			}
			current = scopes[current].parent
			depth--
		case ";":
			if len(directive) == 0 {
				return errors.New("cannot verify saved Nginx transport directives")
			}
			switch directive[0] {
			case "client_max_body_size":
				scopes[current].bodySize = append([]string{}, directive[1:]...)
			case "client_body_timeout":
				scopes[current].timeout = append([]string{}, directive[1:]...)
			case "grpc_pass", "proxy_pass":
				if len(directive) == 2 && (directive[0] == "grpc_pass" && directive[1] == "grpc://127.0.0.1:11002" ||
					directive[0] == "proxy_pass" && directive[1] == "http://127.0.0.1:11004") {
					scopes[current].upstream = true
				}
			}
		}
		directive = nil
	}
	if current != 0 || len(directive) != 0 {
		return errors.New("cannot verify saved Nginx transport blocks")
	}
	for index, item := range scopes {
		if !item.upstream {
			continue
		}
		var bodySize, timeout []string
		location := false
		for at := index; at >= 0; at = scopes[at].parent {
			ancestor := scopes[at]
			location = location || ancestor.location
			if bodySize == nil {
				bodySize = ancestor.bodySize
			}
			if timeout == nil {
				timeout = ancestor.timeout
			}
		}
		if !location || len(bodySize) != 1 || bodySize[0] != "0" || !nginxStreamingTimeout(timeout) {
			return errors.New("saved gRPC/XHTTP locations lack verified unlimited request bodies or a body timeout of at least 300s")
		}
	}
	return nil
}

func nginxStreamingTimeout(arguments []string) bool {
	value := strings.Join(arguments, "")
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return seconds >= 300
	}
	duration, err := time.ParseDuration(value)
	return err == nil && duration >= 300*time.Second
}

type nginxLimitLexer struct {
	input string
	at    int
	start int
}

// Quotes, comments and escaped delimiters must not impersonate directives or
// close a location. Preserve only decoded tokens, never secret-bearing errors.
func (lexer *nginxLimitLexer) next() (string, bool, error) {
	for lexer.at < len(lexer.input) {
		ch := lexer.input[lexer.at]
		if strings.ContainsRune(" \t\r\n", rune(ch)) {
			lexer.at++
		} else if ch == '#' {
			for lexer.at < len(lexer.input) && lexer.input[lexer.at] != '\n' {
				lexer.at++
			}
		} else {
			break
		}
	}
	if lexer.at == len(lexer.input) {
		return "", false, io.EOF
	}
	lexer.start = lexer.at
	ch := lexer.input[lexer.at]
	if ch == '{' || ch == '}' || ch == ';' {
		lexer.at++
		return string(ch), true, nil
	}
	var token strings.Builder
	var quote byte
	variable := false
	for lexer.at < len(lexer.input) {
		ch = lexer.input[lexer.at]
		if ch == '\\' {
			lexer.at++
			if lexer.at == len(lexer.input) {
				return "", false, errors.New("cannot verify saved Nginx quoting")
			}
			token.WriteByte(lexer.input[lexer.at])
			lexer.at++
			continue
		}
		if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				token.WriteByte(ch)
			}
		} else if ch == '\'' || ch == '"' {
			quote = ch
		} else if ch == '$' && lexer.at+1 < len(lexer.input) && lexer.input[lexer.at+1] == '{' {
			token.WriteString("${")
			lexer.at += 2
			variable = true
			continue
		} else if variable {
			token.WriteByte(ch)
			variable = ch != '}'
		} else if strings.ContainsRune(" \t\r\n{};#", rune(ch)) {
			break
		} else {
			token.WriteByte(ch)
		}
		lexer.at++
	}
	if quote != 0 || variable {
		return "", false, errors.New("cannot verify saved Nginx quoting")
	}
	return token.String(), false, nil
}
