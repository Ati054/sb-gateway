package controlplane

import (
	"net/url"
	"regexp"
	"strings"
)

const redacted = "<redacted>"

var (
	sensitiveKeyPattern = regexp.MustCompile(`(?i)(authorization|cookie|password|passwd|token|secret|uuid|private[_-]?key|api[_-]?key|subscription[_-]?url)`)
	uuidPattern         = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	authPattern         = regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+`)
	vlessPattern        = regexp.MustCompile(`(?i)\bvless://[^\s"'<>]+`)
	httpURLPattern      = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>]+`)
)

func redactValue(value any, key string, valuesAreSecretRefs bool) any {
	lowerKey := strings.ToLower(key)
	if key != "" && !valuesAreSecretRefs && sensitiveKeyPattern.MatchString(key) &&
		!strings.HasSuffix(lowerKey, "_secret_ref") && lowerKey != "secret_refs" {
		return redacted
	}
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for childKey, child := range typed {
			result[childKey] = redactValue(child, childKey, key == "secret_refs")
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, child := range typed {
			result[index] = redactValue(child, "", valuesAreSecretRefs)
		}
		return result
	case string:
		if valuesAreSecretRefs || strings.HasSuffix(lowerKey, "_secret_ref") {
			return typed
		}
		return redactText(typed)
	default:
		return typed
	}
}

func redactText(value string) string {
	value = authPattern.ReplaceAllString(value, "$1 "+redacted)
	value = uuidPattern.ReplaceAllString(value, redacted)
	value = vlessPattern.ReplaceAllString(value, "vless://"+redacted)
	return httpURLPattern.ReplaceAllStringFunc(value, redactURL)
}

func redactURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return redacted
	}
	path := "/"
	if parsed.Path != "" && parsed.Path != "/" {
		path = "/" + redacted
	}
	return parsed.Scheme + "://" + parsed.Host + path
}
