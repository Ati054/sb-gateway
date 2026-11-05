//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

func chrPairVLESSStream(vision bool, tlsSettings map[string]any) map[string]any {
	stream := map[string]any{"network": "ws", "security": "tls", "tlsSettings": tlsSettings}
	if vision {
		stream["network"] = "raw"
	} else {
		stream["wsSettings"] = map[string]any{"path": "/isolated-probe"}
	}
	return stream
}

// Compile the synthetic definitions once, outside the measured interval. The
// standalone test must exercise real HandlerService construction without
// launching an extra CLI process for every add. Production uses its embedded
// encoder; this fixture does not measure that encoder's compilation CPU.
func chrPairPreparedEncoder(t *testing.T, ctx context.Context, binary, root string, outbounds []any, preparations *atomic.Int64) xrayOutboundEncoder {
	t.Helper()
	input, output := filepath.Join(root, "dynamic-definitions.json"), filepath.Join(root, "dynamic-definitions.pb")
	body, err := json.Marshal(map[string]any{"outbounds": outbounds})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(input, body, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, binary, "convert", "pb", "-outpbfile", output, input)
	command.Env = append(os.Environ(), "SB_MEMORY_BUDGET=0", "GOMEMLIMIT=64MiB")
	if _, err = command.CombinedOutput(); err != nil {
		t.Fatalf("compile synthetic dynamic definitions: %v", err)
	}
	body, err = os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	compiled := map[string][]byte{}
	for len(body) > 0 {
		number, kind, n := protowire.ConsumeTag(body)
		if n < 0 {
			t.Fatal("invalid compiled config tag")
		}
		length := protowire.ConsumeFieldValue(number, kind, body[n:])
		if length < 0 {
			t.Fatal("invalid compiled config field")
		}
		if number == 2 && kind == protowire.BytesType {
			value, size := protowire.ConsumeBytes(body[n:])
			if size < 0 {
				t.Fatal("invalid compiled outbound")
			}
			tag, _, err := chrPairRetagOutbound(value, "")
			if err != nil {
				t.Fatal(err)
			}
			compiled[tag] = value
		}
		body = body[n+length:]
	}
	templates := map[string][]byte{}
	for _, raw := range outbounds {
		value := raw.(map[string]any)
		tag := value["tag"].(string)
		key, err := chrPairOutboundDefinition(value)
		if err != nil || compiled[tag] == nil {
			t.Fatal("synthetic outbound template missing")
		}
		templates[key] = compiled[tag]
	}
	return func(value map[string]any) ([]byte, error) {
		key, err := chrPairOutboundDefinition(value)
		if err != nil {
			return nil, err
		}
		original := templates[key]
		if original == nil {
			return nil, errors.New("unknown synthetic outbound")
		}
		tag, _ := value["tag"].(string)
		_, encoded, err := chrPairRetagOutbound(original, tag)
		if err == nil {
			preparations.Add(1)
		}
		return encoded, err
	}
}

func chrPairOutboundDefinition(value map[string]any) (string, error) {
	copy := make(map[string]any, len(value))
	for key, item := range value {
		if key != "tag" {
			copy[key] = item
		}
	}
	body, err := json.Marshal(copy)
	return string(body), err
}

// Only replace the tag. Typed sender/proxy fields remain opaque, byte-exact
// protobuf from the installed core, including fields unknown to the controller.
func chrPairRetagOutbound(body []byte, tag string) (string, []byte, error) {
	original := ""
	var result []byte
	if tag != "" {
		result = protowire.AppendTag(result, 1, protowire.BytesType)
		result = protowire.AppendString(result, tag)
	}
	for len(body) > 0 {
		number, kind, n := protowire.ConsumeTag(body)
		if n < 0 {
			return "", nil, errors.New("invalid outbound tag")
		}
		length := protowire.ConsumeFieldValue(number, kind, body[n:])
		if length < 0 {
			return "", nil, errors.New("invalid outbound field")
		}
		if number == 1 && kind == protowire.BytesType {
			value, size := protowire.ConsumeString(body[n:])
			if size < 0 || original != "" {
				return "", nil, errors.New("invalid outbound identity")
			}
			original = value
		} else {
			result = append(result, body[:n+length]...)
		}
		body = body[n+length:]
	}
	if original == "" {
		return "", nil, errors.New("outbound identity missing")
	}
	return original, result, nil
}

func TestCHRPreparedOutboundPreservesOpaqueSettings(t *testing.T) {
	unknown := protowire.AppendTag(nil, 2, protowire.BytesType)
	unknown = protowire.AppendBytes(unknown, []byte{8, 42, 18, 3, 1, 2, 3})
	body := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "old")
	body = append(body, unknown...)
	original, changed, err := chrPairRetagOutbound(body, "new")
	if err != nil || original != "old" {
		t.Fatal(original, err)
	}
	newTag, rest, err := chrPairRetagOutbound(changed, "")
	if err != nil || newTag != "new" || string(rest) != string(unknown) {
		t.Fatal("opaque sender settings changed")
	}
	if _, _, err := chrPairRetagOutbound([]byte{0xff}, "new"); err == nil {
		t.Fatal("malformed protobuf accepted")
	}
}
