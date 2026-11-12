//go:build xray_multicall

package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"testing"

	brrr "github.com/molecule-man/go-brrr"
)

// Encoded independently with the C libbrotli 1.1.0 reference encoder.
func TestBrotliCertificateDecoderReferenceVectors(t *testing.T) {
	binary := make([]byte, 256*32)
	for i := range binary {
		binary[i] = byte(i)
	}
	for _, tc := range []struct {
		name, encoded string
		want          []byte
	}{
		{"empty", "Bg==", nil},
		{"text", "G38TAERP1l/SY9AIzcwEvulRagHnMR1YGadhzg0wtSGPjl/NEwsAUAE=", bytes.Repeat([]byte("TLS certificate compression regression\n"), 128)},
		{"binary", "G/8fAGRAbpafl5pMpCG+PJrgxwUABIEhUBh8fgwA4U+uBQACiUJjsDg8gUgiU6g0OgMjEzMLKxs7BycXNw8vH7+AoJCwiKiYuISklLSMrJy8gqKSsoqqmrqGppa2jq6evoGhkbGJqZm5haWVtY2tnb2Do5Ozi6ubu4enl7ePr59/QGBQcEhoWHhEZFR0TGxcfEJiUnJKalp6RmZWdk5uXn5BYVFxSWlZeUVlVXVNbV19Q2NTc0trW3tHZ1d3T29f/8Dg0PDI6Nj4xOTU9Mzs3PzC4tLyyura+sbm1vbO7t7+weHR8cnp2fnF5dX1ze3d/cPj0/PL69v7x+fX98/v3z+gAQ==", binary},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := base64.StdEncoding.DecodeString(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(io.LimitReader(brrr.NewReader(bytes.NewReader(encoded)), int64(len(tc.want)+1)))
			if err != nil || !bytes.Equal(got, tc.want) {
				t.Fatalf("reference decode: length=%d error=%v", len(got), err)
			}
			if len(encoded) > 1 {
				_, err := io.ReadAll(io.LimitReader(brrr.NewReader(bytes.NewReader(encoded[:len(encoded)-1])), int64(len(tc.want)+1)))
				if err == nil {
					t.Fatal("truncated stream accepted")
				}
			}
		})
	}
}
