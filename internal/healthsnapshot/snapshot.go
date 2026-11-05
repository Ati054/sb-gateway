// Package healthsnapshot binds an optional compact UI snapshot to its durable history.
package healthsnapshot

import "encoding/json"

const Filename = "selector-status.json"
const MaxBytes = 1 << 20

type Envelope struct {
	Version      int             `json:"version"`
	HistoryStamp string          `json:"history_stamp"`
	Status       json.RawMessage `json:"status"`
}
