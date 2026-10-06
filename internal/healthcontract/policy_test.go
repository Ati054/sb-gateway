package healthcontract

import (
	"encoding/json"
	"testing"
)

func TestPolicyToleranceDefaultAndExplicitZero(t *testing.T) {
	for _, tc := range []struct {
		body string
		want int
	}{{`{}`, 50}, {`{"switch_improvement_ms":0}`, 0}, {`{"switch_improvement_ms":200}`, 200}} {
		var policy Policy
		if err := json.Unmarshal([]byte(tc.body), &policy); err != nil || policy.SwitchImprovementMS != tc.want {
			t.Fatalf("decode %s: policy=%+v err=%v", tc.body, policy, err)
		}
	}
}

func TestPolicyRejectsMalformedKnownFields(t *testing.T) {
	for _, body := range []string{
		`{"switch_improvement_ms":"200"}`, `{"probe_batch_size":true}`,
		`{"candidate_service_ids":[1]}`, `{"candidate_service_access":{"node":"service"}}`,
	} {
		var policy Policy
		if err := json.Unmarshal([]byte(body), &policy); err == nil {
			t.Fatalf("malformed wire input silently accepted: %s", body)
		}
	}
}
