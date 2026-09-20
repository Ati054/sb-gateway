package controlplane

import (
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

// acmeProgressState is transient by design. A worker cannot outlive a
// controller restart, so persisting its last callback would present stale work
// as current after recovery.
type acmeProgressState struct {
	ID          string
	Revision    string
	LastAttempt time.Time
	Stage       acmejob.ProgressStage
	At          time.Time
}

// beginACMEProgress establishes the sole active worker tuple. Callbacks from a
// prior process may still arrive while an OS pipe is draining; they may update
// this transient state only when they match this exact operation.
func (s *Server) beginACMEProgress(id, revision string, lastAttempt time.Time) {
	if id == "" || revision == "" || lastAttempt.IsZero() {
		return
	}
	s.acmeProgressMu.Lock()
	defer s.acmeProgressMu.Unlock()
	s.acmeProgress = acmeProgressState{ID: id, Revision: revision, LastAttempt: lastAttempt}
}

func (s *Server) noteACMEProgress(id, revision string, lastAttempt time.Time, event acmejob.ProgressEvent) {
	if !event.Valid() || id == "" || revision == "" || lastAttempt.IsZero() {
		return
	}
	s.acmeProgressMu.Lock()
	defer s.acmeProgressMu.Unlock()
	if s.acmeProgress.ID != id || s.acmeProgress.Revision != revision || !s.acmeProgress.LastAttempt.Equal(lastAttempt) {
		return
	}
	if s.acmeProgress.Stage == event.Stage {
		return
	}
	s.acmeProgress.Stage = event.Stage
	s.acmeProgress.At = s.now()
}

func (s *Server) currentACMEProgress(id string, record acmeRecord) (acmeProgressState, bool) {
	if record.State != "running" {
		return acmeProgressState{}, false
	}
	s.acmeProgressMu.Lock()
	defer s.acmeProgressMu.Unlock()
	progress := s.acmeProgress
	if progress.ID != id || progress.Revision != record.Revision || !progress.LastAttempt.Equal(record.LastAttempt) || progress.Stage == "" || progress.At.IsZero() {
		return acmeProgressState{}, false
	}
	return progress, true
}

func (s *Server) clearACMEProgress(id, revision string, lastAttempt time.Time) {
	s.acmeProgressMu.Lock()
	defer s.acmeProgressMu.Unlock()
	if s.acmeProgress.ID == id && s.acmeProgress.Revision == revision && s.acmeProgress.LastAttempt.Equal(lastAttempt) {
		s.acmeProgress = acmeProgressState{}
	}
}
