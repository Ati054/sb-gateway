package controlplane

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	subscriptionGenerationReference = regexp.MustCompile(`^subscriptions/([A-Za-z0-9._-]+)/generations/([a-f0-9]{16})/`)
	subscriptionGenerationName      = regexp.MustCompile(`^[a-f0-9]{16}$`)
	subscriptionSnapshotName        = regexp.MustCompile(`^subscription-nodes-([a-f0-9]{64})\.json$`)
)

// pruneSubscriptionArtifacts retains only generations referenced by the
// current candidate plus the active, last-known-good and previous revisions.
// Subscription refreshes are immutable, so every other generation is a cache,
// not configuration state.
func (server *Server) pruneSubscriptionArtifacts(current map[string]any) error {
	keepGenerations := map[string]bool{}
	collectSubscriptionGenerations(current, keepGenerations)
	keepRevisions := map[string]bool{}
	for _, revision := range server.subscriptionRetentionRevisions() {
		if revision == "" || keepRevisions[revision] {
			continue
		}
		keepRevisions[revision] = true
		snapshot, err := server.repository.auxiliary("subscription-nodes-" + revision)
		if err != nil {
			return err
		}
		collectSubscriptionGenerations(snapshot, keepGenerations)
	}
	if len(keepGenerations) == 0 {
		return errors.New("current subscription generation set is empty")
	}
	if err := pruneSubscriptionGenerationDirs(server.secrets.root, keepGenerations); err != nil {
		return err
	}
	return pruneSubscriptionSnapshots(server.repository.root, keepRevisions)
}

func (server *Server) subscriptionRetentionRevisions() []string {
	active, _ := server.repository.activeRevision()
	lkg, _ := server.repository.lkgRevision()
	metadata, _ := server.repository.metadata()
	previous := text(metadata["previous_revision"])
	result := make([]string, 0, 3)
	for _, revision := range []string{active, lkg, previous, subscriptionText(metadata["node_snapshot_revision"]), subscriptionText(metadata["previous_node_snapshot_revision"])} {
		if safeRevision(revision) {
			result = append(result, revision)
		}
	}
	return result
}

func collectSubscriptionGenerations(value any, keep map[string]bool) {
	switch current := value.(type) {
	case map[string]any:
		for _, nested := range current {
			collectSubscriptionGenerations(nested, keep)
		}
	case []any:
		for _, nested := range current {
			collectSubscriptionGenerations(nested, keep)
		}
	case string:
		match := subscriptionGenerationReference.FindStringSubmatch(filepath.ToSlash(current))
		if len(match) == 3 {
			keep["subscriptions/"+match[1]+"/generations/"+match[2]] = true
		}
	}
}

func pruneSubscriptionGenerationDirs(secretsRoot string, keep map[string]bool) error {
	subscriptionsRoot := filepath.Join(secretsRoot, "subscriptions")
	subscriptions, err := os.ReadDir(subscriptionsRoot)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, subscription := range subscriptions {
		if !subscription.IsDir() {
			continue
		}
		generationRoot := filepath.Join(subscriptionsRoot, subscription.Name(), "generations")
		generations, err := os.ReadDir(generationRoot)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, generation := range generations {
			if !generation.IsDir() || !subscriptionGenerationName.MatchString(generation.Name()) {
				continue
			}
			reference := "subscriptions/" + subscription.Name() + "/generations/" + generation.Name()
			if keep[reference] {
				continue
			}
			path := filepath.Join(generationRoot, generation.Name())
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("subscription generation is not a real directory")
			}
			if err := os.RemoveAll(path); err != nil {
				return err
			}
		}
	}
	return nil
}

func pruneSubscriptionSnapshots(stateRoot string, keep map[string]bool) error {
	entries, err := os.ReadDir(stateRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		match := subscriptionSnapshotName.FindStringSubmatch(entry.Name())
		if len(match) != 2 || keep[match[1]] {
			continue
		}
		path := filepath.Join(stateRoot, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || strings.Contains(entry.Name(), string(filepath.Separator)) {
			return errors.New("subscription snapshot is not a regular state file")
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return nil
}
