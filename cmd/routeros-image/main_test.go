package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWindowsTempDirCleanupOnly(t *testing.T) {
	cleanup := []byte(
		`{"Action":"output","Test":"TestRelease/subtest","Output":"    testing.go:1617: TempDir RemoveAll cleanup: remove C:\\\\tmp: directory is not empty\\n"}` + "\n" +
			`{"Action":"fail","Test":"TestRelease/subtest"}` + "\n" +
			`{"Action":"fail","Test":"TestRelease"}` + "\n" +
			`{"Action":"fail","Package":"example.test"}` + "\n",
	)
	if !windowsTempDirCleanupOnly(cleanup) {
		t.Fatal("confirmed TempDir cleanup race was not recognized")
	}

	assertion := append([]byte{}, cleanup...)
	assertion = append(assertion, []byte(`{"Action":"fail","Test":"TestOther"}`+"\n")...)
	if windowsTempDirCleanupOnly(assertion) {
		t.Fatal("an unrelated failed test must not be treated as a cleanup race")
	}

	buildFailure := []byte(`{"Action":"build-fail","ImportPath":"example.test"}` + "\n")
	if windowsTempDirCleanupOnly(buildFailure) {
		t.Fatal("a build failure must stop the release")
	}
}

func TestGoReleaseChecksKeepTheFullPackageBoundary(t *testing.T) {
	want := []string{"./cmd/...", "./internal/...", "./tests/tools"}
	got := releaseGoTargets()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestImageBuildArgumentsPreserveDockerHealthcheck(t *testing.T) {
	for engine, want := range map[string][]string{
		"podman": {"build", "--format", "docker"},
		"docker": {"build", "--provenance=false"},
	} {
		if got := imageBuildArguments(engine); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %v, want %v", engine, got, want)
		}
	}
}

func TestImageBuildCommonPinsReleaseProvenance(t *testing.T) {
	want := []string{
		"--platform", "linux/arm64",
		"--build-arg", "SB_GATEWAY_VERSION=1.6.0",
		"--build-arg", "SB_GATEWAY_REVISION=abc123",
		"--build-arg", "SB_GATEWAY_SOURCE=https://github.com/example/project",
		"--tag", "sb-gateway:1.6.0-arm64",
	}
	got := imageBuildCommon("1.6.0", "abc123", "https://github.com/example/project", "sb-gateway:1.6.0-arm64")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestStageInputArchiveSurvivesSourceRemoval(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "dist", "raw.tar")
	if err := os.MkdirAll(filepath.Dir(source), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("docker archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	staged, cleanup, err := stageInputArchive(root, filepath.Join("dist", "raw.tar"))
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := os.RemoveAll(filepath.Join(root, "dist")); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(staged)
	if err != nil || string(body) != "docker archive" {
		t.Fatalf("staged archive was not preserved: body=%q err=%v", body, err)
	}
	if filepath.Dir(staged) != filepath.Join(root, ".cache-release", "release-input") {
		t.Fatalf("archive staged outside isolated release cache: %s", staged)
	}
}
