package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/imagebundle"
)

type options struct {
	engine, builder, image, outputDir, inputArchive string
	force                                           bool
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
}

func run() error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	packageBody, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return errors.New("run routeros-image from the project root")
	}
	var packageDocument struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(packageBody, &packageDocument) != nil || packageDocument.Version == "" {
		return errors.New("package.json has no version")
	}
	defaults := options{engine: "auto", image: "sb-gateway:" + packageDocument.Version + "-arm64", outputDir: "dist/routeros"}
	flag.StringVar(&defaults.engine, "engine", defaults.engine, "auto, docker or podman")
	flag.StringVar(&defaults.builder, "builder", "", "project-specific Docker Buildx builder")
	flag.StringVar(&defaults.image, "image", defaults.image, "image tag")
	flag.StringVar(&defaults.outputDir, "output-dir", defaults.outputDir, "bundle output directory")
	flag.StringVar(&defaults.inputArchive, "input-archive", "", "validate and package an existing Docker archive instead of building it")
	flag.BoolVar(&defaults.force, "force", false, "replace a different archive with the same version")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	stagedInput, cleanupInput, err := stageInputArchive(root, defaults.inputArchive)
	if err != nil {
		return err
	}
	defer cleanupInput()
	if err := runReleaseChecks(root); err != nil {
		return err
	}
	var engine string
	if defaults.inputArchive == "" {
		engine, err = selectEngine(defaults.engine)
		if err != nil {
			return err
		}
		if engine == "podman" && !strings.Contains(defaults.image, "/") {
			// Podman canonicalizes unqualified local tags in docker-archive output.
			// Use the canonical name up front so the exported tag is verified exactly.
			defaults.image = "localhost/" + defaults.image
		}
		if defaults.builder != "" && engine != "docker" {
			return errors.New("--builder is supported only with Docker")
		}
	} else if defaults.builder != "" || defaults.engine != "auto" {
		return errors.New("--input-archive cannot be combined with --builder or an explicit --engine")
	}
	output := defaults.outputDir
	if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return err
	}
	archiveName := "sb-gateway-" + packageDocument.Version + "-linux-arm64.tar"
	temporary, err := os.CreateTemp(output, "."+archiveName+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		return err
	}
	_ = os.Remove(temporaryPath)
	defer os.Remove(temporaryPath)
	if defaults.inputArchive != "" {
		if err := copyFile(stagedInput, temporaryPath); err != nil {
			return fmt.Errorf("copy input archive: %w", err)
		}
	} else if defaults.builder != "" {
		revision, source, err := releaseProvenance(root)
		if err != nil {
			return err
		}
		common := imageBuildCommon(packageDocument.Version, revision, source, defaults.image)
		arguments := []string{"buildx", "build", "--builder", defaults.builder, "--provenance=false", "--output", "type=docker,dest=" + temporaryPath}
		arguments = append(arguments, common...)
		arguments = append(arguments, ".")
		if err := command(root, "docker", arguments); err != nil {
			return err
		}
	} else {
		revision, source, err := releaseProvenance(root)
		if err != nil {
			return err
		}
		common := imageBuildCommon(packageDocument.Version, revision, source, defaults.image)
		arguments := imageBuildArguments(engine)
		arguments = append(arguments, common...)
		arguments = append(arguments, ".")
		if err := command(root, engine, arguments); err != nil {
			return err
		}
		platform, err := commandOutput(root, engine, "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", defaults.image)
		if err != nil {
			return err
		}
		if platform != "linux/arm64" {
			return fmt.Errorf("refusing to export %s; expected linux/arm64", platform)
		}
		save := []string{"save"}
		if engine == "podman" {
			save = append(save, "--format", "docker-archive")
		}
		save = append(save, "--output", temporaryPath, defaults.image)
		if err := command(root, engine, save); err != nil {
			return err
		}
	}
	if err := imagebundle.Normalize(temporaryPath); err != nil {
		return err
	}
	details, err := imagebundle.Validate(temporaryPath, defaults.image, packageDocument.Version)
	if err != nil {
		return err
	}
	archiveHash, err := imagebundle.SHA256File(temporaryPath)
	if err != nil {
		return err
	}
	finalArchive := filepath.Join(output, archiveName)
	if existingHash, hashErr := imagebundle.SHA256File(finalArchive); hashErr == nil {
		if existingHash != archiveHash && !defaults.force {
			return fmt.Errorf("%s already exists with a different SHA256; bump version or use --force", archiveName)
		}
		if existingHash == archiveHash {
			_ = os.Remove(temporaryPath)
		} else if err := replaceFile(temporaryPath, finalArchive); err != nil {
			return err
		}
	} else if !errors.Is(hashErr, os.ErrNotExist) {
		return hashErr
	} else if err := replaceFile(temporaryPath, finalArchive); err != nil {
		return err
	}
	info, err := os.Stat(finalArchive)
	if err != nil {
		return err
	}
	manifest := map[string]any{
		"schema": 1, "archive": archiveName, "bytes": info.Size(), "sha256": archiveHash,
		"docker_config": details.DockerConfig, "repo_tags": details.RepoTags, "platform": details.Platform,
		"version": details.Version, "revision": details.Revision, "source": details.Source,
		"xray_version": details.XrayVersion, "xray_revision": details.XrayRevision,
		"lifecycle_version": details.LifecycleVersion, "config_schema_version": details.ConfigSchemaVersion,
		"minimum_config_schema_version": details.MinimumConfigSchemaVersion,
	}
	manifestBody, _ := json.MarshalIndent(manifest, "", "  ")
	if err := atomicWrite(filepath.Join(output, archiveName+".sha256"), []byte(archiveHash+"  "+archiveName+"\n")); err != nil {
		return err
	}
	if err := atomicWrite(filepath.Join(output, "sb-gateway-"+packageDocument.Version+"-linux-arm64.manifest.json"), append(manifestBody, '\n')); err != nil {
		return err
	}
	scriptsOutput := filepath.Join(output, "routeros")
	if err := os.MkdirAll(scriptsOutput, 0o755); err != nil {
		return err
	}
	scripts, err := filepath.Glob(filepath.Join(root, "routeros", "*.rsc"))
	if err != nil {
		return err
	}
	sort.Strings(scripts)
	for _, script := range scripts {
		if err := copyFile(script, filepath.Join(scriptsOutput, filepath.Base(script))); err != nil {
			return err
		}
	}
	fmt.Println("RouterOS WebFig bundle ready:", output)
	fmt.Println("Archive:", archiveName)
	fmt.Println("SHA256:", archiveHash)
	return nil
}

func stageInputArchive(root, input string) (string, func(), error) {
	if input == "" {
		return "", func() {}, nil
	}
	source := input
	if !filepath.IsAbs(source) {
		source = filepath.Join(root, source)
	}
	stagingRoot := filepath.Join(root, ".cache-release", "release-input")
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		return "", func() {}, fmt.Errorf("prepare release input staging: %w", err)
	}
	temporary, err := os.CreateTemp(stagingRoot, ".docker-archive-*.tar")
	if err != nil {
		return "", func() {}, fmt.Errorf("prepare release input staging: %w", err)
	}
	staged := temporary.Name()
	if err := temporary.Close(); err != nil {
		_ = os.Remove(staged)
		return "", func() {}, err
	}
	_ = os.Remove(staged)
	if err := copyFile(source, staged); err != nil {
		_ = os.Remove(staged)
		return "", func() {}, fmt.Errorf("stage input archive: %w", err)
	}
	return staged, func() { _ = os.Remove(staged) }, nil
}

func releaseProvenance(root string) (string, string, error) {
	revision := gitValue(root, []string{"rev-parse", "HEAD"})
	if revision == "" {
		var err error
		revision, err = localRevision(root)
		if err != nil {
			return "", "", err
		}
	}
	source := gitValue(root, []string{"config", "--get", "remote.origin.url"})
	if source == "" {
		source = "local"
	}
	return revision, source, nil
}

func imageBuildCommon(version, revision, source, image string) []string {
	return []string{
		"--platform", "linux/arm64",
		"--build-arg", "SB_GATEWAY_VERSION=" + version,
		"--build-arg", "SB_GATEWAY_REVISION=" + revision,
		"--build-arg", "SB_GATEWAY_SOURCE=" + source,
		"--tag", image,
	}
}

func runReleaseChecks(root string) error {
	fmt.Println("Running mandatory release checks...")
	_, testsErr := os.Stat(filepath.Join(root, "tests"))
	if testsErr == nil {
		if err := runGoReleaseChecks(root, runtime.GOOS); err != nil {
			return fmt.Errorf("Go release checks failed: %w", err)
		}
		if err := command(root, "npm", []string{"run", "lint"}); err != nil {
			return fmt.Errorf("Web lint failed: %w", err)
		}
		if err := command(root, "npm", []string{"test"}); err != nil {
			return fmt.Errorf("Web release checks failed: %w", err)
		}
	} else if !errors.Is(testsErr, os.ErrNotExist) {
		return testsErr
	} else {
		fmt.Println("Public source tree detected; running production build checks without private test material.")
		if err := command(root, "go", []string{"build", "./cmd/..."}); err != nil {
			return fmt.Errorf("Go production build failed: %w", err)
		}
		if err := command(root, "npm", []string{"run", "lint"}); err != nil {
			return fmt.Errorf("Web lint failed: %w", err)
		}
		if err := command(root, "npm", []string{"run", "build"}); err != nil {
			return fmt.Errorf("Web production build failed: %w", err)
		}
	}
	if err := command(root, "npm", []string{"run", "build:static"}); err != nil {
		return fmt.Errorf("Static Web build failed: %w", err)
	}
	return nil
}

func runGoReleaseChecks(root, goos string) error {
	targets := releaseGoTargets()
	if goos != "windows" {
		return command(root, "go", append([]string{"test"}, targets...))
	}

	// Windows file scanners can briefly retain a just-closed TempDir entry.
	// Check packages separately and retry only the failed package once. If the
	// retry contains nothing except Go's TempDir cleanup error, keep the release
	// moving; compilation errors and actual failed tests still stop it.
	listed, err := commandOutput(root, "go", append([]string{"list"}, targets...)...)
	if err != nil {
		return fmt.Errorf("list release packages: %w", err)
	}
	for _, packageName := range strings.Fields(listed) {
		var packageErr error
		var output []byte
		for attempt := 1; attempt <= 2; attempt++ {
			output, packageErr = goTestJSON(root, packageName)
			if packageErr == nil {
				break
			}
			if attempt == 1 {
				fmt.Printf("Retrying Go package once after a transient Windows filesystem failure: %s\n", packageName)
				time.Sleep(750 * time.Millisecond)
			}
		}
		if packageErr != nil {
			if windowsTempDirCleanupOnly(output) {
				fmt.Printf("WARNING: ignoring confirmed Windows TempDir cleanup race after passed test body: %s\n", packageName)
				continue
			}
			return fmt.Errorf("package %s failed twice: %w", packageName, packageErr)
		}
	}
	return nil
}

type goTestEvent struct {
	Action string `json:"Action"`
	Test   string `json:"Test"`
	Output string `json:"Output"`
}

func goTestJSON(root, packageName string) ([]byte, error) {
	cmd := exec.Command("go", "test", "-json", packageName)
	cmd.Dir = root
	body, err := cmd.CombinedOutput()
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		var event goTestEvent
		if json.Unmarshal(line, &event) == nil && event.Output != "" {
			fmt.Print(event.Output)
		}
	}
	if err != nil {
		return body, fmt.Errorf("command failed: go test -json %s: %w", packageName, err)
	}
	return body, nil
}

func windowsTempDirCleanupOnly(body []byte) bool {
	cleanupTests := map[string]bool{}
	failedTests := map[string]bool{}
	cleanupSeen := false
	for _, line := range bytes.Split(body, []byte{'\n'}) {
		var event goTestEvent
		if json.Unmarshal(line, &event) != nil {
			continue
		}
		if strings.Contains(event.Output, "TempDir RemoveAll cleanup:") {
			cleanupSeen = true
			cleanupTests[event.Test] = true
		}
		if event.Action == "fail" && event.Test != "" {
			failedTests[event.Test] = true
		}
		if event.Action == "build-fail" {
			return false
		}
	}
	if !cleanupSeen || len(failedTests) == 0 {
		return false
	}
	for testName := range failedTests {
		covered := cleanupTests[testName]
		if !covered {
			for cleanupTest := range cleanupTests {
				if strings.HasPrefix(cleanupTest, testName+"/") {
					covered = true
					break
				}
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

func releaseGoTargets() []string {
	return []string{"./cmd/...", "./internal/...", "./tests/tools"}
}

func selectEngine(value string) (string, error) {
	if value != "auto" && value != "docker" && value != "podman" {
		return "", errors.New("--engine must be auto, docker or podman")
	}
	if value != "auto" {
		if _, err := exec.LookPath(value); err != nil {
			return "", fmt.Errorf("%s is not available in PATH", value)
		}
		return value, nil
	}
	for _, candidate := range []string{"podman", "docker"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", errors.New("Docker or Podman is required")
}

func imageBuildArguments(engine string) []string {
	if engine == "podman" {
		// Docker archive export cannot recover HEALTHCHECK after an OCI build
		// has already dropped it. Preserve it at the image construction step.
		return []string{"build", "--format", "docker"}
	}
	return []string{"build", "--provenance=false"}
}

func command(root, name string, arguments []string) error {
	cmd := exec.Command(name, arguments...)
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("command failed: %s %s: %w", name, strings.Join(arguments, " "), err)
	}
	return nil
}

func commandOutput(root, name string, arguments ...string) (string, error) {
	cmd := exec.Command(name, arguments...)
	cmd.Dir = root
	cmd.Stderr = os.Stderr
	body, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func gitValue(root string, arguments []string) string {
	value, err := commandOutput(root, "git", arguments...)
	if err != nil {
		return ""
	}
	return value
}

func localRevision(root string) (string, error) {
	hash := sha256.New()
	includedDirectories := map[string]bool{
		"app": true, "build": true, "cmd": true, "internal": true,
		"public": true, "rulesets": true, "scripts": true, "templates": true, "worker": true,
	}
	includedFiles := map[string]bool{
		"Dockerfile": true, "entrypoint.sh": true, "go.mod": true, "go.sum": true,
		"next.config.ts": true, "package-lock.json": true, "package.json": true,
		"postcss.config.mjs": true, "tsconfig.json": true, "vite.config.ts": true,
	}
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		parts := strings.Split(filepath.ToSlash(relative), "/")
		if entry.IsDir() && len(parts) == 1 && !includedDirectories[parts[0]] {
			return filepath.SkipDir
		}
		if !entry.IsDir() && (includedFiles[parts[0]] || includedDirectories[parts[0]]) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	buffer := make([]byte, 1<<20)
	for _, path := range files {
		relative, _ := filepath.Rel(root, path)
		_, _ = io.WriteString(hash, filepath.ToSlash(relative)+"\x00")
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		if _, err := io.CopyBuffer(hash, file, buffer); err != nil {
			file.Close()
			return "", err
		}
		if err := file.Close(); err != nil {
			return "", err
		}
	}
	return "local-sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func atomicWrite(path string, body []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return replaceFile(temporaryPath, path)
}

func replaceFile(source, destination string) error {
	if _, err := os.Stat(destination); err == nil && runtime.GOOS == "windows" {
		if err := os.Remove(destination); err != nil {
			return err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}

func copyFile(source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(destination)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	return errors.Join(copyErr, closeErr)
}
