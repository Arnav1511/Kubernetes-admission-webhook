package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	yaml := `blockLatestTag: true
requireResourceLimits: false
requireLabels:
  - app
  - owner
blockHostNetwork: true
blockedRegistries:
  - docker.io
blockPrivilegeEscalation: true
maxReplicaCount: 5
exemptNamespaces:
  - kube-system
`
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if !p.BlockLatestTag {
		t.Error("BlockLatestTag: got false, want true")
	}
	if p.RequireResourceLimits {
		t.Error("RequireResourceLimits: got true, want false")
	}
	if len(p.RequireLabels) != 2 || p.RequireLabels[0] != "app" || p.RequireLabels[1] != "owner" {
		t.Errorf("RequireLabels: got %v, want [app owner]", p.RequireLabels)
	}
	if p.MaxReplicaCount != 5 {
		t.Errorf("MaxReplicaCount: got %d, want 5", p.MaxReplicaCount)
	}
	if len(p.ExemptNamespaces) != 1 || p.ExemptNamespaces[0] != "kube-system" {
		t.Errorf("ExemptNamespaces: got %v, want [kube-system]", p.ExemptNamespaces)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("Load on a missing file returned nil error, want error")
	}
}

func TestLoadMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("blockLatestTag: [unclosed\n"), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load on malformed YAML returned nil error, want error")
	}
}

// An empty policy file must not silently become an enforcing policy.
func TestLoadEmptyFileYieldsZeroPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	p, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if p.BlockLatestTag || p.RequireResourceLimits || p.BlockHostNetwork || p.BlockPrivilegeEscalation {
		t.Errorf("empty file should yield a zero-value policy, got %+v", p)
	}
}

func TestDefaultIsEnforcing(t *testing.T) {
	p := Default()

	if !p.BlockLatestTag {
		t.Error("Default BlockLatestTag: got false, want true")
	}
	if !p.RequireResourceLimits {
		t.Error("Default RequireResourceLimits: got false, want true")
	}
	if !p.BlockHostNetwork {
		t.Error("Default BlockHostNetwork: got false, want true")
	}
	if !p.BlockPrivilegeEscalation {
		t.Error("Default BlockPrivilegeEscalation: got false, want true")
	}
	if len(p.ExemptNamespaces) == 0 {
		t.Error("Default ExemptNamespaces: got empty, want kube-system and friends")
	}
}
