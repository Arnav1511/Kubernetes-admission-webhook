package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Policy defines the admission policies to enforce.
type Policy struct {
	// BlockLatestTag rejects pods using :latest or untagged images
	BlockLatestTag bool `yaml:"blockLatestTag"`

	// RequireResourceLimits rejects containers without CPU/memory limits
	RequireResourceLimits bool `yaml:"requireResourceLimits"`

	// RequireLabels lists labels that must be present on every pod
	RequireLabels []string `yaml:"requireLabels"`

	// BlockedRegistries rejects images from these registries
	BlockedRegistries []string `yaml:"blockedRegistries"`

	// BlockPrivilegeEscalation rejects containers with privileged mode or escalation
	BlockPrivilegeEscalation bool `yaml:"blockPrivilegeEscalation"`

	// MaxReplicaCount caps the number of replicas in a Deployment (0 = no limit)
	MaxReplicaCount int `yaml:"maxReplicaCount"`

	// ExemptNamespaces are namespaces excluded from policy enforcement
	ExemptNamespaces []string `yaml:"exemptNamespaces"`
}

// Load reads a policy config from a YAML file.
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// Default returns a sensible default policy.
func Default() *Policy {
	return &Policy{
		BlockLatestTag:           true,
		RequireResourceLimits:    true,
		RequireLabels:            []string{"app", "owner"},
		BlockedRegistries:        []string{},
		BlockPrivilegeEscalation: true,
		MaxReplicaCount:          0,
		ExemptNamespaces:         []string{"kube-system", "kube-public", "argocd"},
	}
}
