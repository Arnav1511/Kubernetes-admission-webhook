package validator

import (
	"fmt"
	"strings"

	"github.com/Arnav1511/k8s-policy-webhook/internal/config"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
)

// Result holds the outcome of a validation check.
type Result struct {
	Allowed  bool
	Messages []string
}

// Validator enforces admission policies against Kubernetes resources.
type Validator struct {
	policy *config.Policy
}

// New creates a Validator with the given policy.
func New(policy *config.Policy) *Validator {
	return &Validator{policy: policy}
}

// ValidatePod runs all pod-level policy checks.
func (v *Validator) ValidatePod(pod *corev1.PodSpec, labels map[string]string, namespace string) Result {
	var messages []string

	// Skip exempt namespaces
	for _, ns := range v.policy.ExemptNamespaces {
		if namespace == ns {
			return Result{Allowed: true}
		}
	}

	// Check all containers (init + regular)
	allContainers := append(pod.Containers, pod.InitContainers...)
	for _, c := range allContainers {
		msgs := v.validateContainer(c)
		messages = append(messages, msgs...)
	}

	// Check required labels
	if len(v.policy.RequireLabels) > 0 {
		msgs := v.validateLabels(labels)
		messages = append(messages, msgs...)
	}
	
	// Block hostNetwork       
	if v.policy.BlockHostNetwork && pod.HostNetwork {
    messages = append(messages, "hostNetwork is not allowed — pods must use cluster networking")
}
	
	return Result{
		Allowed:  len(messages) == 0,
		Messages: messages,
	}
}

// ValidateDeployment runs deployment-level policy checks.
func (v *Validator) ValidateDeployment(deploy *appsv1.Deployment) Result {
	var messages []string

	// Skip exempt namespaces
	for _, ns := range v.policy.ExemptNamespaces {
		if deploy.Namespace == ns {
			return Result{Allowed: true}
		}
	}

	// Check replica count cap
	if v.policy.MaxReplicaCount > 0 && deploy.Spec.Replicas != nil {
		if int(*deploy.Spec.Replicas) > v.policy.MaxReplicaCount {
			messages = append(messages, fmt.Sprintf(
				"replica count %d exceeds maximum allowed %d",
				*deploy.Spec.Replicas, v.policy.MaxReplicaCount,
			))
		}
	}

	// Run pod-level checks on the template
	podResult := v.ValidatePod(
		&deploy.Spec.Template.Spec,
		deploy.Spec.Template.Labels,
		deploy.Namespace,
	)
	messages = append(messages, podResult.Messages...)

	return Result{
		Allowed:  len(messages) == 0,
		Messages: messages,
	}
}

// validateContainer checks a single container against policies.
func (v *Validator) validateContainer(c corev1.Container) []string {
	var msgs []string

	// Block :latest tag or untagged images
	if v.policy.BlockLatestTag {
		if isLatestOrUntagged(c.Image) {
			msgs = append(msgs, fmt.Sprintf(
				"container %q uses image %q — :latest or untagged images are not allowed; pin a specific version",
				c.Name, c.Image,
			))
		}
	}

	// Require resource limits
	if v.policy.RequireResourceLimits {
		if c.Resources.Limits == nil {
			msgs = append(msgs, fmt.Sprintf(
				"container %q has no resource limits — CPU and memory limits are required",
				c.Name,
			))
		} else {
			if _, ok := c.Resources.Limits[corev1.ResourceCPU]; !ok {
				msgs = append(msgs, fmt.Sprintf(
					"container %q is missing CPU limit",
					c.Name,
				))
			}
			if _, ok := c.Resources.Limits[corev1.ResourceMemory]; !ok {
				msgs = append(msgs, fmt.Sprintf(
					"container %q is missing memory limit",
					c.Name,
				))
			}
		}
	}

	// Block privilege escalation
	if v.policy.BlockPrivilegeEscalation {
		if c.SecurityContext != nil {
			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				msgs = append(msgs, fmt.Sprintf(
					"container %q runs in privileged mode — this is not allowed",
					c.Name,
				))
			}
			if c.SecurityContext.AllowPrivilegeEscalation != nil && *c.SecurityContext.AllowPrivilegeEscalation {
				msgs = append(msgs, fmt.Sprintf(
					"container %q allows privilege escalation — set allowPrivilegeEscalation: false",
					c.Name,
				))
			}
		}
	}

	// Block images from banned registries
	for _, reg := range v.policy.BlockedRegistries {
		if strings.HasPrefix(c.Image, reg) {
			msgs = append(msgs, fmt.Sprintf(
				"container %q uses image from blocked registry %q",
				c.Name, reg,
			))
		}
	}

	return msgs
}

// validateLabels checks that required labels are present.
func (v *Validator) validateLabels(labels map[string]string) []string {
	var msgs []string
	for _, required := range v.policy.RequireLabels {
		if val, ok := labels[required]; !ok || val == "" {
			msgs = append(msgs, fmt.Sprintf(
				"required label %q is missing — all pods must include this label",
				required,
			))
		}
	}
	return msgs
}

// isLatestOrUntagged returns true if the image uses :latest or has no tag.
func isLatestOrUntagged(image string) bool {
	// Handle digest references (always pinned)
	if strings.Contains(image, "@sha256:") {
		return false
	}
	parts := strings.Split(image, ":")
	if len(parts) == 1 {
		return true // no tag at all
	}
	return parts[len(parts)-1] == "latest"
}
