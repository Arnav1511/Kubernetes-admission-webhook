package validator

import (
	"testing"

	"github.com/Arnav1511/k8s-policy-webhook/internal/config"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func boolPtr(b bool) *bool { return &b }

func TestBlockLatestTag(t *testing.T) {
	v := New(&config.Policy{BlockLatestTag: true})

	tests := []struct {
		name    string
		image   string
		allowed bool
	}{
		{"explicit latest", "nginx:latest", false},
		{"no tag", "nginx", false},
		{"pinned tag", "nginx:1.25.3", true},
		{"sha256 digest", "nginx@sha256:abc123", true},
		{"registry with port and latest", "registry.io:5000/app:latest", false},
		{"registry with port and tag", "registry.io:5000/app:v1.2", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "test", Image: tt.image}},
			}
			result := v.ValidatePod(pod, map[string]string{}, "default")
			if result.Allowed != tt.allowed {
				t.Errorf("image %q: got allowed=%v, want %v. Messages: %v",
					tt.image, result.Allowed, tt.allowed, result.Messages)
			}
		})
	}
}

func TestRequireResourceLimits(t *testing.T) {
	v := New(&config.Policy{RequireResourceLimits: true})

	tests := []struct {
		name    string
		limits  corev1.ResourceList
		allowed bool
	}{
		{
			"both limits set",
			corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("100m"),
				corev1.ResourceMemory: resource.MustParse("128Mi"),
			},
			true,
		},
		{"no limits", nil, false},
		{
			"only cpu",
			corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m")},
			false,
		},
		{
			"only memory",
			corev1.ResourceList{corev1.ResourceMemory: resource.MustParse("128Mi")},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:  "test",
					Image: "nginx:1.25",
					Resources: corev1.ResourceRequirements{
						Limits: tt.limits,
					},
				}},
			}
			result := v.ValidatePod(pod, map[string]string{}, "default")
			if result.Allowed != tt.allowed {
				t.Errorf("limits %v: got allowed=%v, want %v. Messages: %v",
					tt.limits, result.Allowed, tt.allowed, result.Messages)
			}
		})
	}
}

func TestRequireLabels(t *testing.T) {
	v := New(&config.Policy{RequireLabels: []string{"app", "owner"}})

	tests := []struct {
		name    string
		labels  map[string]string
		allowed bool
	}{
		{"all labels present", map[string]string{"app": "web", "owner": "team-a"}, true},
		{"missing owner", map[string]string{"app": "web"}, false},
		{"empty labels", map[string]string{}, false},
		{"empty value", map[string]string{"app": "web", "owner": ""}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "test", Image: "nginx:1.25"}},
			}
			result := v.ValidatePod(pod, tt.labels, "default")
			if result.Allowed != tt.allowed {
				t.Errorf("labels %v: got allowed=%v, want %v. Messages: %v",
					tt.labels, result.Allowed, tt.allowed, result.Messages)
			}
		})
	}
}

func TestBlockPrivilegeEscalation(t *testing.T) {
	v := New(&config.Policy{BlockPrivilegeEscalation: true})

	tests := []struct {
		name    string
		sc      *corev1.SecurityContext
		allowed bool
	}{
		{"no security context", nil, true},
		{"privileged true", &corev1.SecurityContext{Privileged: boolPtr(true)}, false},
		{"privileged false", &corev1.SecurityContext{Privileged: boolPtr(false)}, true},
		{"escalation true", &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(true)}, false},
		{"escalation false", &corev1.SecurityContext{AllowPrivilegeEscalation: boolPtr(false)}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.PodSpec{
				Containers: []corev1.Container{{
					Name:            "test",
					Image:           "nginx:1.25",
					SecurityContext: tt.sc,
				}},
			}
			result := v.ValidatePod(pod, map[string]string{}, "default")
			if result.Allowed != tt.allowed {
				t.Errorf("got allowed=%v, want %v. Messages: %v",
					result.Allowed, tt.allowed, result.Messages)
			}
		})
	}
}

func TestExemptNamespaces(t *testing.T) {
	v := New(&config.Policy{
		BlockLatestTag:    true,
		ExemptNamespaces:  []string{"kube-system"},
	})

	// This would normally fail (no tag) but kube-system is exempt
	pod := &corev1.PodSpec{
		Containers: []corev1.Container{{Name: "test", Image: "nginx"}},
	}
	result := v.ValidatePod(pod, map[string]string{}, "kube-system")
	if !result.Allowed {
		t.Errorf("kube-system should be exempt, got denied: %v", result.Messages)
	}
}

func TestBlockHostNetwork(t *testing.T) {
    v := New(&config.Policy{BlockHostNetwork: true})

    tests := []struct {
        name        string
        hostNetwork bool
        allowed     bool
    }{
        {"hostNetwork true", true, false},
        {"hostNetwork false", false, true},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            pod := &corev1.PodSpec{
                HostNetwork: tt.hostNetwork,
                Containers:  []corev1.Container{{Name: "test", Image: "nginx:1.25"}},
            }
            result := v.ValidatePod(pod, map[string]string{}, "default")
            if result.Allowed != tt.allowed {
                t.Errorf("got allowed=%v, want %v", result.Allowed, tt.allowed)
            }
        })
    }
}

func TestBlockedRegistries(t *testing.T) {
	v := New(&config.Policy{
		BlockedRegistries: []string{"untrusted.io/", "docker.io/sketchy/"},
	})

	tests := []struct {
		name    string
		image   string
		allowed bool
	}{
		{"blocked registry", "untrusted.io/myapp:v1", false},
		{"blocked org", "docker.io/sketchy/thing:v1", false},
		{"allowed registry", "gcr.io/myproject/app:v1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pod := &corev1.PodSpec{
				Containers: []corev1.Container{{Name: "test", Image: tt.image}},
			}
			result := v.ValidatePod(pod, map[string]string{}, "default")
			if result.Allowed != tt.allowed {
				t.Errorf("image %q: got allowed=%v, want %v", tt.image, result.Allowed, tt.allowed)
			}
		})
	}
}
