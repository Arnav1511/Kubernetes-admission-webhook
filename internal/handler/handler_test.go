package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Arnav1511/k8s-policy-webhook/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
)

func TestValidateResponsesEchoRequestUID(t *testing.T) {
	tests := []struct {
		name        string
		uid         types.UID
		body        []byte
		wantAllowed bool
	}{
		{
			name:        "allowed pod",
			uid:         "allowed-uid",
			body:        admissionReviewBody(t, "allowed-uid", rawPod(t, goodPod())),
			wantAllowed: true,
		},
		{
			name:        "policy denied pod",
			uid:         "denied-uid",
			body:        admissionReviewBody(t, "denied-uid", rawPod(t, badPod())),
			wantAllowed: false,
		},
		{
			name:        "decode error pod",
			uid:         "decode-error-uid",
			body:        malformedPodAdmissionReviewBody("decode-error-uid"),
			wantAllowed: false,
		},
	}

	wh := NewWebhookHandler(testPolicy(), zap.NewNop().Sugar())

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/validate", bytes.NewReader(tt.body))

			wh.Validate(rec, req)

			resp := decodeAdmissionReview(t, rec)
			if resp.APIVersion != "admission.k8s.io/v1" || resp.Kind != "AdmissionReview" {
				t.Fatalf("got %s %s, want admission.k8s.io/v1 AdmissionReview", resp.APIVersion, resp.Kind)
			}
			if resp.Response == nil {
				t.Fatal("response is nil")
			}
			if resp.Response.UID != tt.uid {
				t.Fatalf("got UID %q, want %q", resp.Response.UID, tt.uid)
			}
			if resp.Response.Allowed != tt.wantAllowed {
				t.Fatalf("got allowed=%v, want %v", resp.Response.Allowed, tt.wantAllowed)
			}
			if got := rec.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("got content type %q, want application/json", got)
			}
		})
	}
}

func TestWriteAdmissionReviewLogsWriteErrors(t *testing.T) {
	core, logs := observer.New(zap.ErrorLevel)
	wh := NewWebhookHandler(testPolicy(), zap.New(core).Sugar())

	wh.writeAdmissionReview(errorResponseWriter{}, &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: &admissionv1.AdmissionResponse{UID: "write-error", Allowed: true},
	})

	if logs.FilterMessage("Failed to write admission review response").Len() != 1 {
		t.Fatalf("expected one write error log, got %d entries", logs.Len())
	}
}

func testPolicy() *config.Policy {
	return &config.Policy{
		BlockLatestTag:           true,
		RequireResourceLimits:    true,
		RequireLabels:            []string{"app", "owner"},
		BlockHostNetwork:         true,
		BlockPrivilegeEscalation: true,
	}
}

func goodPod() corev1.Pod {
	allowPrivilegeEscalation := false
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "good-pod",
			Namespace: "default",
			Labels: map[string]string{
				"app":   "demo",
				"owner": "platform",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:  "web",
				Image: "nginx:1.25.3",
				Resources: corev1.ResourceRequirements{
					Limits: corev1.ResourceList{
						corev1.ResourceCPU:    resource.MustParse("100m"),
						corev1.ResourceMemory: resource.MustParse("128Mi"),
					},
				},
				SecurityContext: &corev1.SecurityContext{
					AllowPrivilegeEscalation: &allowPrivilegeEscalation,
				},
			}},
		},
	}
}

func badPod() corev1.Pod {
	pod := goodPod()
	pod.Name = "bad-pod"
	pod.Spec.Containers[0].Image = "nginx:latest"
	return pod
}

func rawPod(t *testing.T, pod corev1.Pod) runtime.RawExtension {
	t.Helper()
	raw, err := json.Marshal(pod)
	if err != nil {
		t.Fatalf("marshal pod: %v", err)
	}
	return runtime.RawExtension{Raw: raw}
}

func admissionReviewBody(t *testing.T, uid types.UID, object runtime.RawExtension) []byte {
	t.Helper()
	review := admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Request: &admissionv1.AdmissionRequest{
			UID:       uid,
			Kind:      metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"},
			Resource:  metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"},
			Namespace: "default",
			Operation: admissionv1.Create,
			Object:    object,
		},
	}
	raw, err := json.Marshal(review)
	if err != nil {
		t.Fatalf("marshal admission review: %v", err)
	}
	return raw
}

func malformedPodAdmissionReviewBody(uid types.UID) []byte {
	return []byte(fmt.Sprintf(`{
		"apiVersion":"admission.k8s.io/v1",
		"kind":"AdmissionReview",
		"request":{
			"uid":%q,
			"kind":{"group":"","version":"v1","kind":"Pod"},
			"resource":{"group":"","version":"v1","resource":"pods"},
			"namespace":"default",
			"operation":"CREATE",
			"object":"not-a-pod-object"
		}
	}`, uid))
}

func decodeAdmissionReview(t *testing.T, rec *httptest.ResponseRecorder) admissionv1.AdmissionReview {
	t.Helper()
	var resp admissionv1.AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
	return resp
}

type errorResponseWriter struct{}

func (errorResponseWriter) Header() http.Header {
	return http.Header{}
}

func (errorResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced write error")
}

func (errorResponseWriter) WriteHeader(int) {}

var _ http.ResponseWriter = errorResponseWriter{}

func TestDecodeAdmissionReviewRejectsNonJSON(t *testing.T) {
	wh := NewWebhookHandler(testPolicy(), zap.NewNop().Sugar())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{"))

	wh.Validate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
