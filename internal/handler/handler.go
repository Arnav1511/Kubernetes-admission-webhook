package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Arnav1511/k8s-policy-webhook/internal/config"
	"github.com/Arnav1511/k8s-policy-webhook/internal/validator"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var (
	scheme = runtime.NewScheme()
	codecs = serializer.NewCodecFactory(scheme)
)

// WebhookHandler handles admission review requests.
type WebhookHandler struct {
	validator *validator.Validator
	logger    *zap.SugaredLogger
}

// NewWebhookHandler creates a handler with the given policy and logger.
func NewWebhookHandler(policy *config.Policy, logger *zap.SugaredLogger) *WebhookHandler {
	return &WebhookHandler{
		validator: validator.New(policy),
		logger:    logger,
	}
}

// Validate processes a ValidatingAdmissionWebhook request.
func (wh *WebhookHandler) Validate(w http.ResponseWriter, r *http.Request) {
	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		wh.logger.Errorw("Failed to read request body", "error", err)
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}

	// Deserialize AdmissionReview
	var admissionReview admissionv1.AdmissionReview
	if err := json.Unmarshal(body, &admissionReview); err != nil {
		wh.logger.Errorw("Failed to unmarshal admission review", "error", err)
		http.Error(w, "failed to unmarshal request", http.StatusBadRequest)
		return
	}

	req := admissionReview.Request
	if req == nil {
		http.Error(w, "empty admission request", http.StatusBadRequest)
		return
	}

	wh.logger.Infow("Processing admission request",
		"uid", req.UID,
		"kind", req.Kind.Kind,
		"namespace", req.Namespace,
		"name", req.Name,
		"operation", req.Operation,
	)

	// Validate based on resource kind
	var result validator.Result
	switch req.Kind.Kind {
	case "Pod":
		var pod corev1.Pod
		if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
			wh.sendError(w, req.UID, fmt.Sprintf("failed to decode Pod: %v", err))
			return
		}
		result = wh.validator.ValidatePod(&pod.Spec, pod.Labels, req.Namespace)

	case "Deployment":
		var deploy appsv1.Deployment
		if err := json.Unmarshal(req.Object.Raw, &deploy); err != nil {
			wh.sendError(w, req.UID, fmt.Sprintf("failed to decode Deployment: %v", err))
			return
		}
		result = wh.validator.ValidateDeployment(&deploy)

	default:
		// Allow unknown resource types
		result = validator.Result{Allowed: true}
	}

	// Log the decision
	if result.Allowed {
		wh.logger.Infow("Admission ALLOWED",
			"uid", req.UID,
			"kind", req.Kind.Kind,
			"name", req.Name,
			"namespace", req.Namespace,
		)
	} else {
		wh.logger.Warnw("Admission DENIED",
			"uid", req.UID,
			"kind", req.Kind.Kind,
			"name", req.Name,
			"namespace", req.Namespace,
			"violations", result.Messages,
		)
	}

	// Build response
	response := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: &admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: result.Allowed,
		},
	}

	if !result.Allowed {
		response.Response.Result = &metav1.Status{
			Code:    http.StatusForbidden,
			Message: "Policy violation: " + strings.Join(result.Messages, "; "),
		}
	}

	respBytes, err := json.Marshal(response)
	if err != nil {
		wh.logger.Errorw("Failed to marshal response", "error", err)
		http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}

// sendError sends an error admission response.
func (wh *WebhookHandler) sendError(w http.ResponseWriter, uid interface{}, msg string) {
	wh.logger.Errorw("Admission error", "message", msg)
	resp := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Code:    http.StatusInternalServerError,
				Message: msg,
			},
		},
	}
	respBytes, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBytes)
}
