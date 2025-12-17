package main

import (
	"encoding/json"
	"fmt"
	"time"

	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// processAdmissionRequest processes an admission request and returns an admission response
func (s *Server) processAdmissionRequest(req *admissionv1.AdmissionRequest, startTime time.Time) *admissionv1.AdmissionResponse {
	// Create base response with request UID
	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	// Only process Pod resources
	if req.Kind.Kind != "Pod" || req.Resource.Resource != "pods" {
		s.logger.V(3).Info("Skipping non-pod resource",
			zap.String("kind", req.Kind.Kind),
			zap.String("resource", req.Resource.Resource),
		)
		return response
	}

	// Only process CREATE and UPDATE operations
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		s.logger.V(3).Info("Skipping non-create/update operation",
			zap.String("operation", string(req.Operation)),
		)
		return response
	}

	// Parse pod from request
	pod, err := s.parsePodFromRequest(req)
	if err != nil {
		s.logger.Error(err, "Failed to parse pod from request")
		return s.createErrorResponse(string(req.UID), fmt.Sprintf("Failed to parse pod: %v", err))
	}

	s.logger.Info("Starting DNS injection",
		zap.String("Name", pod.Name),
		zap.String("Namespace", pod.Namespace),
	)

	// Get current configuration
	config := s.config

	// Create DNS configuration for injection
	dnsConfig := s.createDNSConfig(config)

	// Create a copy of the pod for modification
	podCopy := pod.DeepCopy()

	// Inject DNS configuration
	injectionStart := time.Now()
	if err := injectDNSConfig(podCopy, dnsConfig); err != nil {
		s.logger.Error(err, "DNS injection failed",
			zap.String("Name", pod.Name),
			zap.String("Namespace", pod.Namespace),
		)

		return s.createErrorResponse(string(req.UID), fmt.Sprintf("Failed to inject DNS configuration: %v", err))
	}

	// Generate JSON patch for the modifications
	patch, err := s.generateJSONPatch(pod, podCopy)
	if err != nil {
		s.logger.Error(err, "Failed to generate patch",
			zap.String("Name", pod.Name),
			zap.String("Namespace", pod.Namespace),
		)
		return s.createErrorResponse(string(req.UID), fmt.Sprintf("Failed to generate patch: %v", err))
	}

	// Set patch in response
	patchType := admissionv1.PatchTypeJSONPatch
	response.Patch = patch
	response.PatchType = &patchType

	s.logger.Info("DNS injection successful",
		zap.String("Name", pod.Name),
		zap.String("Namespace", pod.Namespace),
		zap.Duration("Duration", time.Since(injectionStart)),
		zap.Int("patchSize", len(patch)),
	)

	return response
}

// parsePodFromRequest extracts a Pod object from the admission request
func (s *Server) parsePodFromRequest(req *admissionv1.AdmissionRequest) (*corev1.Pod, error) {
	var pod corev1.Pod

	if req.Object.Raw == nil {
		return nil, fmt.Errorf("admission request object is nil")
	}

	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pod object: %w", err)
	}

	// Set namespace if not present (for CREATE operations)
	if pod.Namespace == "" && req.Namespace != "" {
		pod.Namespace = req.Namespace
	}

	s.logger.V(3).Info("Successfully parsed pod from request",
		zap.String("podName", pod.Name),
		zap.String("podNamespace", pod.Namespace),
		zap.String("podUID", string(pod.UID)),
	)

	return &pod, nil
}

// createDNSConfig creates a DNS configuration from the webhook configuration
func (s *Server) createDNSConfig(webhookConfig *Config) *DNSConfig {
	// Build nameservers list: [node-local-dns, cluster-dns]
	nameservers := []string{webhookConfig.NodeLocalDNSAddress}
	if webhookConfig.ClusterDNSAddress != "" {
		nameservers = append(nameservers, webhookConfig.ClusterDNSAddress)
	}

	dnsConfig := &DNSConfig{
		Nameservers: nameservers,
		Searches:    webhookConfig.SearchDomains,
		Options:     webhookConfig.DNSOptions,
	}

	s.logger.V(3).Info("Created DNS configuration",
		zap.Strings("nameservers", dnsConfig.Nameservers),
		zap.Strings("searches", dnsConfig.Searches),
		zap.Int("options", len(dnsConfig.Options)),
	)

	return dnsConfig
}

// generateJSONPatch generates a JSON patch between original and modified pods
func (s *Server) generateJSONPatch(original, modified *corev1.Pod) ([]byte, error) {
	// Create JSON patch operations
	var patches []map[string]interface{}

	// Add DNS policy change
	patches = append(patches, map[string]interface{}{
		"op":    "replace",
		"path":  "/spec/dnsPolicy",
		"value": string(corev1.DNSNone),
	})

	// Add DNS configuration
	if modified.Spec.DNSConfig != nil {
		patches = append(patches, map[string]interface{}{
			"op":    "add",
			"path":  "/spec/dnsConfig",
			"value": modified.Spec.DNSConfig,
		})
	}

	// Marshal patches to JSON
	patchBytes, err := json.Marshal(patches)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON patch: %w", err)
	}

	s.logger.V(3).Info("Generated JSON patch",
		zap.Int("patchOperations", len(patches)),
		zap.Int("patchSize", len(patchBytes)),
	)

	return patchBytes, nil
}

// createErrorResponse creates an admission response that denies the request with an error
func (s *Server) createErrorResponse(uid string, message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		UID:     types.UID(uid),
		Allowed: false,
		Result: &metav1.Status{
			Code:    400,
			Message: message,
		},
	}
}

func injectDNSConfig(pod *corev1.Pod, dnsConfig *DNSConfig) error {
	if pod == nil || pod.Spec.DNSConfig != nil {
		// Skip injection if pod is nil or already has DNS configuration
		return nil
	}

	// Skip injection if dnsPolicy is explicitly set to None
	if pod.Spec.DNSPolicy == corev1.DNSNone {
		return nil
	}
	// Skip injection if hostnetwork but without DNSClusterFirstWithHostNet policy
	if pod.Spec.HostNetwork && pod.Spec.DNSPolicy != corev1.DNSClusterFirstWithHostNet {
		return nil
	}
	// Create a copy of the pod to avoid modifying the original
	podCopy := pod.DeepCopy()

	// Set DNS policy to None to use custom DNS configuration
	podCopy.Spec.DNSPolicy = corev1.DNSNone

	// Create DNS configuration for Kubernetes
	podDNSConfig := &corev1.PodDNSConfig{
		Nameservers: make([]string, len(dnsConfig.Nameservers)),
		Searches:    make([]string, len(dnsConfig.Searches)),
		Options:     make([]corev1.PodDNSConfigOption, len(dnsConfig.Options)),
	}

	// Copy nameservers
	copy(podDNSConfig.Nameservers, dnsConfig.Nameservers)

	// Copy search domains
	copy(podDNSConfig.Searches, dnsConfig.Searches)

	// Copy DNS options - convert from config.DNSOption to corev1.PodDNSConfigOption
	for i, opt := range dnsConfig.Options {
		value := opt.Value // Create a copy to avoid pointer issues
		podDNSConfig.Options[i] = corev1.PodDNSConfigOption{
			Name:  opt.Name,
			Value: &value,
		}
	}

	// Assign the DNS configuration to the pod
	podCopy.Spec.DNSConfig = podDNSConfig

	// Copy the modified pod back to the original
	*pod = *podCopy

	return nil
}
