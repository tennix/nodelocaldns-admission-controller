package main

import (
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// processAdmissionRequest processes an admission request and returns an admission response
func (s *Server) processAdmissionRequest(req *admissionv1.AdmissionRequest) *admissionv1.AdmissionResponse {
	// Create base response with request UID
	response := &admissionv1.AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	// Only process Pod resources
	if req.Kind.Kind != "Pod" || req.Resource.Resource != "pods" {
		s.logger.V(3).Info("Skipping non-pod resource",
			"kind", req.Kind.Kind,
			"resource", req.Resource.Resource,
		)
		return response
	}

	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		s.logger.Error(err, "Failed to unmarshal pod from request")
		return s.createErrorResponse(string(req.UID), fmt.Sprintf("Failed to parse pod: %v", err))
	}
	podCopy := pod.DeepCopy()
	switch req.Operation {
	case admissionv1.Create: // for create, we need to inject dnsConfig
		domains := []string{
			fmt.Sprintf("%s.svc.%s", pod.Namespace, s.config.ClusterDomain),
			fmt.Sprintf("svc.%s", s.config.ClusterDomain),
			s.config.ClusterDomain,
		}
		dnsConfig := &DNSConfig{
			Nameservers: []string{s.config.NodeLocalDNSAddress, s.config.ClusterDNSAddress},
			Searches:    domains,
			Options:     s.config.DNSOptions,
		}
		if err := injectDNSConfig(podCopy, dnsConfig); err != nil {
			s.logger.Error(err, "DNS injection failed",
				"Name", pod.Name,
				"Namespace", pod.Namespace,
			)

			return s.createErrorResponse(string(req.UID), fmt.Sprintf("Failed to inject DNS configuration: %v", err))
		}
	case admissionv1.Update: // for update, we need to reset the dnsConfig
		var oldPod corev1.Pod
		if err := json.Unmarshal(req.OldObject.Raw, &oldPod); err != nil {
			s.logger.Error(err, "Failed to unmarshal old pod from update request")
			return s.createErrorResponse(string(req.UID), fmt.Sprintf("Failed to parse pod: %v", err))
		}
		// DNSPolicy and DNSConfig is immutable, need to reset to the same as existing pod
		// The generated patch will have no effect
		podCopy.Spec.DNSConfig = oldPod.Spec.DNSConfig
		podCopy.Spec.DNSPolicy = oldPod.Spec.DNSPolicy
	default:
		s.logger.V(3).Info("Skipping non-create/update operation", "operation", string(req.Operation))
		return response
	}
	patch, err := s.generateJSONPatch(&pod, podCopy)
	if err != nil {
		s.logger.Error(err, "Failed to generate patch",
			"Name", pod.Name,
			"Namespace", pod.Namespace,
		)
		return s.createErrorResponse(string(req.UID), fmt.Sprintf("Failed to generate patch: %v", err))
	}

	// Set patch in response
	patchType := admissionv1.PatchTypeJSONPatch
	response.Patch = patch
	response.PatchType = &patchType

	s.logger.V(3).Info("DNS injection successful",
		"Name", pod.Name,
		"Namespace", pod.Namespace,
	)
	return response
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

	s.logger.V(3).Info("Generated JSON patch", "patchOperations", len(patches))

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
