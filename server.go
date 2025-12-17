package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// HTTP timeouts
	ReadTimeout  = 5 * time.Second
	WriteTimeout = 5 * time.Second
	IdleTimeout  = 60 * time.Second

	// Content type for admission requests/responses
	ContentTypeJSON = "application/json"

	// Admission webhook paths
	InjectPath = "/inject"
	HealthPath = "/health"
	ReadyPath  = "/ready"
)

// Server implements the WebhookServer interface
type Server struct {
	logger   logr.Logger
	server   *http.Server
	config   *Config
	port     int
	certFile string
	keyFile  string
}

// NewServer creates a new webhook server
func NewServer(logger logr.Logger, port int, certFile, keyFile string, cfg *Config) (*Server, error) {
	server := &Server{
		config:   cfg,
		port:     port,
		certFile: certFile,
		keyFile:  keyFile,
	}

	// Create HTTP server with TLS configuration
	mux := http.NewServeMux()
	mux.HandleFunc(InjectPath, server.HandleInject)
	mux.HandleFunc(HealthPath, server.handleHealth)
	mux.HandleFunc(ReadyPath, server.handleReady)

	server.server = &http.Server{
		Addr:         ":" + strconv.Itoa(port),
		Handler:      mux,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return server, nil
}

// Start begins serving the webhook server
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting webhook server",
		zap.Int("port", s.port),
		zap.String("certFile", s.certFile),
		zap.String("keyFile", s.keyFile),
	)

	// Validate TLS certificate files
	if err := s.validateCertificates(); err != nil {
		s.logger.Error(err, "Certificate validation failed")
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := s.server.ListenAndServeTLS(s.certFile, s.keyFile); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("failed to start HTTPS server: %w", err)
		}
	}()

	// Wait for either context cancellation or server error
	select {
	case <-ctx.Done():
		s.logger.Info("Context cancelled, shutting down server")
		return s.Stop(context.Background())
	case err := <-errChan:
		s.logger.Error(err, "Server failed to start")
		return err
	case <-time.After(2 * time.Second):
		// Server started successfully
		s.logger.Info("Webhook server started successfully", zap.Int("port", s.port))
		return nil
	}
}

// Stop gracefully shuts down the webhook server
func (s *Server) Stop(ctx context.Context) error {
	s.logger.Info("Stopping webhook server")

	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := s.server.Shutdown(shutdownCtx); err != nil {
		s.logger.Error(err, "Failed to gracefully shutdown server")
		return fmt.Errorf("failed to shutdown server: %w", err)
	}

	s.logger.Info("Webhook server stopped successfully")
	return nil
}

// HandleInject processes admission requests for DNS configuration injection
func (s *Server) HandleInject(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	s.logger.Info("Processing admission request",
		zap.String("method", r.Method),
		zap.String("url", r.URL.Path),
	)

	// Validate request method
	if r.Method != http.MethodPost {
		s.logger.Error(fmt.Errorf("method not allowed"), "Invalid request method", zap.String("method", r.Method))
		s.writeErrorResponse(w, http.StatusMethodNotAllowed, "Only POST method is allowed")
		return
	}

	// Validate content type
	contentType := r.Header.Get("Content-Type")
	if contentType != ContentTypeJSON {
		s.logger.Error(fmt.Errorf("content type mismatch"), "Invalid content type", zap.String("contentType", contentType))
		s.writeErrorResponse(w, http.StatusBadRequest, "Content-Type must be application/json")
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Error(err, "Failed to read request body")
		s.writeErrorResponse(w, http.StatusBadRequest, "Failed to read request body")
		return
	}
	defer r.Body.Close()

	// Parse admission review request
	admissionReview, err := s.parseAdmissionReview(body)
	if err != nil {
		s.logger.Error(err, "Failed to parse admission review")
		s.writeErrorResponse(w, http.StatusBadRequest, fmt.Sprintf("Failed to parse admission review: %v", err))
		return
	}

	// Process the admission request
	response := s.processAdmissionRequest(admissionReview.Request, startTime)

	// Create admission review response
	admissionResponse := &admissionv1.AdmissionReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admission.k8s.io/v1",
			Kind:       "AdmissionReview",
		},
		Response: response,
	}

	// Marshal response
	responseBytes, err := json.Marshal(admissionResponse)
	if err != nil {
		s.logger.Error(err, "Failed to marshal response")
		s.writeErrorResponse(w, http.StatusInternalServerError, "Failed to marshal response")
		return
	}

	// Write response
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(responseBytes); err != nil {
		s.logger.Error(err, "Failed to write response")
	}

	// Log response
	result := "success"
	if !response.Allowed {
		result = "failure"
	}
	s.logger.Info("Admission request processed",
		zap.Duration("Duration", time.Since(startTime)),
		zap.String("result", result),
		zap.Bool("allowed", response.Allowed),
	)
}

// validateCertificates validates that the TLS certificate files exist and are valid
func (s *Server) validateCertificates() error {
	// Load certificate to validate it
	cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate pair: %w", err)
	}

	// Basic validation - ensure certificate is not nil
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("certificate is empty")
	}

	s.logger.Info("TLS certificates validated successfully",
		zap.String("certFile", s.certFile),
		zap.String("keyFile", s.keyFile),
	)

	return nil
}

// parseAdmissionReview parses the admission review from request body
func (s *Server) parseAdmissionReview(body []byte) (*admissionv1.AdmissionReview, error) {
	var admissionReview admissionv1.AdmissionReview

	if err := json.Unmarshal(body, &admissionReview); err != nil {
		return nil, fmt.Errorf("failed to unmarshal admission review: %w", err)
	}

	// Validate admission review structure
	if admissionReview.Request == nil {
		return nil, fmt.Errorf("admission review request is nil")
	}

	if admissionReview.Request.UID == "" {
		return nil, fmt.Errorf("admission review request UID is empty")
	}

	s.logger.V(3).Info("Parsed admission review request",
		zap.String("uid", string(admissionReview.Request.UID)),
		zap.String("kind", admissionReview.Request.Kind.Kind),
		zap.String("resource", admissionReview.Request.Resource.Resource),
		zap.String("operation", string(admissionReview.Request.Operation)),
		zap.String("namespace", admissionReview.Request.Namespace),
		zap.String("name", admissionReview.Request.Name),
	)

	return &admissionReview, nil
}

// writeErrorResponse writes an error response to the client
func (s *Server) writeErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	s.logger.Info("Writing error response",
		zap.Int("statusCode", statusCode),
		zap.String("message", message),
	)

	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(statusCode)

	errorResponse := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    statusCode,
			"message": message,
		},
	}

	if err := json.NewEncoder(w).Encode(errorResponse); err != nil {
		s.logger.Error(err, "Failed to write error response")
	}
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"status": "healthy",
		"time":   time.Now().UTC().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// handleReady handles readiness check requests
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// Configuration is loaded at startup, so we're always ready if the server is running
	w.Header().Set("Content-Type", ContentTypeJSON)
	w.WriteHeader(http.StatusOK)

	response := map[string]string{
		"status": "ready",
		"time":   time.Now().UTC().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(response)
}

// generateRequestID generates a unique request ID for logging
func generateRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}
