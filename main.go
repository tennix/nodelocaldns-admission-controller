package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2/textlogger"
)

var (
	certFile     = flag.String("cert-file", "/etc/certs/tls.crt", "Path to TLS certificate file")
	keyFile      = flag.String("key-file", "/etc/certs/tls.key", "Path to TLS private key file")
	port         = flag.Int("port", 8443, "Port to listen on")
	logVerbosity = flag.Int("log-verbosity", 1, "Log verbosity")
)

func main() {
	flag.Parse()

	logconf := textlogger.NewConfig(textlogger.Verbosity(*logVerbosity))
	logger := textlogger.NewLogger(logconf)
	logger.Info("nodelocaldns-admission-controller",
		"cert-file", *certFile,
		"key-file", *keyFile,
		"port", *port,
		"log-verbosity", *logVerbosity,
	)

	// Set up context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Shutdown signal received", "signal", sig.String())
		cancel()
	}()

	cfg, err := rest.InClusterConfig()
	if err != nil {
		logger.Error(err, "Failed to create kubernetes config")
		os.Exit(1)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		logger.Error(err, "Failed to create Kubernetes client")
		os.Exit(1)
	}
	service, err := client.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{})
	if err != nil {
		logger.Error(err, "Failed to discover cluster DNS")
		os.Exit(1)
	}
	clusterDNSIP := service.Spec.ClusterIP

	// Load configuration with discovered DNS IP
	webhookConfig, err := LoadConfig(clusterDNSIP)
	if err != nil {
		logger.Error(err, "Failed to load configuration")
		os.Exit(1)
	}

	// Create webhook server
	server, err := NewServer(logger, *port, *certFile, *keyFile, webhookConfig)
	if err != nil {
		logger.Error(err, "Failed to create webhook server")
		os.Exit(1)
	}

	// Start webhook server
	if err := server.Start(ctx); err != nil {
		logger.Error(err, "Failed to start webhook server")
		os.Exit(1)
	}

	logger.Info("Webhook server started", "port", *port)

	// Wait for shutdown signal
	<-ctx.Done()

	// Stop webhook server
	if err := server.Stop(context.Background()); err != nil {
		logger.Error(err, "Failed to stop webhook server")
	}

	logger.Info("Webhook server shutdown complete")
}
