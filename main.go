package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/pingcap/log"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	certFile = flag.String("cert-file", "/etc/certs/tls.crt", "Path to TLS certificate file")
	keyFile  = flag.String("key-file", "/etc/certs/tls.key", "Path to TLS private key file")
	port     = flag.Int("port", 8443, "Port to listen on")
	logLevel = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
)

func main() {
	flag.Parse()

	// Set up log
	logger, props, err := log.InitLogger(&log.Config{Level: *logLevel})
	if err != nil {
		panic(err)
	}
	log.ReplaceGlobals(logger, props)

	log.Info("nodelocaldns-admission-controller",
		zap.String("cert-file", *certFile),
		zap.String("key-file", *keyFile),
		zap.Int("port", *port),
		zap.String("log-level", *logLevel),
	)

	// Set up context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Info("Shutdown signal received",
			zap.String("signal", sig.String()),
		)
		cancel()
	}()

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Error("Failed to create kubernetes config", zap.Error(err))
		os.Exit(1)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Error("Failed to create Kubernetes client", zap.Error(err))
		os.Exit(1)
	}
	service, err := client.CoreV1().Services("kube-system").Get(ctx, "kube-dns", metav1.GetOptions{})
	if err != nil {
		log.Error("Failed to discover cluster DNS", zap.Error(err))
		os.Exit(1)
	}
	clusterDNSIP := service.Spec.ClusterIP

	// Load configuration with discovered DNS IP
	webhookConfig, err := LoadConfig(clusterDNSIP)
	if err != nil {
		log.Error("Failed to load configuration", zap.Error(err))
		os.Exit(1)
	}

	// Create webhook server
	server, err := NewServer(ctrl.Log.WithName("admission-controler"), *port, *certFile, *keyFile, webhookConfig)
	if err != nil {
		log.Error("Failed to create webhook server", zap.Error(err))
		os.Exit(1)
	}

	// Start webhook server
	if err := server.Start(ctx); err != nil {
		log.Error("Failed to start webhook server", zap.Error(err))
		os.Exit(1)
	}

	log.Info("Webhook server started", zap.Int("port", *port))

	// Wait for shutdown signal
	<-ctx.Done()

	// Stop webhook server
	if err := server.Stop(context.Background()); err != nil {
		log.Error("Failed to stop webhook server", zap.Error(err))
	}

	log.Info("Webhook server shutdown complete")
}
