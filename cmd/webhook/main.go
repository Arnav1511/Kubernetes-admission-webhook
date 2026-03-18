package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Arnav1511/k8s-policy-webhook/internal/config"
	"github.com/Arnav1511/k8s-policy-webhook/internal/handler"
	"go.uber.org/zap"
)

func main() {
	var (
		port     int
		certFile string
		keyFile  string
		cfgFile  string
	)

	flag.IntVar(&port, "port", 8443, "Webhook server port")
	flag.StringVar(&certFile, "cert", "/etc/webhook/certs/tls.crt", "TLS certificate file")
	flag.StringVar(&keyFile, "key", "/etc/webhook/certs/tls.key", "TLS key file")
	flag.StringVar(&cfgFile, "config", "/etc/webhook/config/policy.yaml", "Policy config file")
	flag.Parse()

	// Initialize structured logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Load policy configuration
	policyCfg, err := config.Load(cfgFile)
	if err != nil {
		sugar.Warnw("Failed to load config, using defaults", "error", err)
		policyCfg = config.Default()
	}
	sugar.Infow("Policy configuration loaded",
		"blocked_registries", policyCfg.BlockedRegistries,
		"require_resource_limits", policyCfg.RequireResourceLimits,
		"require_labels", policyCfg.RequireLabels,
		"block_latest_tag", policyCfg.BlockLatestTag,
		"block_privilege_escalation", policyCfg.BlockPrivilegeEscalation,
	)

	// Load TLS certs
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		sugar.Fatalw("Failed to load TLS certificates", "error", err)
	}

	// Setup HTTP handler
	wh := handler.NewWebhookHandler(policyCfg, sugar)

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", wh.Validate)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sugar.Infow("Starting webhook server", "port", port)
		if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			sugar.Fatalw("Server failed", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	sugar.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		sugar.Fatalw("Server forced shutdown", "error", err)
	}
	sugar.Info("Server exited cleanly")
}
