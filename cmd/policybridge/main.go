package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/policybridge/policybridge/internal/api"
	"github.com/policybridge/policybridge/internal/session"
)

//go:embed all:static
var staticFS embed.FS

func main() {
	if len(os.Args) > 1 && os.Args[1] == "-healthcheck" {
		if err := runHealthcheck(); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	addr := getEnv("POLICYBRIDGE_LISTEN_ADDR", "127.0.0.1")
	port := getEnv("POLICYBRIDGE_LISTEN_PORT", "8080")
	listenAddr := fmt.Sprintf("%s:%s", addr, port)

	api.WarnIfExposed(listenAddr)

	tempRoot := os.TempDir()
	store := session.NewStore(tempRoot, session.DefaultIdleTimeout)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.StartCleanup(ctx)

	srv := api.NewServer(store, listenAddr)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/", srv.Handler())
	mux.Handle("/healthz", srv.Handler())
	mux.Handle("/", staticHandler())

	server := &http.Server{
		Addr:         listenAddr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		slog.Info("PolicyBridge starting", "address", listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	slog.Info("shutting down")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
	store.Shutdown()
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "frontend not embedded", http.StatusNotFound)
		})
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		f, err := sub.Open(stringsTrimPrefix(path, "/"))
		if err != nil {
			r.URL.Path = "/index.html"
			fileServer.ServeHTTP(w, r)
			return
		}
		f.Close()
		fileServer.ServeHTTP(w, r)
	})
}

func stringsTrimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func runHealthcheck() error {
	port := getEnv("POLICYBRIDGE_LISTEN_PORT", "8080")
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz: %s", resp.Status)
	}
	return nil
}

// Ensure static directory exists for development builds.
func init() {
	_ = filepath.Join
}
