package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"finalServerProj/internal/handlers"
	"finalServerProj/internal/logging"
	"finalServerProj/internal/v"
)

func main() {
	// CLI PART
	flag.StringVar(&v.Addr, "addr", ":8080", "addres")
	flag.StringVar(&v.StoragePath, "storage", "./storage", "path to the storage")

	flag.Parse()

	// SERVER PART
	logger := logging.New()
	server := handlers.New(logger)

	// creating two dirictories for files
	v.EntitiesUploadDir = filepath.Join(v.StoragePath, v.EntitiesUploadDir)
	v.EvidenceUploadDir = filepath.Join(v.StoragePath, v.EvidenceUploadDir)

	if err := os.MkdirAll(v.EntitiesUploadDir, 0o755); err != nil {
		slog.Error("Failed to create upload directory", slog.String("error", err.Error()))
		os.Exit(1)
	}
	if err := os.MkdirAll(v.EvidenceUploadDir, 0o755); err != nil {
		slog.Error("Failed to create upload directory", slog.String("error", err.Error()))
		os.Exit(1)
	}

	mux := http.NewServeMux()

	logger.Info("Server started", slog.String("addr", v.Addr))

	srv := &http.Server{
		Addr:         v.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,

		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	mux.HandleFunc("POST /api/v1/entities", server.CaseHandler())
	mux.HandleFunc("GET /api/v1/entities/{id}", server.GetEntityHandler())
	mux.HandleFunc("GET /api/v1/evidence/{filename}", server.GetEvidenceHandler())

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
