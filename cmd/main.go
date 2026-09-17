package main

import (
	"log/slog"
	"net/http"
	"os"
	"time"

	"finalServerProj/internal/handlers"
	"finalServerProj/internal/logging"
	"finalServerProj/internal/variables"
)

func main() {
	mux := http.NewServeMux()

	logger := logging.New()
	server := handlers.New(logger)

	logger.Info("Server started", slog.String("addr", variables.Addr))

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,

		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	mux.HandleFunc("/api/v1/entities", server.CaseHandler())

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
