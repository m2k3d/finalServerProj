package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"time"

	"finalServerProj/internal/handlers"
	"finalServerProj/internal/logging"
	"finalServerProj/internal/vars"
)

func main() {
	// cli part
	flag.StringVar(&vars.Addr, "addr", ":8080", "addres")
	flag.StringVar(&vars.StoragePath, "storage", "./storage", "path to the storage")

	flag.Parse()

	// server part
	mux := http.NewServeMux()

	logger := logging.New()
	server := handlers.New(logger)

	logger.Info("Server started", slog.String("addr", vars.Addr))

	srv := &http.Server{
		Addr:         vars.Addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,

		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	mux.HandleFunc("/api/v1/entities", server.CaseHandler())

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("Server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
