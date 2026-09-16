package main

import (
	"net/http"

	"finalServerProj/internal/handlers"
	"finalServerProj/internal/logging"
)

const addr = ":8080"

func main() {
	mux := http.NewServeMux()

	logger := logging.New()
	h := handlers.New(logger)

	mux.HandleFunc("/api/v1/entities", handlers.CaseHandler)

	// logger.Info("Server started", slog.String("addr", addr))
}
