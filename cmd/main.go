package main

import (
	"finalServerProj/handlers"
	"net/http"
)

const addr = ":8080"

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/entities", handlers.CaseHandler)

	// logger.Info("Server started", slog.String("addr", addr))
}
