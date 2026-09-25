package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
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

	wrapped := server.RecoveryMiddleware(mux)

	srv := &http.Server{
		Addr:         v.Addr,
		Handler:      wrapped,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,

		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	mux.HandleFunc("POST /api/v1/entities", server.CaseHandler())
	mux.HandleFunc("GET /api/v1/entities/{id}", server.GetEntityHandler())
	mux.HandleFunc("GET /api/v1/evidence/{filename}", server.GetEvidenceHandler())

	err := Run(srv, logger, v.Addr)
	if err != nil {
		slog.Error("Server error", slog.String("error", err.Error()))
		os.Exit(1)

	}
}

func Run(s *http.Server, l *slog.Logger, addr string) error {
	serverErrors := make(chan error, 1)

	go func() {
		l.Info("Server starting", slog.String("address", addr))
		serverErrors <- s.ListenAndServe()
	}()

	osSignals := make(chan os.Signal, 1)

	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("server failed to start or crashed: %w", err)

	case sig := <-osSignals:
		l.Info("Received OS signal, initiating graceful shutdown",
			slog.String("signal", sig.String()),
		)

		// Создаем контекст с таймаутом. Даем серверу максимум 30 секунд на завершение текущих запросов.
		const gracefulTimeout = 30 * time.Second
		ctx, cancel := context.WithTimeout(context.Background(), gracefulTimeout)
		defer cancel()

		l.Info("Graceful shutdown started", slog.Duration("timeout", gracefulTimeout))

		// Вызываем Shutdown. Он блокируется, пока все соединения не закроются или пока не истечет контекст
		if err := s.Shutdown(ctx); err != nil {
			l.Error("Graceful shutdown failed", slog.Any("error", err))

			// Если завершить плавно не вышло (например, завис обработчик), закрываем принудительно
			if closeErr := s.Close(); closeErr != nil {
				l.Error("Forceful close also failed", slog.Any("error", closeErr))
			}
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}

		l.Info("Graceful shutdown completed successfully")
		return nil
	}
}
