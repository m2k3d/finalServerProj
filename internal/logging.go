package internal

import (
	"log/slog"
	"os"
)

type handler struct {
	logger *slog.Logger
}

func New(h *handler) {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	h.logger = slog.New(slog.NewTextHandler(os.Stderr, opts))
}
