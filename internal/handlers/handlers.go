package handlers

import (
	"log/slog"
)

type Handler struct {
	logger *slog.Logger
}

func New(l *slog.Logger) *Handler {
	return &Handler{
		logger: l,
	}
}

/*
func (h *Handler) CaseHandler(w http.ResponseWriter, r *http.Request) {
	h.logger = logging.New
}
*/
