package handlers

import (
	"log/slog"
	"net/http"

	"finalServerProj/internal/variables"
)

type Server struct {
	logger *slog.Logger
}

type Dessier struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	ThreatLevel     int      `json:"treat_level"`
	Vulnerabilities []string `json:"Vulnerabilities"`
}

func New(l *slog.Logger) *Server {
	return &Server{
		logger: l,
	}
}

func (s *Server) CaseHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, variables.MaxRequestSize)

		if err := r.ParseMultipartForm(variables.MaxMemory); err != nil {
			slog.Warn("request size exceeded or parse error", slog.String("error", err.Error()))
			http.Error(w, "request size is too bit or invalid", http.StatusRequestEntityTooLarge)
			return
		}
		defer r.MultipartForm.RemoveAll()

		w.Header().Set("Content-Type", "multipart/form-data")

		s.logger.Info("Request handled",
			slog.String("path", r.URL.Path),
			slog.String("method", r.Method),
		)
	}
}
