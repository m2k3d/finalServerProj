package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"finalServerProj/internal/v"

	"github.com/google/uuid"
)

type Server struct {
	logger *slog.Logger
}

func New(l *slog.Logger) *Server {
	return &Server{
		logger: l,
	}
}

func (s *Server) CaseHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, v.MaxRequestSize)
		defer r.Body.Close()

		if err := r.ParseMultipartForm(v.MaxMemory); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "{\"error\":\"request body exceeds 20MB limit\"}", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "{\"error\":\"malformed multipart form\"}", http.StatusBadRequest)
			}
			return
		}

		defer r.MultipartForm.RemoveAll()

		dossierValues := r.MultipartForm.Value["dossier"]
		if len(dossierValues) == 0 {
			http.Error(w, "field \" dossier \" doesn't contain a file", http.StatusBadRequest)
			return
		}

		var dossier v.Dossier
		if err := json.Unmarshal([]byte(dossierValues[0]), &dossier); err != nil {
			http.Error(w, "error while trying to unmarshall the dossier", http.StatusBadRequest)
			return

		}

		err := processDossie(dossier)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid dossie: %s", err.Error()), http.StatusBadRequest)
			return
		}

		dossierID := uuid.NewString()

		evidenceFiles := r.MultipartForm.File["evidence"]
		if len(evidenceFiles) == 0 {
			http.Error(w, "field \" evidence \" doesn't contain a file", http.StatusBadRequest)
			return
		}

		response := v.UploadResponse{
			DossierID:      dossierID,
			SavedEvidence:  make([]string, 0),
			FailedEvidence: make([]v.FailedEvidence, 0),
		}

		for _, fileHeader := range evidenceFiles {
			filename, err := processSingleFile(fileHeader)
			if err != nil {
				slog.Error("error uploading specific file",
					slog.String("filename", fileHeader.Filename),
					slog.String("error", err.Error()),
				)

				failed := v.FailedEvidence{
					OriginalFilename: fileHeader.Filename,
					Reason:           err.Error(),
				}

				response.FailedEvidence = append(response.FailedEvidence, failed)

				continue
			}

			response.SavedEvidence = append(response.SavedEvidence, filename)
		}
		if len(response.SavedEvidence) == 0 {
			http.Error(w, "there is not a saved evidence", http.StatusBadRequest)
			return
		}

		storedEntity := v.StoredEntity{
			ID:              dossierID,
			Name:            dossier.Name,
			Description:     dossier.Description,
			ThreatLevel:     dossier.ThreatLevel,
			Vulnerabilities: dossier.Vulnerabilities,
			EvidenceFiles:   response.SavedEvidence,
		}

		finalPath := filepath.Join(v.EntitiesUploadDir, dossierID+".json")
		tmpPath := finalPath + ".tmp"

		data, err := json.Marshal(storedEntity)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to marshall entity: %s", err.Error()), http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
			http.Error(w, fmt.Sprintf("failed to write file: %s", err.Error()), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmpPath, finalPath); err != nil {
			http.Error(w, fmt.Sprintf("failed to rename file: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if len(response.FailedEvidence) != 0 {
			response.Status = "partial_success"
			w.WriteHeader(http.StatusMultiStatus)
		} else {
			response.Status = "success"
			w.WriteHeader(http.StatusCreated)
		}

		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to send JSON response", slog.String("error", err.Error()))
		}
	}
}

func processSingleFile(fh *multipart.FileHeader) (string, error) {
	// Базовая защита от Path Traversal атак
	filename := filepath.Base(fh.Filename)
	if filename == "" || filename == "." || filename == ".." {
		return "", fmt.Errorf("invalid file name")
	}

	// Быстрая проверка по расширению (первичный фильтр)
	if fh.Size == 0 { // == 0 mb?
		return "", fmt.Errorf("file_empty")
	}
	if fh.Size > v.MaxMemory { // > 3 mb?
		return "", fmt.Errorf("file_too_large")
	}

	// Открываем файл
	file, err := fh.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, 512)
	if _, err := file.Read(buffer); err != nil && err != io.EOF {
		return "", fmt.Errorf("error reading file header: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("failed to reset file pointer: %w", err)
	}

	extByMime := map[string]string{
		"image/jpeg": ".jpg", "image/png": ".png",
	}
	mimeType := http.DetectContentType(buffer)
	ext, ok := extByMime[mimeType]
	if !ok {
		return "", fmt.Errorf("invalid_mime_type")
	}

	uniqueFilename := uuid.NewString() + ext
	dstPath := filepath.Join(v.EvidenceUploadDir, uniqueFilename)

	// Создаем файл на диске
	dst, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("failed to create file on disk: %w", err)
	}
	defer dst.Close()

	// Копируем данные из оперативной памяти/временного файла в постоянный
	if _, err := io.Copy(dst, file); err != nil {
		if rmErr := os.Remove(dstPath); rmErr != nil {
			slog.Error("failed to remove corrupted file",
				slog.String("path", dstPath),
				slog.String("error", rmErr.Error()),
			)
		}
		return "", fmt.Errorf("error writing file: %w", err)
	}

	return uniqueFilename, nil
}

func processDossie(d v.Dossier) error {
	if strings.TrimSpace(d.Name) == "" {
		return errors.New("the dossie doesn't contain the name")
	}
	if strings.TrimSpace(d.Description) == "" {
		return errors.New("the dossie doesn't contain the description")
	}
	return nil
}
