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

		if err := r.ParseMultipartForm(v.MaxMemory); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, `{"error":"request body exceeds 20MB limit"}`, http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, `{"error":"malformed multipart form"}`, http.StatusBadRequest)
			}
			return
		}

		defer r.MultipartForm.RemoveAll()

		files := r.MultipartForm.File["evidence"]
		if len(files) == 0 {
			http.Error(w, "field \" evidence \" doesn't contain a file", http.StatusBadRequest)
			return
		}

		response := v.UploadResponse{
			DossierID:      "",
			Status:         "",
			SavedEvidence:  make([]string, 0),
			FailedEvidence: make([]v.FailedEvidence, 0),
		}

		for _, fileHeader := range files {
			filename, err := processSingleFile(fileHeader)
			if err != nil {
				// Если один файл с ошибкой, мы логируем это, добавляем в список Failed и идем дальше!
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

			// Если успех - сохраняем данные
			response.SavedEvidence = append(response.SavedEvidence, filename)
		}

		w.Header().Set("Content-Type", "application/json")

		switch {
		case len(response.SavedEvidence) == 0:
			w.WriteHeader(http.StatusBadRequest)
		case len(response.FailedEvidence) != 0:
			w.WriteHeader(http.StatusMultiStatus)
		default:
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

	// Проверяем MIME-тип по сигнатуре (первые 512 байт).
	// Это защищает от простой подмены расширения, но не от специально сфабрикованных файлов.
	// Для критичных сценариев используйте специализированные библиотеки.
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
