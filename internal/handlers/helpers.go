package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"

	"finalServerProj/internal/variables"

	"github.com/google/uuid"
)

var ErrInfra = errors.New("infra_error")

func paranormalIndex(savedSizes []int64, total int) float64 {
	var sum int64
	for _, s := range savedSizes {
		sum += s
	}
	mb := float64(sum) / (1024 * 1024)
	return mb * math.Sqrt(float64(total))
}

func writeJsonHandler(w http.ResponseWriter, errMsg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": errMsg})
}

func (s *Server) processSingleFile(fh *multipart.FileHeader) (savedName string, err error) {
	// Быстрая проверка по расширению (первичный фильтр)
	if fh.Size == 0 { // == 0 mb?
		return "", fmt.Errorf("file_empty")
	}
	if fh.Size > variables.MaxMemory { // > 3 mb?
		return "", fmt.Errorf("file_too_large")
	}

	file, err := fh.Open()
	if err != nil {
		return "", fmt.Errorf("%w: failed to open file: %w", ErrInfra, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			s.Logger.Error("failed to close uploaded file",
				slog.String("error", closeErr.Error()),
			)
		}
	}()

	buffer := make([]byte, 512)
	if _, err := file.Read(buffer); err != nil && err != io.EOF {
		return "", fmt.Errorf("%w: failed to read file: %w", ErrInfra, err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("%w: failed to seek file: %w", ErrInfra, err)
	}

	mimeType := http.DetectContentType(buffer)
	ext, ok := variables.SafeExtensions[mimeType]
	if !ok {
		return "", fmt.Errorf("invalid_mime_type")
	}

	uniqueFilename := uuid.NewString() + ext
	dstPath := filepath.Join(s.Evidence, uniqueFilename)

	// Создаем файл на диске
	dst, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("%w: %w", err, ErrInfra)
	}
	defer func() {
		if closeErr := dst.Close(); closeErr != nil {
			err = fmt.Errorf("%w: failed to close file: %w", ErrInfra, closeErr)
			savedName = ""

			if rmErr := os.Remove(dstPath); rmErr != nil {
				s.Logger.Error("failed to remove corrupted file",
					slog.String("path", dstPath),
					slog.String("error", rmErr.Error()),
				)
			}
		}
	}()

	// Копируем данные из оперативной памяти/временного файла в постоянный
	if _, err := io.Copy(dst, file); err != nil {
		if rmErr := os.Remove(dstPath); rmErr != nil {
			s.Logger.Error("failed to remove corrupted file",
				slog.String("path", dstPath),
				slog.String("error", rmErr.Error()),
			)
		}
		return "", fmt.Errorf("%w: %w", err, ErrInfra)
	}

	return uniqueFilename, nil
}
