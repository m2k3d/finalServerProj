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

	"finalServerProj/internal/v"

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

	mimeType := http.DetectContentType(buffer)
	ext, ok := v.SafeExtensions[mimeType]
	if !ok {
		return "", fmt.Errorf("invalid_mime_type")
	}

	uniqueFilename := uuid.NewString() + ext
	dstPath := filepath.Join(v.EvidenceUploadDir, uniqueFilename)

	// Создаем файл на диске
	dst, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("%w: %w", err, ErrInfra)
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
		return "", fmt.Errorf("%w: %w", err, ErrInfra)
	}

	return uniqueFilename, nil
}
