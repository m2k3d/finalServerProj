package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
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
				writeJsonHandler(w, "request body exceeds 20MB limit", http.StatusRequestEntityTooLarge)
			} else {
				writeJsonHandler(w, "malformed multipart form", http.StatusBadRequest)
			}
			return
		}

		defer r.MultipartForm.RemoveAll()

		dossierValues := r.MultipartForm.Value["dossier"]
		if len(dossierValues) == 0 {
			writeJsonHandler(w, "field \" dossier \" doesn't contain a file", http.StatusBadRequest)
			return
		}

		if len(dossierValues[0]) > v.MaxDossierSize {
			writeJsonHandler(w, "dossier json size exceeds 1MB limit", http.StatusBadRequest)
			return
		}

		var dossier v.Dossier
		if err := json.Unmarshal([]byte(dossierValues[0]), &dossier); err != nil {
			writeJsonHandler(w, "error while trying to unmarshall the dossier", http.StatusBadRequest)
			return
		}

		err := processDossie(dossier)
		if err != nil {
			writeJsonHandler(w, fmt.Sprintf("invalid dossie: %s", err.Error()), http.StatusBadRequest)
			return
		}

		dossierID := uuid.NewString()

		evidenceFiles := r.MultipartForm.File["evidence"]
		if len(evidenceFiles) == 0 {
			writeJsonHandler(w, "field \" evidence \" doesn't contain a file", http.StatusBadRequest)
			return
		}
		if len(evidenceFiles) > v.MaxEvidenceFiles {
			writeJsonHandler(w, "field \" evidence \" contains more than 10 files", http.StatusBadRequest)
			return
		}

		response := v.UploadResponse{
			DossierID:      dossierID,
			SavedEvidence:  make([]string, 0),
			FailedEvidence: make([]v.FailedEvidence, 0),
		}

		var savedSize []int64 // для исоплользования в формуле (которая используются в логировании)

		for _, fileHeader := range evidenceFiles {
			filename, err := processSingleFile(fileHeader)
			if err != nil {
				if errors.Is(err, ErrInfra) {
					for _, name := range response.SavedEvidence {
						if err := os.Remove(filepath.Join(v.EvidenceUploadDir, name)); err != nil {
							slog.Error("error removing the file",
								slog.String("filename", name),
								slog.String("error", err.Error()),
							)
						}
					}

					writeJsonHandler(w, "failed to save evidence", http.StatusInternalServerError)

					return
				}

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

			savedSize = append(savedSize, fileHeader.Size)

			response.SavedEvidence = append(response.SavedEvidence, filename)
		}

		if len(response.SavedEvidence) == 0 {
			writeJsonHandler(w, "there is not a saved evidence", http.StatusBadRequest)
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
			writeJsonHandler(w, "failed to marshall entity", http.StatusInternalServerError)
			return
		}
		if err := os.WriteFile(tmpPath, data, 0o644); err != nil {
			for _, name := range response.SavedEvidence {
				if err := os.Remove(filepath.Join(v.EvidenceUploadDir, name)); err != nil {
					slog.Error("error removing the file",
						slog.String("filename", name),
						slog.String("error", err.Error()),
					)
				}
			}

			if err := os.Remove(filepath.Join(tmpPath)); err != nil {
				slog.Error("error removing the file",
					slog.String("filename", tmpPath),
					slog.String("error", err.Error()),
				)
			}

			writeJsonHandler(w, "failed to write file", http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmpPath, finalPath); err != nil {
			for _, name := range response.SavedEvidence {
				if err := os.Remove(filepath.Join(v.EvidenceUploadDir, name)); err != nil {
					slog.Error("error removing the file",
						slog.String("filename", name),
						slog.String("error", err.Error()),
					)
				}
			}

			if err := os.Remove(filepath.Join(tmpPath)); err != nil {
				slog.Error("error removing the file",
					slog.String("filename", tmpPath),
					slog.String("error", err.Error()),
				)
			}

			writeJsonHandler(w, "failed to write file", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		if len(response.FailedEvidence) != 0 {
			response.Status = "partial_success"
			w.WriteHeader(http.StatusMultiStatus)
		} else {
			response.Status = "success"
			w.Header().Set("Location", "/api/v1/entities/"+dossierID)
			w.WriteHeader(http.StatusCreated)
		}

		// тут точно хотя бы partial_success
		fmt.Fprintf(os.Stdout, "[ANALYTICS] Dossier ID: %s | Paranormal Index (P): %.2f\n", dossierID, paranormalIndex(savedSize, len(evidenceFiles)))

		if err := json.NewEncoder(w).Encode(response); err != nil {
			slog.Error("failed to send JSON response", slog.String("error", err.Error()))
		}
	}
}

func processDossie(d v.Dossier) error {
	if strings.TrimSpace(d.Name) == "" {
		return errors.New("the dossie doesn't contain the name")
	}
	if strings.TrimSpace(d.Description) == "" {
		return errors.New("the dossie doesn't contain the description")
	}
	if d.ThreatLevel < 1 || d.ThreatLevel > 10 {
		return errors.New("the dossie's threat level is incorrect")
	}
	if len(d.Vulnerabilities) == 0 {
		return errors.New("the dossie's vulnerabilitie is empty")
	}
	return nil
}

func (s *Server) GetEntityHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		filePath := filepath.Join(v.EntitiesUploadDir, id+".json")

		jsonFile, err := os.ReadFile(filePath)
		if err != nil {
			if os.IsNotExist(err) {
				writeJsonHandler(w, "the file doesn't exist", http.StatusNotFound)
				return
			}
			writeJsonHandler(w, "something went wrong", http.StatusBadGateway)
			return
		}

		var entity v.StoredEntity
		err = json.Unmarshal(jsonFile, &entity)
		if err != nil {
			writeJsonHandler(w, "something went wrong", http.StatusBadGateway)
			return
		}

		response := v.EntityResponse{
			ID:              entity.ID,
			Name:            entity.Name,
			Description:     entity.Description,
			ThreatLevel:     entity.ThreatLevel,
			Vulnerabilities: entity.Vulnerabilities,
			// 	EvidenceURLs
		}
		for _, filename := range entity.EvidenceFiles {
			response.EvidenceURLs = append(response.EvidenceURLs, "/api/v1/evidence/"+filename)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func (s *Server) GetEvidenceHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unsafePath := r.PathValue("filename")

		safeName := filepath.Base(unsafePath)
		path := filepath.Join(v.EvidenceUploadDir, safeName)

		file, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeJsonHandler(w, "file is not exist", http.StatusNotFound)
			} else {
				writeJsonHandler(w, "something went wrong", http.StatusNotFound)
			}
			return
		}
		defer file.Close()

		// check is dir?
		fileInfo, err := file.Stat()
		if err != nil {
			writeJsonHandler(w, "can't get the file statistic", http.StatusNotFound)
			return
		}
		if fileInfo.IsDir() {
			writeJsonHandler(w, "file is a dirictory", http.StatusNotFound)
			return
		}

		http.ServeContent(w, r, fileInfo.Name(), fileInfo.ModTime(), file)
	}
}

func (s *Server) RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				// Логируем саму ошибку и стек-трейс, чтобы понять, где именно упал код
				s.logger.Error("panic",
					slog.Any("error", err),
					slog.String("stack", string(debug.Stack())),
				)

				writeJsonHandler(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}
