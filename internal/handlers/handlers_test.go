package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"log/slog"
	"math"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"finalServerProj/internal/variables"

	"github.com/google/uuid"
)

type testFile struct {
	name    string
	content []byte
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	root := t.TempDir()
	s := New(slog.New(slog.NewTextHandler(io.Discard, nil)), root,
		filepath.Join(root, "entities"), filepath.Join(root, "evidence"))
	for _, dir := range []string{s.Entities, s.Evidence} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func testMux(s *Server) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/entities", s.CaseHandler())
	mux.HandleFunc("GET /api/v1/entities/{id}", s.GetEntityHandler())
	mux.HandleFunc("GET /api/v1/evidence/{filename}", s.GetEvidenceHandler())
	return s.RecoveryMiddleware(mux)
}

func validDossier() variables.Dossier {
	return variables.Dossier{
		Name: "Призрак библиотеки", Description: "Раскидывает книги по ночам",
		ThreatLevel: 4, Vulnerabilities: []string{"соль", "громкая музыка"},
	}
}

func jsonString(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// Используем настоящие изображения; padding позволяет проверять границы размера.
func imageBytes(t *testing.T, extension string, size int) []byte {
	t.Helper()
	var buf bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	var err error
	switch extension {
	case ".png":
		err = png.Encode(&buf, img)
	case ".jpg":
		err = jpeg.Encode(&buf, img, nil)
	default:
		t.Fatalf("unsupported test image extension: %s", extension)
	}
	if err != nil {
		t.Fatal(err)
	}
	if size > buf.Len() {
		buf.Write(make([]byte, size-buf.Len()))
	}
	return buf.Bytes()
}

func newMultipartRequest(t *testing.T, dossier *string, files []testFile) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if dossier != nil {
		if err := writer.WriteField("dossier", *dossier); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range files {
		part, err := writer.CreateFormFile("evidence", file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities", &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func perform(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", rr.Code, want, rr.Body.String())
	}
}

func decodeJSON[T any](t *testing.T, rr *httptest.ResponseRecorder) T {
	t.Helper()
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}
	var value T
	if err := json.Unmarshal(rr.Body.Bytes(), &value); err != nil {
		t.Fatalf("invalid JSON response: %v; body: %s", err, rr.Body.String())
	}
	return value
}

func assertError(t *testing.T, rr *httptest.ResponseRecorder, status int) {
	t.Helper()
	assertStatus(t, rr, status)
	body := decodeJSON[map[string]string](t, rr)
	if len(body) != 1 || body["error"] == "" {
		t.Fatalf("expected a single nonempty error field, got %#v", body)
	}
}

func assertDirCount(t *testing.T, dir string, want int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != want {
		t.Fatalf("directory %s contains %d entries, want %d: %v", dir, len(entries), want, entries)
	}
}

func assertStorageEmpty(t *testing.T, s *Server) {
	t.Helper()
	assertDirCount(t, s.Entities, 0)
	assertDirCount(t, s.Evidence, 0)
}

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// Не вызывать из параллельных тестов: stdout является общим для процесса.
func captureStdout(t *testing.T, run func()) string {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdout-")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = file
	defer func() {
		os.Stdout = previous
		file.Close()
	}()
	run()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestNew(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	root := t.TempDir()
	entities, evidence := filepath.Join(root, "entities"), filepath.Join(root, "evidence")
	s := New(logger, root, entities, evidence)
	if s.Logger != logger || s.StoragePath != root || s.Entities != entities || s.Evidence != evidence {
		t.Fatalf("constructor did not preserve its dependencies: %+v", s)
	}
}

func TestCaseHandler_InvalidDossier(t *testing.T) {
	cases := []struct {
		name string
		json string
	}{
		{"empty", ""},
		{"malformed JSON", "{broken"},
		{"null", "null"},
		{"array", "[]"},
		{"missing fields", "{}"},
		{"missing name", `{"description":"d","threat_level":1,"vulnerabilities":["salt"]}`},
		{"blank name", `{"name":" \t","description":"d","threat_level":1,"vulnerabilities":["salt"]}`},
		{"missing description", `{"name":"n","threat_level":1,"vulnerabilities":["salt"]}`},
		{"blank description", `{"name":"n","description":" \n","threat_level":1,"vulnerabilities":["salt"]}`},
		{"missing threat level", `{"name":"n","description":"d","vulnerabilities":["salt"]}`},
		{"threat level below limit", `{"name":"n","description":"d","threat_level":0,"vulnerabilities":["salt"]}`},
		{"threat level above limit", `{"name":"n","description":"d","threat_level":11,"vulnerabilities":["salt"]}`},
		{"fractional threat level", `{"name":"n","description":"d","threat_level":1.5,"vulnerabilities":["salt"]}`},
		{"string threat level", `{"name":"n","description":"d","threat_level":"1","vulnerabilities":["salt"]}`},
		{"wrong name type", `{"name":42,"description":"d","threat_level":1,"vulnerabilities":["salt"]}`},
		{"wrong description type", `{"name":"n","description":true,"threat_level":1,"vulnerabilities":["salt"]}`},
		{"missing vulnerabilities", `{"name":"n","description":"d","threat_level":1}`},
		{"empty vulnerabilities", `{"name":"n","description":"d","threat_level":1,"vulnerabilities":[]}`},
		{"null vulnerabilities", `{"name":"n","description":"d","threat_level":1,"vulnerabilities":null}`},
		{"wrong vulnerabilities type", `{"name":"n","description":"d","threat_level":1,"vulnerabilities":"salt"}`},
		{"wrong vulnerability element type", `{"name":"n","description":"d","threat_level":1,"vulnerabilities":[42]}`},
		{"dossier too large", strings.Repeat("x", variables.MaxDossierSize+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			req := newMultipartRequest(t, &tc.json, []testFile{{"valid.png", imageBytes(t, ".png", 0)}})
			assertError(t, perform(testMux(s), req), http.StatusBadRequest)
			assertStorageEmpty(t, s)
		})
	}
	t.Run("missing dossier", func(t *testing.T) {
		s := newTestServer(t)
		req := newMultipartRequest(t, nil, []testFile{{"valid.png", imageBytes(t, ".png", 0)}})
		assertError(t, perform(testMux(s), req), http.StatusBadRequest)
		assertStorageEmpty(t, s)
	})
}

func TestCaseHandler_InvalidEvidence(t *testing.T) {
	cases := []struct {
		name  string
		files []testFile
	}{
		{"missing evidence", nil},
		{"empty file", []testFile{{"empty.png", nil}}},
		{"script disguised as image", []testFile{{"virus.jpg", []byte("<script>alert(1)</script>")}}},
		{"file too large", []testFile{{"large.png", imageBytes(t, ".png", variables.MaxMemory+1)}}},
		{"all rejected", []testFile{{"text.png", []byte("text")}, {"empty.jpg", nil}}},
	}
	tooMany := make([]testFile, variables.MaxEvidenceFiles+1)
	for i := range tooMany {
		tooMany[i] = testFile{fmt.Sprintf("%d.png", i), imageBytes(t, ".png", 0)}
	}
	cases = append(cases, struct {
		name  string
		files []testFile
	}{"too many evidence files", tooMany})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			dossier := jsonString(t, validDossier())
			assertError(t, perform(testMux(s), newMultipartRequest(t, &dossier, tc.files)), http.StatusBadRequest)
			assertStorageEmpty(t, s)
		})
	}
}

func TestCaseHandler_MultipartErrors(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
	}{
		{"missing content type", "", "not multipart"},
		{"missing boundary", "multipart/form-data", "not multipart"},
		{"broken multipart", "multipart/form-data; boundary=test", "not multipart"},
		{"truncated multipart", "multipart/form-data; boundary=test", "--test\r\nContent-Disposition: form-data; name=\"dossier\"\r\n\r\n{}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/entities", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			assertError(t, perform(testMux(s), req), http.StatusBadRequest)
			assertStorageEmpty(t, s)
		})
	}
}

func TestCaseHandler_RequestTooLarge(t *testing.T) {
	s := newTestServer(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dossier := jsonString(t, validDossier())
	req := newMultipartRequest(t, &dossier, []testFile{{"huge.png", imageBytes(t, ".png", variables.MaxRequestSize+1)}})
	assertError(t, perform(testMux(s), req), http.StatusRequestEntityTooLarge)
	assertStorageEmpty(t, s)
	assertDirCount(t, tmp, 0)
}

func TestCaseHandler_MultipartStorageFailure(t *testing.T) {
	s := newTestServer(t)
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "missing"))
	dossier := jsonString(t, validDossier())
	req := newMultipartRequest(t, &dossier, []testFile{{"spill.png", imageBytes(t, ".png", variables.MaxMemory+1)}})
	assertError(t, perform(testMux(s), req), http.StatusInternalServerError)
	assertStorageEmpty(t, s)
}

func TestCaseHandler_Success(t *testing.T) {
	for _, tc := range []struct {
		name         string
		count, level int
	}{
		{"one file and minimum threat level", 1, 1},
		{"two formats and maximum threat level", 2, 10},
		{"maximum file count", variables.MaxEvidenceFiles, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer(t)
			dossier := validDossier()
			dossier.ThreatLevel = tc.level
			data := jsonString(t, dossier)
			files := make([]testFile, tc.count)
			for i := range files {
				ext := ".png"
				if i%2 != 0 {
					ext = ".jpg"
				}
				// Одинаковые исходные имена не должны приводить к перезаписи.
				files[i] = testFile{"same-name.bin", imageBytes(t, ext, 0)}
			}
			h := testMux(s)
			rr := perform(h, newMultipartRequest(t, &data, files))
			assertStatus(t, rr, http.StatusCreated)
			response := decodeJSON[variables.UploadResponse](t, rr)
			if response.Status != "success" || response.FailedEvidence == nil || len(response.FailedEvidence) != 0 {
				t.Fatalf("unexpected success response: %+v", response)
			}
			if got := rr.Header().Get("Location"); got != "/api/v1/entities/"+response.DossierID {
				t.Fatalf("unexpected Location: %q", got)
			}
			assertSavedUpload(t, s, response, dossier, files)

			entityRR := perform(h, httptest.NewRequest(http.MethodGet, rr.Header().Get("Location"), nil))
			assertStatus(t, entityRR, http.StatusOK)
			entity := decodeJSON[variables.EntityResponse](t, entityRR)
			if entity.ID != response.DossierID || entity.Name != dossier.Name || entity.Description != dossier.Description ||
				entity.ThreatLevel != dossier.ThreatLevel || !reflect.DeepEqual(entity.Vulnerabilities, dossier.Vulnerabilities) ||
				!reflect.DeepEqual(entity.EvidenceURLs, response.SavedEvidence) {
				t.Fatalf("unexpected entity response: %+v", entity)
			}
			for i, url := range entity.EvidenceURLs {
				mediaRR := perform(h, httptest.NewRequest(http.MethodGet, url, nil))
				assertStatus(t, mediaRR, http.StatusOK)
				if !bytes.Equal(mediaRR.Body.Bytes(), files[i].content) {
					t.Fatalf("downloaded evidence %d differs from uploaded data", i)
				}
			}
		})
	}
}

func assertSavedUpload(t *testing.T, s *Server, response variables.UploadResponse, dossier variables.Dossier, files []testFile) {
	t.Helper()
	if _, err := uuid.Parse(response.DossierID); err != nil {
		t.Fatalf("invalid dossier UUID: %q", response.DossierID)
	}
	if len(response.SavedEvidence) != len(files) {
		t.Fatalf("saved %d files, want %d", len(response.SavedEvidence), len(files))
	}
	data, err := os.ReadFile(filepath.Join(s.Entities, response.DossierID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var stored variables.StoredEntity
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	if stored.ID != response.DossierID || stored.Name != dossier.Name || stored.Description != dossier.Description ||
		stored.ThreatLevel != dossier.ThreatLevel || !reflect.DeepEqual(stored.Vulnerabilities, dossier.Vulnerabilities) {
		t.Fatalf("unexpected dossier on disk: %+v", stored)
	}
	if len(stored.EvidenceFiles) != len(files) {
		t.Fatalf("stored %d evidence filenames, want %d", len(stored.EvidenceFiles), len(files))
	}
	seen := make(map[string]bool)
	for i, url := range response.SavedEvidence {
		name := stored.EvidenceFiles[i]
		if filepath.Base(name) != name || url != "/api/v1/evidence/"+name || seen[name] {
			t.Fatalf("invalid or duplicate evidence filename/URL: %q, %q", name, url)
		}
		seen[name] = true
		ext := filepath.Ext(name)
		if _, err := uuid.Parse(strings.TrimSuffix(name, ext)); err != nil {
			t.Fatalf("evidence filename is not a UUID: %q", name)
		}
		wantExt := map[string]string{"image/png": ".png", "image/jpeg": ".jpg"}[http.DetectContentType(files[i].content)]
		if ext != wantExt {
			t.Fatalf("extension = %q, want %q", ext, wantExt)
		}
		got, err := os.ReadFile(filepath.Join(s.Evidence, name))
		if err != nil || !bytes.Equal(got, files[i].content) {
			t.Fatalf("stored evidence %q differs: %v", name, err)
		}
	}
	assertDirCount(t, s.Entities, 1)
	assertDirCount(t, s.Evidence, len(files))
}

func TestCaseHandler_FileSizeBoundaryAndPartialSuccess(t *testing.T) {
	s := newTestServer(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	dossier := validDossier()
	data := jsonString(t, dossier)
	good := testFile{"valid.bin", imageBytes(t, ".png", variables.MaxMemory)}
	files := []testFile{
		good,
		{"virus.jpg", []byte("<script>alert(1)</script>")},
		{"empty.png", nil},
		{"large.png", imageBytes(t, ".png", variables.MaxMemory+1)},
	}
	var rr *httptest.ResponseRecorder
	output := captureStdout(t, func() {
		rr = perform(testMux(s), newMultipartRequest(t, &data, files))
	})
	assertStatus(t, rr, http.StatusMultiStatus)
	response := decodeJSON[variables.UploadResponse](t, rr)
	if response.Status != "partial_success" || rr.Header().Get("Location") != "" {
		t.Fatalf("unexpected partial success response: %+v, headers: %v", response, rr.Header())
	}
	wantFailures := []variables.FailedEvidence{
		{OriginalFilename: "virus.jpg", Reason: "invalid_mime_type"},
		{OriginalFilename: "empty.png", Reason: "file_empty"},
		{OriginalFilename: "large.png", Reason: "file_too_large"},
	}
	if !reflect.DeepEqual(response.FailedEvidence, wantFailures) {
		t.Fatalf("failed evidence = %+v, want %+v", response.FailedEvidence, wantFailures)
	}
	assertSavedUpload(t, s, response, dossier, []testFile{good})
	// 3 MiB успешно сохранено, всего 4 файла: P = 3 * sqrt(4) = 6.
	wantLog := fmt.Sprintf("[ANALYTICS] Dossier ID: %s | Paranormal Index (P): 6.00\n", response.DossierID)
	if output != wantLog {
		t.Fatalf("analytics = %q, want %q", output, wantLog)
	}
	assertDirCount(t, tmp, 0)
}

func TestCaseHandler_AnalyticsOnSuccess(t *testing.T) {
	s := newTestServer(t)
	dossier := jsonString(t, validDossier())
	var rr *httptest.ResponseRecorder
	output := captureStdout(t, func() {
		rr = perform(testMux(s), newMultipartRequest(t, &dossier,
			[]testFile{{"one.png", imageBytes(t, ".png", 1<<20)}}))
	})
	assertStatus(t, rr, http.StatusCreated)
	response := decodeJSON[variables.UploadResponse](t, rr)
	want := fmt.Sprintf("[ANALYTICS] Dossier ID: %s | Paranormal Index (P): 1.00\n", response.DossierID)
	if output != want {
		t.Fatalf("analytics = %q, want %q", output, want)
	}
}

func TestCaseHandler_Rollback(t *testing.T) {
	for _, failure := range []string{"evidence creation", "evidence opening after first save", "dossier write"} {
		t.Run(failure, func(t *testing.T) {
			s := newTestServer(t)
			entityDir, evidenceDir := s.Entities, s.Evidence
			// Откат не должен затрагивать файлы других досье.
			entityPath := filepath.Join(entityDir, "existing.json")
			evidencePath := filepath.Join(evidenceDir, "existing.png")
			writeTestFile(t, entityPath, []byte("existing dossier"))
			writeTestFile(t, evidencePath, []byte("existing evidence"))
			dossier := jsonString(t, validDossier())
			req := newMultipartRequest(t, &dossier, []testFile{
				{"one.png", imageBytes(t, ".png", 0)},
				{"two.jpg", imageBytes(t, ".jpg", 0)},
			})
			switch failure {
			case "evidence creation":
				s.Evidence = filepath.Join(s.StoragePath, "missing", "evidence")
			case "evidence opening after first save":
				if err := req.ParseMultipartForm(variables.MaxMemory); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { req.MultipartForm.RemoveAll() })
				// Нет ни содержимого в памяти, ни временного файла: Open вернёт ошибку.
				req.MultipartForm.File["evidence"][1] = &multipart.FileHeader{Filename: "unavailable.jpg", Size: 100}
			case "dossier write":
				s.Entities = filepath.Join(s.StoragePath, "missing", "entities")
			}
			var rr *httptest.ResponseRecorder
			output := captureStdout(t, func() { rr = perform(testMux(s), req) })
			assertError(t, rr, http.StatusInternalServerError)
			if output != "" {
				t.Fatalf("failed request emitted analytics: %q", output)
			}
			assertDirCount(t, entityDir, 1)
			assertDirCount(t, evidenceDir, 1)
			for path, want := range map[string]string{entityPath: "existing dossier", evidencePath: "existing evidence"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("rollback changed existing file %q: %q, %v", path, got, err)
				}
			}
		})
	}
}

func TestGetEntityHandler_InvalidID(t *testing.T) {
	s := newTestServer(t)
	writeTestFile(t, filepath.Join(s.StoragePath, "secret.json"), []byte(`{"secret":"outside storage"}`))
	for _, id := range []string{"", "secret", "../secret", "../../etc/passwd", uuid.NewString() + "/../secret"} {
		t.Run(id, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/placeholder", nil)
			req.SetPathValue("id", id)
			assertError(t, perform(s.GetEntityHandler(), req), http.StatusBadRequest)
		})
	}
	t.Run("encoded traversal through router", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/%2e%2e%2fsecret", nil)
		assertError(t, perform(testMux(s), req), http.StatusBadRequest)
	})
}

func TestGetEntityHandler_StorageErrors(t *testing.T) {
	for _, scenario := range []string{"not found", "invalid JSON", "read failure"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestServer(t)
			id := uuid.NewString()
			path := filepath.Join(s.Entities, id+".json")
			status := http.StatusInternalServerError
			switch scenario {
			case "not found":
				status = http.StatusNotFound
			case "invalid JSON":
				writeTestFile(t, path, []byte("{broken"))
			case "read failure":
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/entities/"+id, nil)
			assertError(t, perform(testMux(s), req), status)
		})
	}
}

func TestGetEvidenceHandler_Range(t *testing.T) {
	s := newTestServer(t)
	content := imageBytes(t, ".png", 100)
	name := uuid.NewString() + ".png"
	writeTestFile(t, filepath.Join(s.Evidence, name), content)
	for _, tc := range []struct {
		name, method, rangeHeader, contentRange string
		status                                  int
		body                                    []byte
	}{
		{"full file", http.MethodGet, "", "", http.StatusOK, content},
		{"first bytes", http.MethodGet, "bytes=0-7", "bytes 0-7/100", http.StatusPartialContent, content[:8]},
		{"open ended", http.MethodGet, "bytes=90-", "bytes 90-99/100", http.StatusPartialContent, content[90:]},
		{"suffix", http.MethodGet, "bytes=-5", "bytes 95-99/100", http.StatusPartialContent, content[95:]},
		{"head", http.MethodHead, "", "", http.StatusOK, nil},
		{"unsatisfiable", http.MethodGet, "bytes=100-", "bytes */100", http.StatusRequestedRangeNotSatisfiable, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/evidence/"+name, nil)
			req.Header.Set("Range", tc.rangeHeader)
			rr := perform(testMux(s), req)
			assertStatus(t, rr, tc.status)
			if tc.status != http.StatusRequestedRangeNotSatisfiable && !bytes.Equal(rr.Body.Bytes(), tc.body) {
				t.Fatalf("unexpected response bytes: %q", rr.Body.Bytes())
			}
			if got := rr.Header().Get("Content-Range"); got != tc.contentRange {
				t.Fatalf("Content-Range = %q, want %q", got, tc.contentRange)
			}
			if tc.status == http.StatusOK || tc.status == http.StatusPartialContent {
				if got := rr.Header().Get("Content-Type"); got != "image/png" {
					t.Fatalf("Content-Type = %q, want image/png", got)
				}
				if got := rr.Header().Get("Accept-Ranges"); got != "bytes" {
					t.Fatalf("Accept-Ranges = %q, want bytes", got)
				}
			}
		})
	}
}

func TestGetEvidenceHandler_ErrorsAndTraversal(t *testing.T) {
	for _, scenario := range []string{"not found", "directory", "open failure", "encoded traversal"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestServer(t)
			url := "/api/v1/evidence/missing.png"
			status := http.StatusNotFound
			switch scenario {
			case "directory":
				if err := os.Mkdir(filepath.Join(s.Evidence, "folder"), 0o755); err != nil {
					t.Fatal(err)
				}
				url = "/api/v1/evidence/folder"
			case "open failure":
				// ENOTDIR воспроизводится и при запуске тестов от root, в отличие от chmod.
				path := filepath.Join(s.StoragePath, "not-a-directory")
				writeTestFile(t, path, []byte("file"))
				s.Evidence = path
				status = http.StatusInternalServerError
			case "encoded traversal":
				writeTestFile(t, filepath.Join(s.StoragePath, "secret.png"), []byte("secret"))
				url = "/api/v1/evidence/%2e%2e%2fsecret.png"
			}
			assertError(t, perform(testMux(s), httptest.NewRequest(http.MethodGet, url, nil)), status)
		})
	}
}

func TestRecoveryMiddleware(t *testing.T) {
	for _, shouldPanic := range []bool{false, true} {
		t.Run(fmt.Sprintf("panic=%t", shouldPanic), func(t *testing.T) {
			s := newTestServer(t)
			var logs bytes.Buffer
			s.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			called := false
			h := s.RecoveryMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				if shouldPanic {
					panic("test panic")
				}
				w.Header().Set("X-Test", "passed")
				w.WriteHeader(http.StatusNoContent)
			}))
			rr := perform(h, httptest.NewRequest(http.MethodGet, "/", nil))
			if !called {
				t.Fatal("middleware did not call the handler")
			}
			if shouldPanic {
				assertError(t, rr, http.StatusInternalServerError)
				if !strings.Contains(logs.String(), "test panic") || !strings.Contains(logs.String(), "stack=") {
					t.Fatalf("panic and stack were not written to the server logger: %s", &logs)
				}
			} else {
				assertStatus(t, rr, http.StatusNoContent)
				if rr.Header().Get("X-Test") != "passed" || rr.Body.Len() != 0 || logs.Len() != 0 {
					t.Fatalf("middleware changed a normal response: %+v, logs: %s", rr, &logs)
				}
			}
		})
	}
}

func TestProcessSingleFile_InfrastructureErrors(t *testing.T) {
	for _, scenario := range []string{"source unavailable", "destination unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			s := newTestServer(t)
			var header *multipart.FileHeader
			if scenario == "source unavailable" {
				header = &multipart.FileHeader{Filename: "missing.png", Size: 100}
			} else {
				dossier := jsonString(t, validDossier())
				req := newMultipartRequest(t, &dossier, []testFile{{"valid.png", imageBytes(t, ".png", 0)}})
				if err := req.ParseMultipartForm(variables.MaxMemory); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { req.Body.Close(); req.MultipartForm.RemoveAll() })
				header = req.MultipartForm.File["evidence"][0]
				s.Evidence = filepath.Join(s.StoragePath, "missing", "evidence")
			}
			name, err := s.processSingleFile(header)
			if name != "" || !errors.Is(err, ErrInfra) {
				t.Fatalf("name = %q, err = %v; want empty name and ErrInfra", name, err)
			}
			var pathErr *os.PathError
			if !errors.As(err, &pathErr) {
				t.Fatalf("underlying file error was not preserved: %v", err)
			}
		})
	}
}

func TestParanormalIndex(t *testing.T) {
	for _, tc := range []struct {
		name  string
		sizes []int64
		total int
		want  float64
	}{
		{"no files", nil, 0, 0},
		{"one MiB", []int64{1 << 20}, 1, 1},
		{"rejected files count toward N", []int64{1 << 20, 3 << 20}, 4, 8},
		{"fractional MiB", []int64{1 << 19}, 2, math.Sqrt2 / 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := paranormalIndex(tc.sizes, tc.total); math.Abs(got-tc.want) > 1e-9 {
				t.Fatalf("index = %v, want %v", got, tc.want)
			}
		})
	}
}
