package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"finalServerProj/internal/v"
)

func newTestServer() *Server {
	return &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func setupStorage(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	v.EntitiesUploadDir = filepath.Join(tmp, "entities")
	v.EvidenceUploadDir = filepath.Join(tmp, "evidence")
	if err := os.MkdirAll(v.EntitiesUploadDir, 0o755); err != nil {
		t.Fatalf("mkdir entities: %v", err)
	}
	if err := os.MkdirAll(v.EvidenceUploadDir, 0o755); err != nil {
		t.Fatalf("mkdir evidence: %v", err)
	}
}

var (
	pngMagic  = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	jpegMagic = []byte{0xFF, 0xD8, 0xFF}
)

func fakeImage(magic []byte, size int) []byte {
	data := make([]byte, size)
	copy(data, magic)
	return data
}

type testFile struct {
	name    string
	content []byte
}

func validDossierJSON() string {
	d := v.Dossier{
		Name:            "Призрак библиотеки",
		Description:     "Раскидывает книги по ночам",
		ThreatLevel:     4,
		Vulnerabilities: []string{"соль", "громкая музыка"},
	}
	b, _ := json.Marshal(d)
	return string(b)
}

func newMultipartRequest(t *testing.T, dossier *string, files []testFile) *http.Request {
	t.Helper()

	buf := &bytes.Buffer{}
	mw := multipart.NewWriter(buf)

	if dossier != nil {
		if err := mw.WriteField("dossier", *dossier); err != nil {
			t.Fatalf("write dossier field: %v", err)
		}
	}

	for _, f := range files {
		part, err := mw.CreateFormFile("evidence", f.name)
		if err != nil {
			t.Fatalf("create form file: %v", err)
		}
		if _, err := part.Write(f.content); err != nil {
			t.Fatalf("write file content: %v", err)
		}
	}

	if err := mw.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities", buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

func dirCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	return len(entries)
}

func decodeUploadResponse(t *testing.T, rr *httptest.ResponseRecorder) v.UploadResponse {
	t.Helper()
	var resp v.UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v, body: %s", err, rr.Body.String())
	}
	return resp
}

func decodeErrorResponse(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode error response: %v, body: %s", err, rr.Body.String())
	}
	return resp["error"]
}

// Поле dossier отсутствует в форме — ожидаем 400.
func TestCaseHandler_MissingDossier(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	req := newMultipartRequest(t, nil, []testFile{{"a.png", fakeImage(pngMagic, 100)}})
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
	}
}

// dossier содержит невалидный JSON — ожидаем 400.
func TestCaseHandler_InvalidJSON(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	bad := "{not valid json"
	req := newMultipartRequest(t, &bad, []testFile{{"a.png", fakeImage(pngMagic, 100)}})
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
	}
}

// dossier структурно валиден, но нарушает бизнес-правила (пустые поля,
// threat_level вне диапазона, пустой vulnerabilities) — ожидаем 400.
func TestCaseHandler_DossierValidationFailures(t *testing.T) {
	tests := []struct {
		name    string
		dossier v.Dossier
	}{
		{"missing name", v.Dossier{Description: "d", ThreatLevel: 5, Vulnerabilities: []string{"x"}}},
		{"missing description", v.Dossier{Name: "n", ThreatLevel: 5, Vulnerabilities: []string{"x"}}},
		{"threat level too low", v.Dossier{Name: "n", Description: "d", ThreatLevel: 0, Vulnerabilities: []string{"x"}}},
		{"threat level too high", v.Dossier{Name: "n", Description: "d", ThreatLevel: 11, Vulnerabilities: []string{"x"}}},
		{"empty vulnerabilities", v.Dossier{Name: "n", Description: "d", ThreatLevel: 5, Vulnerabilities: []string{}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setupStorage(t)
			srv := newTestServer()

			b, _ := json.Marshal(tt.dossier)
			dossierStr := string(b)
			req := newMultipartRequest(t, &dossierStr, []testFile{{"a.png", fakeImage(pngMagic, 100)}})
			rr := httptest.NewRecorder()

			srv.CaseHandler()(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// Поле dossier больше 1MB — ожидаем 400 с конкретным текстом ошибки.
func TestCaseHandler_DossierTooLarge(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	huge := strings.Repeat("a", v.MaxDossierSize+10)
	req := newMultipartRequest(t, &huge, []testFile{{"a.png", fakeImage(pngMagic, 100)}})
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
	}
	if got := decodeErrorResponse(t, rr); got != "dossier json size exceeds 1MB limit" {
		t.Fatalf("unexpected error message: %q", got)
	}
}

// Поле evidence отсутствует (файлов 0) — ожидаем 400.
func TestCaseHandler_NoEvidenceFiles(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	dossier := validDossierJSON()
	req := newMultipartRequest(t, &dossier, nil)
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
	}
}

// Файлов evidence больше 10 — ожидаем 400.
func TestCaseHandler_TooManyEvidenceFiles(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	dossier := validDossierJSON()
	files := make([]testFile, 11)
	for i := range files {
		files[i] = testFile{name: "a.png", content: fakeImage(pngMagic, 50)}
	}
	req := newMultipartRequest(t, &dossier, files)
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
	}
}

// Все файлы evidence не проходят валидацию — ожидаем 400 и что на диске
// не появилось ни JSON-досье, ни файлов улик (сохранять было нечего).
func TestCaseHandler_AllEvidenceInvalid_NoRollbackNeeded(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	entitiesBefore := dirCount(t, v.EntitiesUploadDir)
	evidenceBefore := dirCount(t, v.EvidenceUploadDir)

	dossier := validDossierJSON()
	files := []testFile{
		{"not_an_image.txt", []byte("just plain text, definitely not an image")},
		{"empty.png", []byte{}},
	}
	req := newMultipartRequest(t, &dossier, files)
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
	}

	if got := dirCount(t, v.EntitiesUploadDir); got != entitiesBefore {
		t.Fatalf("entity file should not have been created, dir count %d -> %d", entitiesBefore, got)
	}
	if got := dirCount(t, v.EvidenceUploadDir); got != evidenceBefore {
		t.Fatalf("no evidence file should have been written, dir count %d -> %d", evidenceBefore, got)
	}
}

// Все файлы evidence валидны — ожидаем 201, Location, saved_evidence
// с URL-ами и что на диске появились и JSON-досье, и файлы улик.
func TestCaseHandler_Success(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	entitiesBefore := dirCount(t, v.EntitiesUploadDir)
	evidenceBefore := dirCount(t, v.EvidenceUploadDir)

	dossier := validDossierJSON()
	files := []testFile{
		{"one.png", fakeImage(pngMagic, 100)},
		{"two.jpg", fakeImage(jpegMagic, 200)},
	}
	req := newMultipartRequest(t, &dossier, files)
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d, body: %s", rr.Code, rr.Body.String())
	}

	resp := decodeUploadResponse(t, rr)
	if resp.Status != "success" {
		t.Fatalf("expected status success, got %q", resp.Status)
	}
	if len(resp.SavedEvidence) != 2 {
		t.Fatalf("expected 2 saved evidence, got %d", len(resp.SavedEvidence))
	}
	if len(resp.FailedEvidence) != 0 {
		t.Fatalf("expected 0 failed evidence, got %d", len(resp.FailedEvidence))
	}

	wantLocation := "/api/v1/entities/" + resp.DossierID
	if got := rr.Header().Get("Location"); got != wantLocation {
		t.Fatalf("expected Location %q, got %q", wantLocation, got)
	}

	for _, url := range resp.SavedEvidence {
		if !strings.HasPrefix(url, "/api/v1/evidence/") {
			t.Fatalf("saved_evidence entry is not a URL: %q", url)
		}
		name := filepath.Base(url)
		if _, err := os.Stat(filepath.Join(v.EvidenceUploadDir, name)); err != nil {
			t.Fatalf("expected evidence file on disk for %q: %v", name, err)
		}
	}

	entityPath := filepath.Join(v.EntitiesUploadDir, resp.DossierID+".json")
	data, err := os.ReadFile(entityPath)
	if err != nil {
		t.Fatalf("expected entity file on disk: %v", err)
	}
	var stored v.StoredEntity
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("decode stored entity: %v", err)
	}
	if len(stored.EvidenceFiles) != 2 {
		t.Fatalf("expected 2 evidence files stored, got %d", len(stored.EvidenceFiles))
	}
	for _, name := range stored.EvidenceFiles {
		if strings.Contains(name, "/") {
			t.Fatalf("stored evidence file must be a bare filename, got %q", name)
		}
	}

	if got := dirCount(t, v.EntitiesUploadDir); got != entitiesBefore+1 {
		t.Fatalf("expected 1 new entity file, dir count %d -> %d", entitiesBefore, got)
	}
	if got := dirCount(t, v.EvidenceUploadDir); got != evidenceBefore+2 {
		t.Fatalf("expected 2 new evidence files, dir count %d -> %d", evidenceBefore, got)
	}
}

// Часть файлов evidence валидна, часть — нет (все 3 причины отказа) —
// ожидаем 207, без Location, в досье на диске только валидные улики.
func TestCaseHandler_PartialSuccess(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	dossier := validDossierJSON()
	files := []testFile{
		{"good.png", fakeImage(pngMagic, 100)},
		{"bad_mime.txt", []byte("not an image at all, just plain text")},
		{"empty.png", []byte{}},
		{"too_big.png", fakeImage(pngMagic, v.MaxMemory+1)},
	}
	req := newMultipartRequest(t, &dossier, files)
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusMultiStatus {
		t.Fatalf("expected 207, got %d, body: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "" {
		t.Fatalf("expected no Location header on 207, got %q", got)
	}

	resp := decodeUploadResponse(t, rr)
	if resp.Status != "partial_success" {
		t.Fatalf("expected status partial_success, got %q", resp.Status)
	}
	if len(resp.SavedEvidence) != 1 {
		t.Fatalf("expected 1 saved evidence, got %d", len(resp.SavedEvidence))
	}
	if len(resp.FailedEvidence) != 3 {
		t.Fatalf("expected 3 failed evidence, got %d", len(resp.FailedEvidence))
	}

	wantReasons := map[string]string{
		"bad_mime.txt": "invalid_mime_type",
		"empty.png":    "file_empty",
		"too_big.png":  "file_too_large",
	}
	for _, f := range resp.FailedEvidence {
		want, ok := wantReasons[f.OriginalFilename]
		if !ok {
			t.Fatalf("unexpected failed file: %q", f.OriginalFilename)
		}
		if f.Reason != want {
			t.Fatalf("file %q: expected reason %q, got %q", f.OriginalFilename, want, f.Reason)
		}
	}

	entityPath := filepath.Join(v.EntitiesUploadDir, resp.DossierID+".json")
	data, err := os.ReadFile(entityPath)
	if err != nil {
		t.Fatalf("expected entity file on disk: %v", err)
	}
	var stored v.StoredEntity
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("decode stored entity: %v", err)
	}
	if len(stored.EvidenceFiles) != 1 {
		t.Fatalf("expected only the 1 valid evidence file stored, got %d", len(stored.EvidenceFiles))
	}
}

// Тело запроса не является валидной multipart-формой — ожидаем 400.
func TestCaseHandler_MalformedMultipart(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/entities", strings.NewReader("this is not multipart data"))
	// No Content-Type header set -> ParseMultipartForm fails immediately.
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d, body: %s", rr.Code, rr.Body.String())
	}
}

// Общий размер тела запроса больше 20MB — ожидаем 413.
func TestCaseHandler_RequestBodyTooLarge(t *testing.T) {
	setupStorage(t)
	srv := newTestServer()

	dossier := validDossierJSON()
	// Single "file" that alone pushes the whole multipart body past the 20MB cap.
	files := []testFile{
		{"huge.png", fakeImage(pngMagic, v.MaxRequestSize+1024)},
	}
	req := newMultipartRequest(t, &dossier, files)
	rr := httptest.NewRecorder()

	srv.CaseHandler()(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d, body: %s", rr.Code, rr.Body.String())
	}
}
