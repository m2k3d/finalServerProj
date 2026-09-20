package v // variables, constants

const (
	MaxRequestSize   = 20 << 20 // 20 mb
	MaxMemory        = 3 << 20  // 3 mb
	MaxEvidenceFiles = 10
)

var SafeExtensions = map[string]struct{}{
	"jpeg": {}, "png": {},
}

var (
	StoragePath       string
	Addr              string
	EntitiesUploadDir = "/entities"
	EvidenceUploadDir = "/evidence"
)

type Dossier struct {
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	ThreatLevel     int      `json:"treat_level"`
	Vulnerabilities []string `json:"Vulnerabilities"`
}

type FailedEvidence struct {
	OriginalFilename string `json:"original_filename"`
	Reason           string `json:"reason"`
}

type UploadResponse struct {
	DossierID      string           `json:"dossier_id"`
	Status         string           `json:"status"`
	SavedEvidence  []string         `json:"saved_evidence"`
	FailedEvidence []FailedEvidence `json:"failed_evidence"`
}
