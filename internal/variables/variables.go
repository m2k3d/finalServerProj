package variables

const (
	MaxRequestSize   = 20 << 20 // 20 mb
	MaxMemory        = 3 << 20  // 3 mb
	MaxEvidenceFiles = 10
	Addr             = ":8080"
	UploadDir        = "./storage"
)

var SafeExtensions = map[string]struct{}{
	"jpeg": {}, "png": {},
}
