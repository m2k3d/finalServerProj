package vars // variables, constants

const (
	MaxRequestSize   = 20 << 20 // 20 mb
	MaxMemory        = 3 << 20  // 3 mb
	MaxEvidenceFiles = 10
	UploadDir        = "./storage"
)

var SafeExtensions = map[string]struct{}{
	"jpeg": {}, "png": {},
}

var (
	StoragePath string
	Addr        string
)
