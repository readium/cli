package serve

import (
	"net/http"
	"time"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/mux"
	"github.com/readium/cli/pkg/serve/cache"
	"github.com/readium/go-toolkit/pkg/archive"
	"github.com/readium/go-toolkit/pkg/streamer"
	"github.com/readium/go-toolkit/pkg/util/url"
)

type Remote struct {
	LocalDirectory string          // Local directory base path
	S3             *s3.Client      // AWS S3-compatible storage
	GCS            *storage.Client // Google Cloud Storage
	HTTP           *http.Client    // HTTP-requested storage
	HTTPEnabled    bool            // Whether HTTP is enabled
	HTTPSEnabled   bool            // Whether HTTPS is enabled
	Config         archive.RemoteArchiveConfig
}

func (r Remote) AcceptsScheme(scheme url.Scheme) bool {
	switch scheme {
	case url.SchemeFile:
		return r.LocalDirectory != ""
	case url.SchemeS3:
		return r.S3 != nil
	case url.SchemeGS:
		return r.GCS != nil
	case url.SchemeHTTP:
		return r.HTTPEnabled && r.HTTP != nil
	case url.SchemeHTTPS:
		return r.HTTPSEnabled && r.HTTP != nil
	default:
		return false
	}
}

type ServerConfig struct {
	Debug             bool
	JSONIndent        string
	InferA11yMetadata streamer.InferA11yMetadata
}

type Server struct {
	config ServerConfig
	remote Remote
	router *mux.Router
	lfu    *cache.TinyLFU
}

const MaxCachedPublicationAmount = 10
const MaxCachedPublicationTTL = time.Second * time.Duration(600)

func NewServer(config ServerConfig, remote Remote) *Server {
	return &Server{
		config: config,
		remote: remote,
		lfu:    cache.NewTinyLFU(MaxCachedPublicationAmount, MaxCachedPublicationTTL),
	}
}
