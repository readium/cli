package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"log/slog"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/errors"
	"github.com/readium/cli/pkg/serve"
	"github.com/readium/cli/pkg/serve/client"
	"github.com/readium/go-toolkit/pkg/streamer"
	"github.com/readium/go-toolkit/pkg/util/url"
	"github.com/spf13/cobra"
	"google.golang.org/api/option"
)

var debugFlag bool

var bindAddressFlag string

var bindPortFlag uint16

var schemeFlag []string

var fileDirectoryFlag string

// Cloud-related flags
var s3EndpointFlag string
var s3RegionFlag string
var s3AccessKeyFlag string
var s3SecretKeyFlag string
var s3UsePathStyleFlag bool

var httpAuthorizationFlag string

var remoteArchiveTimeoutFlag uint32
var remoteArchiveCacheSize uint32
var remoteArchiveCacheCount uint32
var remoteArchiveCacheAll uint32

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a local HTTP server, serving a specified directory of publications",
	Long: `Start a local HTTP server, serving a specified directory of publications.

This command will start an HTTP serve listening by default on 'localhost:15080',
serving all compatible files (EPUB, PDF, CBZ, etc.) available from the enabled
access schemes (file, http, https, s3, gs, or a local path if file scheme is enabled)
as Readium Web Publications. To get started, the manifest can be accessed from
'http://localhost:15080/<filename in base64url encoding without padding>/manifest.json'.
This file serves as the entry point and contains metadata and links to the rest
of the files that can be accessed for the publication.

If local file access is enabled, the server also exposes a '/list.json' endpoint that, 
for debugging purposes, returns a list of all the publications found in the directory
along with their encoded paths. This will be replaced by an OPDS 2 feed (or similar)
in a future release.

Note: Take caution before exposing this server on the internet. It does not
implement any authentication, and may have more access to files than expected.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			// For users migrating from previous versions of the CLI
			return errors.New("no arguments expected, base directory for local files is now set with a flag")
		}
		return nil
	},

	SuggestFor: []string{"server"},
	RunE: func(cmd *cobra.Command, args []string) error {
		// By the time we reach this point, we know that the arguments were
		// properly parsed, and we don't want to show the usage if an API error
		// occurs.
		cmd.SilenceUsage = true

		// Validate schemes
		schemes := make([]url.Scheme, len(schemeFlag))
		for i, v := range schemeFlag {
			lowerScheme := url.Scheme(strings.ToLower(v)) // Accomodate for wrong capitalization
			switch lowerScheme {
			case url.SchemeFile, url.SchemeHTTP, url.SchemeHTTPS, url.SchemeS3, url.SchemeGS:
				schemes[i] = lowerScheme
			default:
				return fmt.Errorf("invalid scheme %q, acceptable values: file, http, https, s3, gs", v)
			}
		}

		if fileDirectoryFlag != "" {
			if !slices.Contains(schemes, url.SchemeFile) {
				slog.Warn("local directory specified, but file scheme is not enabled")
			}

			path := filepath.Clean(fileDirectoryFlag)
			fi, err := os.Stat(path)
			if err != nil {
				if os.IsNotExist(err) {
					return fmt.Errorf("given directory %s does not exist", path)
				}
				return fmt.Errorf("failed to stat %s: %w", path, err)
			}
			if !fi.IsDir() {
				return fmt.Errorf("given path %s is not a directory", path)
			}
			fileDirectoryFlag = path
		} else if slices.Contains(schemes, url.SchemeFile) {
			return fmt.Errorf("file scheme is enabled, but no local directory was specified with the --file-directory flag")
		}

		// Log level
		if debugFlag {
			slog.SetLogLoggerLevel(slog.LevelDebug)
		} else {
			slog.SetLogLoggerLevel(slog.LevelInfo)
		}

		// Set up remote publication retrieval clients
		remote := serve.Remote{
			LocalDirectory: fileDirectoryFlag,
		}

		// 30 seconds to set up remote retrieval clients
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// S3
		if slices.Contains(schemes, url.SchemeS3) {
			options := []func(*config.LoadOptions) error{
				config.WithRegion(s3RegionFlag),
				config.WithRequestChecksumCalculation(0),
				config.WithResponseChecksumValidation(0),
				// TODO: look into custom HTTP client, user-agent
			}
			if s3AccessKeyFlag != "" && s3SecretKeyFlag != "" {
				options = append(options, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(s3AccessKeyFlag, s3SecretKeyFlag, "")))
			}
			cfg, err := config.LoadDefaultConfig(ctx, options...)
			if err != nil {
				log.Fatal(err)
			}
			_, err = cfg.Credentials.Retrieve(ctx)
			if err == nil {
				remote.S3 = s3.NewFromConfig(cfg, func(o *s3.Options) {
					if s3EndpointFlag != "" {
						o.BaseEndpoint = aws.String(s3EndpointFlag)
					}
					o.DisableLogOutputChecksumValidationSkipped = true // Non-AWS S3 tends not to support this and it causes logspam
					o.UsePathStyle = s3UsePathStyleFlag
				})
			} else {
				return fmt.Errorf("S3 credentials retrieval failed: %w", err)
			}
		} else if s3AccessKeyFlag != "" || s3SecretKeyFlag != "" || s3EndpointFlag != "" {
			slog.Warn("S3-related flags are set, but S3 scheme is not enabled")
		}

		// GCS
		var err error
		if slices.Contains(schemes, url.SchemeGS) {
			opts := []option.ClientOption{
				option.WithScopes(storage.ScopeReadOnly),
				storage.WithJSONReads(),
				// option.WithUserAgent(TODO),
				// TODO: look into more efficient transport (HTTP client)
			}
			remote.GCS, err = storage.NewClient(ctx, opts...)
			if err != nil {
				return fmt.Errorf("GCS client creation failed: %w", err)
			}
		}

		// HTTP/HTTPS
		remote.HTTP, err = client.NewHTTPClient(httpAuthorizationFlag)
		if err != nil {
			slog.Warn("HTTP client creation failed, HTTP support will be disabled", "error", err)
		}
		remote.HTTPEnabled = slices.Contains(schemes, url.SchemeHTTP)
		remote.HTTPSEnabled = slices.Contains(schemes, url.SchemeHTTPS)

		// Remote archive streaming tweaks
		remote.Config.CacheCountThreshold = int64(remoteArchiveCacheCount)
		remote.Config.CacheSizeThreshold = int64(remoteArchiveCacheSize)
		remote.Config.Timeout = time.Duration(remoteArchiveTimeoutFlag) * time.Second
		remote.Config.CacheAllThreshold = int64(remoteArchiveCacheAll)

		// Create server
		pubServer := serve.NewServer(serve.ServerConfig{
			Debug:             debugFlag,
			JSONIndent:        indentFlag,
			InferA11yMetadata: streamer.InferA11yMetadata(inferA11yFlag),
		}, remote)

		bind := fmt.Sprintf("%s:%d", bindAddressFlag, bindPortFlag)
		httpServer := &http.Server{
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
			Addr:           bind,
			Handler:        pubServer.Routes(),
		}
		slog.Info("Starting HTTP server", "address", "http://"+httpServer.Addr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			slog.Error("Server stopped", "error", err)
		} else {
			slog.Info("Goodbye!")
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringSliceVarP(&schemeFlag, "scheme", "s", []string{"file"}, "Scheme(s) to enable for accessing content. Acceptable values: file, http, https, s3, gs")
	serveCmd.Flags().StringVarP(&bindAddressFlag, "address", "a", "localhost", "Address to bind the HTTP server to")
	serveCmd.Flags().Uint16VarP(&bindPortFlag, "port", "p", 15080, "Port to bind the HTTP server to")
	serveCmd.Flags().StringVarP(&indentFlag, "indent", "i", "", "Indentation used to pretty-print JSON files")
	serveCmd.Flags().Var(&inferA11yFlag, "infer-a11y", "Infer accessibility metadata: no, merged, split")
	serveCmd.Flags().BoolVarP(&debugFlag, "debug", "d", false, "Enable debug mode")

	serveCmd.Flags().StringVar(&fileDirectoryFlag, "file-directory", "", "Local directory path to serve publications from")

	serveCmd.Flags().StringVar(&s3EndpointFlag, "s3-endpoint", "", "Custom S3 endpoint URL")
	serveCmd.Flags().StringVar(&s3RegionFlag, "s3-region", "auto", "S3 region")
	serveCmd.Flags().StringVar(&s3AccessKeyFlag, "s3-access-key", "", "S3 access key")
	serveCmd.Flags().StringVar(&s3SecretKeyFlag, "s3-secret-key", "", "S3 secret key")
	serveCmd.Flags().BoolVar(&s3UsePathStyleFlag, "s3-use-path-style", false, "Use S3 path style buckets (default is to use virtual hosts)")

	serveCmd.Flags().StringVar(&httpAuthorizationFlag, "http-authorization", "", "HTTP authorization header value (e.g. 'Bearer <token>' or 'Basic <base64-credentials>')")

	serveCmd.Flags().Uint32Var(&remoteArchiveTimeoutFlag, "remote-archive-timeout", 60, "Timeout for remote archive requests (in seconds)")
	serveCmd.Flags().Uint32Var(&remoteArchiveCacheSize, "remote-archive-cache-size", 1024*1024, "Max size of items in an archive that can be cached (in bytes)")
	serveCmd.Flags().Uint32Var(&remoteArchiveCacheCount, "remote-archive-cache-count", 64, "Max number of items in an archive that can be cached")
	serveCmd.Flags().Uint32Var(&remoteArchiveCacheAll, "remote-archive-cache-all", 1024*1024, "Archives this size or less (in bytes) will be cached in full")
}
