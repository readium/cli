package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"log/slog"

	nurl "net/url"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/pkg/errors"
	"github.com/readium/cli/pkg/serve"
	"github.com/readium/cli/pkg/serve/auth"
	"github.com/readium/cli/pkg/serve/client"
	"github.com/readium/cli/pkg/serve/session"
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

var mode string

// JWT/JWKS flags
var jwtSharedSecret string
var jwksURL string

// Bonding flags
var bondingDefaultMaxDevices uint16
var bondingMaxBondsPerSubject uint16
var bondingMaxCacheSize uint
var bondingMinDeviceEvictionInterval time.Duration
var bondingCookiePrefix string
var bondingCookieSubfolder string
var bondingSecret string

// Cloud-related flags
var s3EndpointFlag string
var s3RegionFlag string
var s3AccessKeyFlag string
var s3SecretKeyFlag string
var s3UsePathStyleFlag bool

// HTTP client flags
var httpHostWhitelistFlag []string
var httpUnsafeRequestsFlag bool
var httpAuthorizationFlag string
var specificHttpAuthorizationFlag []string

// Remote archive flags
var remoteArchiveTimeoutFlag uint32
var remoteArchiveCacheSize uint32
var remoteArchiveCacheCount uint32
var remoteArchiveCacheAll uint32

// Web flags
var corsAllowedOriginsFlag []string

// Audio parsing flags
var audioEmbeddedChaptersFlag bool
var audioParsingConcurrency uint8
var audioParsingCacheBlockSize uint32
var audioParsingCacheRetain bool

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start a local HTTP server, serving publications locally or remotely",
	Long: `Start a local HTTP server, serving publications locally or remotely.

This command will start an HTTP server listening by default on 'localhost:15080',
serving all compatible files (EPUB, PDF, CBZ, etc.) available from the enabled
access schemes (file, http, https, s3, gs, or a local path if file scheme is enabled)
as Readium Web Publications. To get started, the manifest can be accessed from
'http://localhost:15080/<filename in base64url encoding without padding>/manifest.json'.
This file serves as the entry point and contains metadata and links to the rest
of the files that can be accessed for the publication.

Authentication can be enabled using the -m flag, which replaces the  encoded path
with a JWT. Before exposing this server publicly, consider using this flag to secure
access to publications and prevent abuse or unauthorized access.`,
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
			case url.SchemeFile, url.SchemeHTTP, url.SchemeHTTPS, url.SchemeS3, url.SchemeGS, session.SchemeReadingSession:
				schemes[i] = lowerScheme
			default:
				return fmt.Errorf("invalid scheme %q, acceptable values: file, http, https, s3, gs, session", v)
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
				return fmt.Errorf("failed loading AWS config: %w", err)
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
		urlWhitelist := make([]*nurl.URL, len(httpHostWhitelistFlag))
		for i, rawURL := range httpHostWhitelistFlag {
			parsedURL, err := nurl.Parse(rawURL)
			if err != nil {
				return fmt.Errorf("invalid URL in whitelist: %s: %w", rawURL, err)
			}
			if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
				return fmt.Errorf("whitelisted URL %s must have http or https scheme", rawURL)
			}
			if parsedURL.Host == "" {
				return fmt.Errorf("whitelisted URL %s must have a host", rawURL)
			}
			urlWhitelist[i] = parsedURL
		}
		hostAuthMap := map[string]string{
			"*": httpAuthorizationFlag, // Default authorization
		}
		for _, entry := range specificHttpAuthorizationFlag {
			parts := strings.SplitN(entry, "::", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid specific HTTP authorization entry: %s, expected format 'host::authorization'", entry)
			}
			host := parts[0]
			auth := parts[1]
			hostAuthMap[host] = auth
		}
		remote.HTTP, err = client.NewHTTPClient(hostAuthMap, urlWhitelist, httpUnsafeRequestsFlag)
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

		// Reading session fetcher
		var readingSessionFetcher session.Fetcher
		if slices.Contains(schemes, session.SchemeReadingSession) {
			readingSessionFetcher = session.NewHTTPFetcher(remote.HTTP)
		}

		var authProvider auth.AuthProvider
		switch mode {
		case "base64":
			authProvider = auth.NewB64EncodedAuthProvider()
			slog.Info("Operating in open access mode with base64url encoding (insecure)")
		case "jwt":
			var sharedSecret []byte
			if jwtSharedSecret == "" {
				// Auto-generate shared secret
				var rawSecret [32]byte
				_, err := rand.Reader.Read(rawSecret[:])
				if err != nil {
					return fmt.Errorf("failed to generate random shared secret: %w", err)
				}
				sharedSecret = rawSecret[:]
				slog.Info("Operating in HS256 JWT access mode", "secret", hex.EncodeToString(sharedSecret))
			} else {
				sharedSecret, err = hex.DecodeString(jwtSharedSecret)
				if err != nil {
					return fmt.Errorf("failed to decode hex-encoded JWT shared secret: %w", err)
				}
				slog.Info("Operating in HS256 JWT access mode", "secret", "<jwt-shared-secret flag>")
			}
			authProvider, err = auth.NewJWTAuthProvider(sharedSecret)
			if err != nil {
				return fmt.Errorf("failed creating JWT auth provider: %w", err)
			}
		case "jwks":
			if jwksURL == "" {
				return fmt.Errorf("jwks-url must be specified in jwks mode")
			}
			slog.Info("Operating in JWKS JWT access mode", "jwks_url", jwksURL)
			authProvider, err = auth.NewJWKSAuthProvider(context.Background(), remote.HTTP, jwksURL)
			if err != nil {
				return fmt.Errorf("failed creating JWKS auth provider: %w", err)
			}
		case "jwt-bonding":
			if !slices.Contains(schemes, session.SchemeReadingSession) {
				return fmt.Errorf("in jwt-bonding mode, the reading session scheme must be enabled")
			}

			var sharedSecret []byte
			if jwtSharedSecret == "" {
				// Auto-generate shared secret
				var rawSecret [32]byte
				_, err := rand.Reader.Read(rawSecret[:])
				if err != nil {
					return fmt.Errorf("failed to generate random shared secret: %w", err)
				}
				sharedSecret = rawSecret[:]
				slog.Info("Operating in HS256 JWT access mode with bonding", "secret", hex.EncodeToString(sharedSecret))
			} else {
				sharedSecret, err = hex.DecodeString(jwtSharedSecret)
				if err != nil {
					return fmt.Errorf("failed to decode hex-encoded JWT shared secret: %w", err)
				}
				slog.Info("Operating in HS256 JWT access mode with bonding", "secret", "<jwt-shared-secret flag>")
			}
			var bs []byte
			if bondingSecret == "" {
				var rawBondingSecret [32]byte
				_, err := rand.Reader.Read(rawBondingSecret[:])
				if err != nil {
					return fmt.Errorf("failed to generate random bonding secret: %w", err)
				}
				bs = rawBondingSecret[:]
				slog.Info("No bonding secret provided, auto-generated one (not persisted, will change on restart)", "bonding_secret", hex.EncodeToString(bs))
			} else {
				bs, err = hex.DecodeString(bondingSecret)
				if err != nil {
					return fmt.Errorf("failed to decode hex-encoded bonding secret: %w", err)
				}
				slog.Info("Using provided bonding secret", "bonding_secret", "<bonding-secret flag>")
			}

			authProvider, err = auth.NewJWTBondingAuthProvider(sharedSecret, bs, bondingDefaultMaxDevices, bondingMaxBondsPerSubject, bondingMinDeviceEvictionInterval, bondingMaxCacheSize, bondingCookiePrefix, bondingCookieSubfolder)
			if err != nil {
				return fmt.Errorf("failed creating JWT auth provider: %w", err)
			}
		case "jwks-bonding":
			if jwksURL == "" {
				return fmt.Errorf("jwks-url must be specified in jwks-bonding mode")
			}
			if !slices.Contains(schemes, session.SchemeReadingSession) {
				return fmt.Errorf("in jwks-bonding mode, the reading session scheme must be enabled")
			}
			slog.Info("Operating in JWKS JWT access mode with bonding", "jwks_url", jwksURL)

			var bs []byte
			if bondingSecret == "" {
				var rawBondingSecret [32]byte
				_, err := rand.Reader.Read(rawBondingSecret[:])
				if err != nil {
					return fmt.Errorf("failed to generate random bonding secret: %w", err)
				}
				bs = rawBondingSecret[:]
				slog.Info("No bonding secret provided, auto-generated one (not persisted, will change on restart)", "bonding_secret", hex.EncodeToString(bs))
			} else {
				bs, err = hex.DecodeString(bondingSecret)
				if err != nil {
					return fmt.Errorf("failed to decode hex-encoded bonding secret: %w", err)
				}
				slog.Info("Using provided bonding secret", "bonding_secret", "<bonding-secret flag>")
			}

			authProvider, err = auth.NewJWKSBondingAuthProvider(context.Background(), remote.HTTP, jwksURL, bs, bondingDefaultMaxDevices, bondingMaxBondsPerSubject, bondingMinDeviceEvictionInterval, bondingMaxCacheSize, bondingCookiePrefix, bondingCookieSubfolder)
			if err != nil {
				return fmt.Errorf("failed creating JWKS bonding auth provider: %w", err)
			}
		default:
			return fmt.Errorf("invalid access mode %q, acceptable values: base64, jwt, jwks, jwt-bonding, jwks-bonding", mode)
		}

		// Create server
		pubServer := serve.NewServer(serve.ServerConfig{
			Debug:                 debugFlag,
			JSONIndent:            indentFlag,
			InferA11yMetadata:     streamer.InferA11yMetadata(inferA11yFlag),
			Auth:                  authProvider,
			ReadingSessionFetcher: readingSessionFetcher,
			CORSAllowedOrigins:    corsAllowedOriginsFlag,

			AudioEmbeddedChapters:      audioEmbeddedChaptersFlag,
			AudioParsingConcurrency:    audioParsingConcurrency,
			AudioParsingCacheBlockSize: audioParsingCacheBlockSize,
			AudioParsingCacheRetain:    audioParsingCacheRetain,
		}, remote)

		bind := fmt.Sprintf("%s:%d", bindAddressFlag, bindPortFlag)
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		httpServer := &http.Server{
			ReadTimeout:    10 * time.Second,
			IdleTimeout:    120 * time.Second,
			MaxHeaderBytes: 1 << 20,
			Addr:           bind,
			Handler:        pubServer.Routes(),
			Protocols:      protocols,
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

	serveCmd.Flags().StringSliceVarP(&schemeFlag, "scheme", "s", []string{url.SchemeFile.String()}, "Scheme(s) to enable for accessing content. Acceptable values: file, http, https, s3, gs, session")
	serveCmd.Flags().StringVarP(&bindAddressFlag, "address", "a", "localhost", "Address to bind the HTTP server to")
	serveCmd.Flags().Uint16VarP(&bindPortFlag, "port", "p", 15080, "Port to bind the HTTP server to")
	serveCmd.Flags().StringVarP(&indentFlag, "indent", "i", "", "Indentation used to pretty-print JSON files")
	serveCmd.Flags().Var(&inferA11yFlag, "infer-a11y", "Infer accessibility metadata: no, merged, split")
	serveCmd.Flags().BoolVarP(&debugFlag, "debug", "d", false, "Enable debug mode")
	serveCmd.Flags().StringVarP(&mode, "mode", "m", "base64", "Access mode: base64 (default, base64url-encoded paths), jwt (JWT auth with a shared secret), jwks (JWT auth with keys in a JWKS), jwt-bonding (JWT auth with device bonding), jwks-bonding (JWKS-backed JWT auth with device bonding")

	serveCmd.Flags().StringVar(&jwtSharedSecret, "jwt-shared-secret", "", "Hex-encoded shared secret used for HS256 JWT signature validation. If omitted, but JWT auth is enabled, the secret is auto-generated and logged (debug) at runtime")
	serveCmd.Flags().StringVar(&jwksURL, "jwks-url", "", "URL to a JWKS (JSON Web Key Set) used for JWT signature validation when in 'jwks' mode")

	serveCmd.Flags().Uint16Var(&bondingDefaultMaxDevices, "bonding-default-max-devices", 2, "If not set in content rights, the default maximum number of devices to allow for bonding to a JWT in jwt-weak-bonding mode")
	serveCmd.Flags().Uint16Var(&bondingMaxBondsPerSubject, "bonding-max-bonds-per-subject", 100, "Ceiling on bonded devices tracked per JWT subject for rights-limited publications. Caps the effective device limit to defend against sessions declaring unreasonable per-publication device counts. Publications with unlimited devices bypass the cache entirely and aren't affected. Set to 0 to disable (use only the publication's own limit)")
	serveCmd.Flags().StringVar(&bondingSecret, "bonding-secret", "", "Hex-encoded secret used for bonding cookies and other data. Strongly recommended for persistence after restarts")
	serveCmd.Flags().UintVar(&bondingMaxCacheSize, "bonding-max-cache-size", 10_000, "Determines the size of the cache storing session bonding information. As # of sessions (JWT `sub`) approaches this number, reading session bonds will be evicted from cache. If using `jti` in the JWT, multiply # of sessions by ~2x")
	serveCmd.Flags().DurationVar(&bondingMinDeviceEvictionInterval, "bonding-min-device-eviction-interval", time.Second*30, "Minimum interval before a device can be replaced with a new one in the cache. The shorter the interval, the more abuse potential")
	serveCmd.Flags().StringVar(&bondingCookiePrefix, "cookie-prefix", "bonding", "Prefix for the cookie names used for device bonding")
	serveCmd.Flags().StringVar(&bondingCookieSubfolder, "cookie-subfolder", "", "Subfolder for paths of cookies set by the webserver, don't use unless it's running in a specific subfolder through a proxy")

	serveCmd.Flags().StringVar(&fileDirectoryFlag, "file-directory", "", "Local directory path to serve publications from")

	serveCmd.Flags().StringVar(&s3EndpointFlag, "s3-endpoint", "", "Custom S3 endpoint URL")
	serveCmd.Flags().StringVar(&s3RegionFlag, "s3-region", "auto", "S3 region")
	serveCmd.Flags().StringVar(&s3AccessKeyFlag, "s3-access-key", "", "S3 access key")
	serveCmd.Flags().StringVar(&s3SecretKeyFlag, "s3-secret-key", "", "S3 secret key")
	serveCmd.Flags().BoolVar(&s3UsePathStyleFlag, "s3-use-path-style", false, "Use S3 path style buckets (default is to use virtual hosts)")

	serveCmd.Flags().StringSliceVar(&httpHostWhitelistFlag, "http-host-whitelist", []string{}, "Whitelist of HTTP hosts/paths to allow for remote HTTP requests (e.g. 'http://1.1.1.1', 'https://na1.storage.example.com/the/path'). If omitted, anything that resolves to a public IP is allowed.")
	serveCmd.Flags().BoolVar(&httpUnsafeRequestsFlag, "http-unsafe-requests", false, "Allow potentially unsafe HTTP requests to private IP addresses (e.g. localhost). Enable only if you completely control the requests made to the server, otherwise this can be dangerous")
	serveCmd.Flags().StringVar(&httpAuthorizationFlag, "http-authorization", "", "HTTP authorization header value (e.g. 'Bearer <token>' or 'Basic <base64-credentials>')")
	serveCmd.Flags().StringSliceVar(&specificHttpAuthorizationFlag, "http-host-authorization", []string{}, "Specific HTTP authorization header values for specific hosts/paths, in the format 'host::authorization', for example 'example.com::Bearer abc123'")

	serveCmd.Flags().Uint32Var(&remoteArchiveTimeoutFlag, "remote-archive-timeout", 60, "Timeout for remote archive requests (in seconds)")
	serveCmd.Flags().Uint32Var(&remoteArchiveCacheSize, "remote-archive-cache-size", 1024*1024, "Max size of items in an archive that can be cached (in bytes)")
	serveCmd.Flags().Uint32Var(&remoteArchiveCacheCount, "remote-archive-cache-count", 64, "Max number of items in an archive that can be cached")
	serveCmd.Flags().Uint32Var(&remoteArchiveCacheAll, "remote-archive-cache-all", 1024*1024, "Archives this size or less (in bytes) will be cached in full")

	serveCmd.Flags().BoolVar(&audioEmbeddedChaptersFlag, "audio-embedded-chapters", true, "Whether to parse chapters embedded in audio files, in particular M4B. Will cause more range reads to be made on audio files, increasing load time")
	serveCmd.Flags().Uint8Var(&audioParsingConcurrency, "audio-parsing-concurrency", 8, "Number of audio files to parse concurrently when retrieving metadata and chapters. Also bounds the parallel range reads made within a single file (e.g. fetching scattered chapter titles)")
	serveCmd.Flags().Uint32Var(&audioParsingCacheBlockSize, "audio-parsing-cache-block-size", 256<<10, "Block size in bytes for the read cache used when parsing audio files for metadata and chapters. Larger blocks may reduce the number of range requests but increase data transfer for scattered reads")
	serveCmd.Flags().BoolVar(&audioParsingCacheRetain, "audio-parsing-cache-retain", true, "Keep the data fetched while parsing remote audiobooks in memory and serve matching byte ranges from it. Browsers request exactly these ranges (container header, embedded chapters) before starting playback, so this significantly reduces the time to first audio. Disable to save memory (roughly one cache block per chapter plus the file headers)")

	serveCmd.Flags().StringSliceVar(&corsAllowedOriginsFlag, "cors-allowed-origin", []string{"*"}, "Allowed origins for CORS requests. Repeat the flag or comma-separate to allow multiple origins (e.g. 'https://reader.example.com'). Use '*' to allow any origin")
}
