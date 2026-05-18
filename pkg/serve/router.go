package serve

import (
	"log/slog"
	"net/http"
	"net/http/pprof"

	"github.com/CAFxX/httpcompression"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/readium/cli/pkg/serve/problems"
)

func (s *Server) Routes() *mux.Router {
	r := mux.NewRouter()

	r.Use(handlers.CORS(
		handlers.AllowedOrigins(s.config.CORSAllowedOrigins),
		handlers.AllowedMethods([]string{http.MethodGet, http.MethodHead, http.MethodOptions}),
		handlers.AllowedHeaders([]string{"Authorization", "Content-Type", "Range"}),
		handlers.ExposedHeaders([]string{"Content-Length", "Content-Range", "Accept-Ranges"}),
	))

	r.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	if s.config.Debug {
		r.HandleFunc("/debug/pprof/", pprof.Index)
		r.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		r.HandleFunc("/debug/pprof/profile", pprof.Profile)
		r.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		r.HandleFunc("/debug/pprof/trace", pprof.Trace)

		r.Handle("/debug/pprof/allocs", pprof.Handler("allocs"))
		r.Handle("/debug/pprof/block", pprof.Handler("block"))
		r.Handle("/debug/pprof/goroutine", pprof.Handler("goroutine"))
		r.Handle("/debug/pprof/heap", pprof.Handler("heap"))
		r.Handle("/debug/pprof/mutex", pprof.Handler("mutex"))
		r.Handle("/debug/pprof/threadcreate", pprof.Handler("threadcreate"))
	}

	pub := r.PathPrefix("/webpub/{path}").Subrouter()
	pub.Use(func(next http.Handler) http.Handler {
		adapter, _ := httpcompression.DefaultAdapter(httpcompression.ContentTypes(compressableMimes, false))
		return adapter(next)
	})
	pub.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			vars := mux.Vars(req)
			token := vars["path"]
			newRequest, aerr := s.config.Auth.Validate(w, req, token)
			if aerr == nil {
				next.ServeHTTP(w, newRequest)
				return
			}
			if len(aerr.RedirectPath) > 0 {
				ru, _ := r.Get("manifest").URLPath("path", aerr.RedirectPath)
				http.Redirect(w, req, ru.String(), aerr.StatusCode)
				return
			}

			var p error
			switch aerr.StatusCode {
			case http.StatusBadRequest:
				slog.DebugContext(req.Context(), "auth validation failed", "error", aerr.Err, "status", aerr.StatusCode)
				p = problems.BadRequest.Build().Wrap(aerr.Err).Detail(aerr.Err.Error()).Problem()
			case http.StatusForbidden:
				slog.DebugContext(req.Context(), "auth validation failed", "error", aerr.Err, "status", aerr.StatusCode)
				p = problems.Forbidden.Build().Wrap(aerr.Err).Detail(aerr.Err.Error()).Problem()
			case http.StatusGone:
				slog.DebugContext(req.Context(), "auth validation failed", "error", aerr.Err, "status", aerr.StatusCode)
				p = problems.Gone.Build().Wrap(aerr.Err).Detail(aerr.Err.Error()).Problem()
			default:
				slog.ErrorContext(req.Context(), "auth validation failed", "error", aerr.Err, "status", aerr.StatusCode)
				p = problems.Internal("", aerr.Err)
			}
			problems.Write(p, w, req)
		})
	})
	pub.HandleFunc("", func(w http.ResponseWriter, req *http.Request) {
		ru, _ := r.Get("manifest").URLPath("path", mux.Vars(req)["path"])
		http.Redirect(w, req, ru.String(), http.StatusFound)
	})
	pub.HandleFunc("/manifest.json", s.getManifest).Name("manifest")
	pub.HandleFunc("/{asset:.*}", s.getAsset).Name("asset")

	s.router = r
	return r
}
