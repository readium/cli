package serve

import (
	"context"
	"net/http"
	"net/http/pprof"

	"github.com/CAFxX/httpcompression"
	"github.com/gorilla/mux"
)

type ContextKey string

const ContextPathKey ContextKey = "path"

func (s *Server) Routes() *mux.Router {
	r := mux.NewRouter()

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
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			vars := mux.Vars(r)
			token := vars["path"]
			newPath, status, err := s.config.Auth.Validate(token)
			if err != nil {
				http.Error(w, err.Error(), status)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ContextPathKey, newPath)))
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
