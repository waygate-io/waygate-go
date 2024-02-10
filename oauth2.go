package waygate

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
)

//go:embed templates
var fs embed.FS

type OAuth2Handler struct {
	mux *http.ServeMux
}

func NewOAuth2Handler(prefix string) *OAuth2Handler {

	tmpl, err := template.ParseFS(fs, "templates/*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		redirectUri := r.Form.Get("redirect_uri")
		if redirectUri == "" {
			w.WriteHeader(400)
			io.WriteString(w, "redirect_uri missing")
			return
		}

		tmplData := struct {
			Prefix      string
			RedirectUri string
		}{
			Prefix:      prefix,
			RedirectUri: redirectUri,
		}

		err = tmpl.ExecuteTemplate(w, "authorize.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/approve", func(w http.ResponseWriter, r *http.Request) {

		redirectUri := r.Form.Get("redirect_uri")
		if redirectUri == "" {
			w.WriteHeader(400)
			io.WriteString(w, "redirect_uri missing")
			return
		}

		http.Redirect(w, r, redirectUri, 307)
	})

	h := &OAuth2Handler{
		mux: mux,
	}

	return h
}

func (h *OAuth2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
