package waygate

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/lastlogin-io/obligator"
	"github.com/waygate-io/waygate-go/josencillo"
)

//go:embed templates
var fs embed.FS

type OAuth2Handler struct {
	mux *http.ServeMux
}

func NewOAuth2Handler(prefix string, jose *josencillo.JOSE) *OAuth2Handler {

	tmpl, err := template.ParseFS(fs, "templates/*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {

		authReq, err := obligator.ParseAuthRequest(w, r)
		if err != nil {
			return
		}

		issuedAt := time.Now().UTC()
		jwt, err := jose.NewJWT(map[string]interface{}{
			"iat":                 issuedAt,
			"client_id":           authReq.ClientId,
			"redirect_uri":        authReq.RedirectUri,
			"scope":               authReq.Scope,
			"state":               authReq.State,
			"pkce_code_challenge": authReq.CodeChallenge,
		})
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		err = setCookie(w, r, "waygate_auth_request", jwt, 8*60)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		tmplData := struct {
			Prefix      string
			RedirectUri string
		}{
			Prefix:      prefix,
			RedirectUri: authReq.RedirectUri,
		}

		err = tmpl.ExecuteTemplate(w, "authorize.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/approve", func(w http.ResponseWriter, r *http.Request) {

		jwtCookie, err := r.Cookie("waygate_auth_request")
		if err != nil {
			w.WriteHeader(401)
			io.WriteString(w, err.Error())
			return
		}

		if jwtCookie.Value == "" {
			w.WriteHeader(401)
			io.WriteString(w, "No auth request cookie present")
			return
		}

		claims, err := jose.ParseJWT(jwtCookie.Value)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		domain := r.Form.Get("domain")

		issuedAt := time.Now().UTC()
		codeJwt, err := jose.NewJWT(map[string]interface{}{
			"iat":    issuedAt,
			"type":   "code",
			"domain": domain,
		})
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		redirectUri := claims["redirect_uri"].(string)

		fullRedirectUri := obligator.AuthUri(redirectUri, &obligator.OAuth2AuthRequest{
			ClientId:     claims["client_id"].(string),
			RedirectUri:  redirectUri,
			ResponseType: "code",
			Scope:        "waygate",
			State:        claims["state"].(string),
		})

		fullRedirectUri = fmt.Sprintf("%s&code=%s", fullRedirectUri, codeJwt)

		http.Redirect(w, r, fullRedirectUri, 307)
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		// TODO: proper Access Token Request parsing: https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.3
		codeJwt := r.Form.Get("code")

		claims, err := jose.ParseJWT(codeJwt)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		issuedAt := time.Now().UTC()
		accessTokenJwt, err := jose.NewJWT(map[string]interface{}{
			"iat":    issuedAt,
			"type":   "access_token",
			"domain": claims["domain"].(string),
		})

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")

		tokenRes := obligator.OAuth2TokenResponse{
			AccessToken: accessTokenJwt,
			ExpiresIn:   3600,
			TokenType:   "bearer",
		}

		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		enc.Encode(tokenRes)
	})

	h := &OAuth2Handler{
		mux: mux,
	}

	return h
}

func (h *OAuth2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mux.ServeHTTP(w, r)
}
