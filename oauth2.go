package waygate

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
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

		r.ParseForm()

		authReq, err := oauth.ParseAuthRequest(r.Form)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
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

		r.ParseForm()

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

		state := claims["state"].(string)
		fullRedirectUri := fmt.Sprintf("%s?code=%s&state=%s", redirectUri, codeJwt, state)

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

		tokenRes := oauth.TokenResponse{
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

type TokenFlow struct {
	flowState     *oauth.AuthCodeFlowState
	authServerUri string
	port          int
}

func NewTokenFlow() (*TokenFlow, error) {

	authServerUri := fmt.Sprintf("https://%s/oauth2", WaygateServerDomain)

	port, err := randomOpenPort()
	if err != nil {
		return nil, err
	}

	localUri := fmt.Sprintf("http://localhost:%d", port)

	flowState, err := oauth.StartAuthCodeFlow(authServerUri+"/authorize", &oauth.AuthRequest{
		ClientId:    localUri,
		RedirectUri: fmt.Sprintf("%s/oauth2/callback", localUri),
		Scope:       "waygate",
	})
	if err != nil {
		return nil, err
	}

	flow := &TokenFlow{
		flowState:     flowState,
		authServerUri: authServerUri,
		port:          port,
	}

	return flow, nil
}

func (f *TokenFlow) GetAuthUri() string {
	return f.flowState.AuthUri
}

func (f *TokenFlow) GetToken() (string, error) {
	return f.GetTokenWithRedirect(nil)
}

func (f *TokenFlow) GetTokenWithRedirect(redirUriCh chan string) (string, error) {

	debugToken := os.Getenv("WAYGATE_DEBUG_TOKEN")
	if debugToken != "" && debugToken != "reset" {
		if redirUriCh != nil {
			go func() {
				fmt.Println("would redirect to", <-redirUriCh)
			}()
		}
		fmt.Println("WAYGATE_DEBUG_TOKEN:", debugToken)
		return debugToken, nil
	}

	mux := http.NewServeMux()

	listenStr := fmt.Sprintf(":%d", f.port)
	server := &http.Server{
		Addr:    listenStr,
		Handler: mux,
	}

	tokenCh := make(chan string)

	mux.HandleFunc("/oauth2/callback", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		stateParam := r.Form.Get("state")
		if stateParam != f.flowState.State {
			w.WriteHeader(500)
			io.WriteString(w, "Invalid state param")
			return
		}

		code := r.Form.Get("code")

		httpClient := &http.Client{}

		params := url.Values{}
		params.Set("code", code)
		body := strings.NewReader(params.Encode())

		tokenUri := fmt.Sprintf("%s/token", f.authServerUri)

		req, err := http.NewRequest(http.MethodPost, tokenUri, body)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

		res, err := httpClient.Do(req)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		//if res.StatusCode != 200 {
		//	w.WriteHeader(500)
		//	io.WriteString(w, "Bad HTTP response code")
		//	return
		//}

		var tokenRes oauth.TokenResponse

		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		err = json.Unmarshal(bodyBytes, &tokenRes)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		tokenCh <- tokenRes.AccessToken

		if redirUriCh != nil {
			redirUri := <-redirUriCh
			http.Redirect(w, r, redirUri, 303)
		}

		go func() {
			server.Shutdown(context.Background())
		}()
	})

	go server.ListenAndServe()

	token := <-tokenCh

	//fmt.Println(token)

	return token, nil
}
