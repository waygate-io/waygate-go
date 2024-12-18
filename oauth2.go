package waygate

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	oauth "github.com/anderspitman/little-oauth2-go"
	"github.com/mdp/qrterminal/v3"
	"github.com/waygate-io/waygate-go/josencillo"
)

//go:embed templates
var fs embed.FS

type OAuth2Handler struct {
	mux *http.ServeMux
}

func NewOAuth2Handler(db *Database, serverUri, prefix string, jose *josencillo.JOSE) *OAuth2Handler {

	tmpl, err := template.ParseFS(fs, "templates/*")
	exitOnError(err)

	mux := http.NewServeMux()

	kvStore, err := NewKvStore(db.db.DB)
	exitOnError(err)

	oauthServer := oauth.NewServer(serverUri+prefix, kvStore)

	mux.Handle("/device", oauthServer)
	mux.Handle("/device-verify", oauthServer)

	mux.HandleFunc("/user-verify", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		userCode := r.Form.Get("code")

		tmplData := struct {
			Prefix   string
			UserCode string
		}{
			Prefix:   prefix,
			UserCode: userCode,
		}

		err = tmpl.ExecuteTemplate(w, "user_verify.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/approve-device", func(w http.ResponseWriter, r *http.Request) {

		fmt.Println("/approve-device")

		r.ParseForm()

		userCode := r.Form.Get("user_code")
		domain := r.Form.Get("domain")

		issuedAt := time.Now().UTC()
		accessTokenJwt, err := jose.NewJWT(map[string]interface{}{
			"iat":    issuedAt,
			"type":   "access_token",
			"domain": domain,
		})

		tokenRes := &oauth.TokenResponse{
			AccessToken: accessTokenJwt,
			ExpiresIn:   3600,
			TokenType:   "bearer",
		}

		err = oauthServer.CompleteDeviceFlow(userCode, tokenRes)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		tmplData := struct {
			Domain string
		}{
			Domain: domain,
		}

		err = tmpl.ExecuteTemplate(w, "user_verify_success.html", tmplData)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}
	})

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {

		r.ParseForm()

		authReq, err := oauth.ParseAuthRequest(r.Form)
		if err != nil {
			w.WriteHeader(500)
			io.WriteString(w, err.Error())
			return
		}

		scopeParam := strings.Join(authReq.Scopes, " ")

		issuedAt := time.Now().UTC()
		jwt, err := jose.NewJWT(map[string]interface{}{
			"iat":                 issuedAt,
			"client_id":           authReq.ClientId,
			"redirect_uri":        authReq.RedirectUri,
			"scope":               scopeParam,
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
		tokenReq, err := oauth.ParseTokenRequest(r.Form)
		if err != nil {
			w.WriteHeader(400)
			io.WriteString(w, err.Error())
			return
		}

		if tokenReq.GrantType == "urn:ietf:params:oauth:grant-type:device_code" {
			oauthServer.ServeHTTP(w, r)
			return
		}

		codeJwt := tokenReq.Code

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
		Scopes:      []string{"waygate"},
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

		localUri := fmt.Sprintf("http://localhost:%d", f.port)

		tokenReq := &oauth.TokenRequest{
			Code:         code,
			RedirectUri:  fmt.Sprintf("%s/oauth2/callback", localUri),
			ClientId:     localUri,
			CodeVerifier: f.flowState.CodeVerifier,
		}

		tokenUri := fmt.Sprintf("%s/token", f.authServerUri)
		tokenRes, err := oauth.MakeTokenRequest(tokenUri, tokenReq)
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

func DoDeviceFlow() (string, error) {

	authServerUri := fmt.Sprintf("https://%s/oauth2", WaygateServerDomain)

	localUri := fmt.Sprintf("http://localhost")

	flow, err := oauth.StartDeviceFlow(authServerUri+"/device", &oauth.AuthRequest{
		ClientId: localUri,
		Scopes:   []string{"waygate"},
	})
	if err != nil {
		return "", err
	}

	qrterminal.GenerateHalfBlock(flow.DeviceResponse.VerificationUriComplete, qrterminal.L, os.Stdout)

	fmt.Println("Use the QR code above")

	fmt.Println("\nOr click the link below")
	fmt.Println(flow.DeviceResponse.VerificationUriComplete)

	fmt.Println("\nOr enter the link and code below")
	fmt.Println(flow.DeviceResponse.VerificationUri)
	fmt.Println(flow.DeviceResponse.UserCode)

	tokenRes, err := flow.Complete(authServerUri + "/token")
	if err != nil {
		return "", err
	}

	return tokenRes.AccessToken, nil
}
