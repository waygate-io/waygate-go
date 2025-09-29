package waygate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"

	oauth "github.com/anderspitman/little-oauth2-go"
	"github.com/mdp/qrterminal/v3"
)

type TokenFlow struct {
	flowState     *oauth.AuthCodeFlowState
	authServerUri string
	port          int
}

func NewTokenFlow() (*TokenFlow, error) {

	// TODO: use authPrefix instead of hard-coding
	authServerUri := fmt.Sprintf("https://%s/auth/oauth", WaygateServerDomain)

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
