package waygate

import (
	"io"
	"net/http"
)

type OAuth2Handler struct {
}

func NewOAuth2Handler() *OAuth2Handler {
	h := &OAuth2Handler{}

	return h
}

func (h *OAuth2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	//w.Write([]byte("<h1>Hi there OAuth2Handler</h1>"))
	redirectUri := r.Form.Get("redirect_uri")
	if redirectUri == "" {
		w.WriteHeader(400)
		io.WriteString(w, "redirect_uri missing")
		return
	}

	http.Redirect(w, r, redirectUri, 307)
}
