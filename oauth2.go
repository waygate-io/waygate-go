package waygate

import (
	"net/http"
)

type OAuth2Handler struct {
}

func NewOAuth2Handler() *OAuth2Handler {
	h := &OAuth2Handler{}

	return h
}

func (h *OAuth2Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<h1>Hi there OAuth2Handler</h1>"))
}
