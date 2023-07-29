package httpserver

import (
	"net/http"
	"strings"
)

const (
	AuthorizationBearer = "Bearer "

	HeaderAuthorization  = "Authorization"
	HeaderAcceptLanguage = "Accept-Language"
)

// *** request extractor

type req struct {
	request *http.Request
}

func extractRequest(r *http.Request) req {
	return req{
		request: r,
	}
}

func (r req) getAuthorization() string {
	if len(r.request.Header[HeaderAuthorization]) == 0 {
		return ""
	}

	return strings.Replace(r.request.Header[HeaderAuthorization][0], AuthorizationBearer, "", -1)
}

func (r req) getLang() string {
	if len(r.request.Header[HeaderAcceptLanguage]) == 0 {
		return "en"
	}
	return r.request.Header[HeaderAcceptLanguage][0]
}
