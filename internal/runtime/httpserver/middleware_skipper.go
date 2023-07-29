package httpserver

import (
	"fmt"
	"strings"
)

// middlewareName: name of middleware
type middlewareName string

// skippedPath: path to be skipped
//
// a key value of path and list of http method
type skippedPath map[string][]string

// skipList: pool, which path to be skip on a specific middleware
type skipMiddleware map[middlewareName]skippedPath

const (
	middlewareAuth   middlewareName = "auth"
	middlewareLogger middlewareName = "logger"
)

type skipParams struct {
	method      string
	path        string
	paramNames  []string
	paramValues []string
}

// ***

// skip: register which endpoint to skip the middleware
func (h *HttpServerHandler) skip(name middlewareName, method string, path string) {
	if len(h.skipMiddleware) == 0 {
		h.skipMiddleware = make(skipMiddleware)
	}
	if len(h.skipMiddleware[name]) == 0 {
		h.skipMiddleware[name] = make(skippedPath)
	}

	h.skipMiddleware[name][path] = append(h.skipMiddleware[name][path], method)
}

// isSkipped: check endpoint must skip the middleware or not
func (h *HttpServerHandler) isSkipped(name middlewareName, params skipParams) (skip bool) {
	path := h.translatePath(params.path, params.paramNames, params.paramValues)

	methods := h.skipMiddleware[name][path]
	if len(methods) == 0 {
		return
	}
	for _, m := range methods {
		if m == params.method {
			return true
		}
	}
	return
}

// translatePath: translate given path
func (h *HttpServerHandler) translatePath(path string, paramNames []string, paramValues []string) string {
	if len(paramValues) == 0 {
		return path
	}

	for i, v := range paramValues {
		path = strings.Replace(path, v, fmt.Sprintf(":%s", paramNames[i]), 1)
	}
	return path
}
