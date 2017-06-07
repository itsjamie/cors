/*
This code implements the flow chart that can be found here.
http://www.html5rocks.com/static/images/cors_server_flowchart.png
A Default Config for example is below:
	cors.Config{
		Origins:        "*",
		Methods:        "GET, PUT, POST, DELETE",
		RequestHeaders: "Origin, Authorization, Content-Type",
		ExposedHeaders: "",
		MaxAge: 1 * time.Minute,
		Credentials: true,
		ValidateHeaders: false,
	}
*/
package cors

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	allowOrigin      string = "Access-Control-Allow-Origin"
	allowCredentials        = "Access-Control-Allow-Credentials"
	allowHeaders            = "Access-Control-Allow-Headers"
	allowMethods            = "Access-Control-Allow-Methods"
	maxAge                  = "Access-Control-Max-Age"

	origin         = "Origin"
	requestMethod  = "Access-Control-Request-Method"
	requestHeaders = "Access-Control-Request-Headers"
	exposeHeaders  = "Access-Control-Expose-Headers"

	optionsMethod = "OPTIONS"
)

// Options defines the configuration options available to control how the CORS middleware should function.
type Options struct {
	// Enabling this causes us to compare Request-Method and Request-Headers to confirm they contain a subset of the Allowed Methods and Allowed Headers. The spec however allows for the server to always match, and simply return the allowed methods and headers. Either is supported in this middleware.
	ValidateHeaders bool

	// Comma delimited list of origin domains. Wildcard "*" is also allowed, and matches all origins. If the origin does not match an item in the list, then the request is denied.
	Origins string
	origins []string

	// This are the headers that the resource supports, and will accept in the request. Default is "Authorization".
	RequestHeaders string
	requestHeaders []string

	// These are headers that should be accessable by the CORS client, they are in addition to those defined by the spec as "simple response headers"
	//	 Cache-Control
	//	 Content-Language
	//	 Content-Type
	//	 Expires
	//	 Last-Modified
	//	 Pragma
	ExposedHeaders string

	// Comma delimited list of acceptable HTTP methods.
	Methods string
	methods []string

	// The amount of time in seconds that the client should cache the Preflight request
	MaxAge time.Duration
	maxAge string

	// If true, then cookies and Authorization headers are allowed along with the request. This is passed to the browser, but is not enforced.
	Credentials bool
	credentials string

	forceOriginMatch bool
}

// prepare a configuration for usage by the handler
func (o *Options) prepare() {
	o.origins = strings.Split(o.Origins, ", ")
	o.methods = strings.Split(o.Methods, ", ")
	o.requestHeaders = strings.Split(o.RequestHeaders, ", ")
	o.maxAge = fmt.Sprintf("%.f", o.MaxAge.Seconds())

	// Generates a boolean of value "true".
	o.credentials = fmt.Sprintf("%t", o.Credentials)

	if o.Origins == "*" {
		o.forceOriginMatch = true
	}

	// Convert to lower-case once as request headers are supposed to be a case-insensitive match
	for idx, header := range o.requestHeaders {
		o.requestHeaders[idx] = strings.ToLower(header)
	}
}

// Handler will handle CORS.
type Handler struct {
	next    http.Handler
	options Options
}

// New returns a HTTP handler that will handle CORS requests, and forward to the next handler if the request should proceed.
func New(o Options) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if o.Origins == "" {
			panic("You must set at least a single valid origin. If you don't want CORS, to apply, simply remove the middleware.")
		}

		o.prepare()

		return Handler{
			next:    next,
			options: o,
		}
	}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Read the Origin header from the HTTP request
	currentOrigin := r.Header.Get(origin)
	w.Header().Add("Vary", origin)

	// CORS headers are added whenever the browser request includes an "Origin" header. However, if no Origin is supplied, they should never be added.
	if currentOrigin == "" {
		h.next.ServeHTTP(w, r)
		return
	}

	originMatch := false
	if !h.options.forceOriginMatch {
		originMatch = matchOrigin(currentOrigin, h.options.origins)
	}

	if h.options.forceOriginMatch || originMatch {
		valid := false
		preflight := false

		if r.Method == optionsMethod {
			if requestMethod := r.Header.Get(requestMethod); requestMethod != "" {
				preflight = true
				valid = handlePreflight(h, requestMethod, w, r)
			}
		}

		if !preflight {
			valid = handleRequest(h, w)
		}

		if valid {

			if h.options.Credentials {
				w.Header().Set(allowCredentials, h.options.credentials)
				// Allowed origins cannot be the string "*" cannot be used for a resource that supports credentials.
				w.Header().Set(allowOrigin, currentOrigin)
			} else if h.options.forceOriginMatch {
				w.Header().Set(allowOrigin, "*")
			} else {
				w.Header().Set(allowOrigin, currentOrigin)
			}

			// If this is a preflight request, we are finished, quit.
			if preflight {
				w.WriteHeader(http.StatusOK)
				return
			}
			h.next.ServeHTTP(w, r)
		}
	}

	return // callpath that does not involve forwarding the request, either origin mismatch or invalid
}

// Case-sensitive match of origin header
func matchOrigin(targetOrigin string, origins []string) bool {
	for _, value := range origins {
		if value == targetOrigin {
			return true
		}
	}
	return false
}

// handlePreflight handles the initial request that is sent to determine if a cross-origin request should be allowed
func handlePreflight(h Handler, requestMethod string, w http.ResponseWriter, r *http.Request) bool {
	if !h.options.ValidateHeaders {
		if ok := validateRequestMethod(requestMethod, h.options.methods); !ok {
			return false
		}

		if ok := validateRequestHeaders(r.Header.Get(requestHeaders), h.options.requestHeaders); !ok {
			return false
		}
	}

	w.Header().Set(allowMethods, h.options.Methods)
	w.Header().Set(allowHeaders, h.options.RequestHeaders)
	if h.options.maxAge != "0" {
		w.Header().Set(maxAge, h.options.maxAge)
	}

	return true
}

func handleRequest(h Handler, w http.ResponseWriter) bool {
	if h.options.ExposedHeaders != "" {
		w.Header().Set(exposeHeaders, h.options.ExposedHeaders)
	}

	return true
}

// Case-sensitive match of request method
func validateRequestMethod(requestMethod string, methods []string) bool {
	if requestMethod != "" {
		for _, value := range methods {
			if value == requestMethod {
				return true
			}
		}
	}

	return false
}

// Case-insensitive match of request headers
func validateRequestHeaders(requestHeaders string, allowedRequestHeaders []string) bool {
	headers := strings.Split(requestHeaders, ",")

	for _, header := range headers {
		match := false
		header = strings.ToLower(strings.Trim(header, " \t\r\n"))

		for _, value := range allowedRequestHeaders {
			if value == header {
				match = true
				break
			}
		}

		if !match {
			return false
		}
	}

	return true
}
