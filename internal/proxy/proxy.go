package proxy

import (
	"context"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"

	"github.com/Zhantec/credentials-broker/internal/config"
)

type SecretResolver interface {
	GetSecret(secretPath, secretName string) (string, error)
}

// Serve returns a dispatch function for proxy-mode targets: it resolves the
// target's secret, forwards the request to target.BaseURL with the secret
// injected as a header, and streams the upstream response back verbatim.
func Serve(secrets SecretResolver, httpClient *http.Client) func(http.ResponseWriter, *http.Request, *config.Target) {
	return func(w http.ResponseWriter, r *http.Request, target *config.Target) {
		secretPath, secretName := target.SecretPathAndName()
		secret, err := secrets.GetSecret(secretPath, secretName)
		if err != nil {
			log.Printf("proxy: resolving secret for target %s: %v", target.Name, err)
			http.Error(w, "secret unavailable", http.StatusBadGateway)
			return
		}

		base, err := url.Parse(target.BaseURL)
		if err != nil {
			log.Printf("proxy: parsing base_url for target %s: %v", target.Name, err)
			http.Error(w, "bad upstream request", http.StatusInternalServerError)
			return
		}

		// ServeMux hands the wildcard to us percent-decoded, so "%3F"/"%23"
		// would otherwise re-parse as query/fragment metacharacters and
		// "%2e%2e" as a "..' segment escaping base_url's path prefix.
		// path.Clean resolves the traversal; leaving RawPath empty makes the
		// join re-escape everything else.
		rest := path.Clean("/" + r.PathValue("rest"))
		if strings.HasSuffix(r.PathValue("rest"), "/") && !strings.HasSuffix(rest, "/") {
			rest += "/"
		}

		if httpClient.Timeout > 0 {
			ctx, cancel := context.WithTimeout(r.Context(), httpClient.Timeout)
			defer cancel()
			r = r.WithContext(ctx)
		}

		rp := &httputil.ReverseProxy{
			Transport: httpClient.Transport,
			Rewrite: func(pr *httputil.ProxyRequest) {
				pr.Out.URL.Path = rest
				pr.Out.URL.RawPath = ""
				pr.SetURL(base)
				pr.Out.Header.Del("Authorization")
				pr.Out.Header.Set(target.InjectHeader, target.InjectPrefix+secret)
			},
			ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
				log.Printf("proxy: upstream request for target %s failed: %v", target.Name, err)
				http.Error(w, "upstream unreachable", http.StatusBadGateway)
			},
		}
		rp.ServeHTTP(w, r)
	}
}
