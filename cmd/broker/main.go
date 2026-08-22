package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Zhantec/credentials-broker/internal/config"
	"github.com/Zhantec/credentials-broker/internal/oauth"
	"github.com/Zhantec/credentials-broker/internal/proxy"
	"github.com/Zhantec/credentials-broker/internal/secrets"
	"github.com/Zhantec/credentials-broker/internal/server"
)

func main() {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "/etc/credentials-broker/config.yaml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("loading config: %v", err)
	}

	secretsClient := secrets.NewClient(
		os.Getenv("INFISICAL_BASE_URL"),
		os.Getenv("INFISICAL_CLIENT_ID"),
		os.Getenv("INFISICAL_CLIENT_SECRET"),
		cfg.Infisical.WorkspaceID,
		cfg.Infisical.Environment,
	)
	httpClient := &http.Client{Timeout: 30 * time.Second}
	oauthClient := oauth.NewClient(secretsClient, httpClient)

	handler := server.New(cfg, map[string]server.DispatchFunc{
		"proxy": proxy.Serve(secretsClient, httpClient),
		"oauth": proxy.Serve(oauthClient, httpClient),
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	addr := fmt.Sprintf(":%s", port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("credentials-broker listening on %s", addr)
	log.Fatal(srv.ListenAndServe())
}
