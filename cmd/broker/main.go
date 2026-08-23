package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Zhantec/credentials-broker/internal/oauth"
	"github.com/Zhantec/credentials-broker/internal/proxy"
	"github.com/Zhantec/credentials-broker/internal/secrets"
	"github.com/Zhantec/credentials-broker/internal/server"
	"github.com/Zhantec/credentials-broker/internal/store"
)

func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "credentials-broker.db"
	}

	adminAPIKey := os.Getenv("ADMIN_API_KEY")
	if adminAPIKey == "" {
		log.Fatal("ADMIN_API_KEY must be set")
	}

	s, err := store.Open(dbPath)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	defer func() { _ = s.Close() }()

	secretsClient := secrets.NewClient(
		os.Getenv("INFISICAL_BASE_URL"),
		os.Getenv("INFISICAL_CLIENT_ID"),
		os.Getenv("INFISICAL_CLIENT_SECRET"),
	)
	httpClient := &http.Client{Timeout: 30 * time.Second}
	oauthClient := oauth.NewClient(secretsClient, httpClient)

	handlers := map[string]server.DispatchFunc{
		"proxy": proxy.Serve(secretsClient, httpClient),
		"oauth": proxy.Serve(oauthClient, httpClient),
	}

	handler, err := server.New(s, adminAPIKey, handlers)
	if err != nil {
		log.Fatalf("building server: %v", err)
	}

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
