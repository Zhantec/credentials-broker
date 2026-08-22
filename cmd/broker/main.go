package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Zhantec/credentials-broker/internal/config"
	"github.com/Zhantec/credentials-broker/internal/execute"
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

	handler := server.New(
		cfg,
		proxy.Serve(secretsClient, &http.Client{Timeout: 30 * time.Second}),
		execute.Serve(secretsClient, openDB),
	)

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

func openDB(driverName, dsn string) (*sql.DB, error) {
	if driverName != "postgres" {
		return nil, fmt.Errorf("unsupported driver %q", driverName)
	}
	return sql.Open("pgx", dsn)
}
