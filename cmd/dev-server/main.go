// dev-server is a standalone mock OAuth2 server for local development.
//
// It provides token issuance and RFC 7662 introspection endpoints
// backed by in-memory storage. Configure via environment variables:
//
//	DEV_AUTH_PORT          - listen port (default: 9091)
//	DEV_AUTH_CLIENT_ID     - Basic Auth client ID (default: dev)
//	DEV_AUTH_CLIENT_SECRET - Basic Auth client secret (default: dev)
//	DEV_AUTH_USERS         - user definitions in "name|email|scopes;..." format
//	                         (default: admin|admin@dev.local|admin openid profile email)
package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/turnkeystaffing/go-authclient/devserver"
)

func main() {
	port := envOr("DEV_AUTH_PORT", "9091")
	clientID := envOr("DEV_AUTH_CLIENT_ID", "dev")
	clientSecret := envOr("DEV_AUTH_CLIENT_SECRET", "dev")
	usersStr := envOr("DEV_AUTH_USERS", "admin|admin@dev.local|admin openid profile email")

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	users := devserver.ParseUsersEnv(usersStr)
	if len(users) == 0 {
		log.Error("no valid users parsed from DEV_AUTH_USERS")
		os.Exit(1)
	}

	srv := devserver.New(devserver.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Users:        users,
		Logger:       log,
	})

	addr := ":" + port
	log.Info("dev-auth server starting",
		"addr", addr,
		"client_id", clientID,
		"users", len(users),
	)
	for _, u := range users {
		log.Info("registered dev user", "name", u.Name, "email", u.Email, "scope", u.Scope)
	}

	if err := http.ListenAndServe(addr, srv.Handler()); err != nil {
		log.Error("server error", "error", err)
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
