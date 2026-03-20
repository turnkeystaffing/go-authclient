// dev-server is a standalone mock OAuth2 server for local development.
//
// It provides JWT token issuance, RFC 7662 introspection, and JWKS endpoints
// backed by in-memory storage. Configure via environment variables:
//
//	DEV_AUTH_PORT          - listen port (default: 9091)
//	DEV_AUTH_CLIENT_ID     - Basic Auth client ID (default: dev)
//	DEV_AUTH_CLIENT_SECRET - Basic Auth client secret (default: dev)
//	DEV_AUTH_USERS         - user definitions in "name|email|scopes;..." format
//	                         (default: admin|admin@dev.local|admin openid profile email)
//	DEV_AUTH_ISSUER        - JWT issuer claim (default: http://localhost:<port>)
//	DEV_AUTH_SERVICES      - per-audience user definitions in
//	                         "audience:name|email|scopes,name2|email2|scopes2;audience2:..." format
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
	issuer := envOr("DEV_AUTH_ISSUER", "http://localhost:"+port)
	servicesStr := os.Getenv("DEV_AUTH_SERVICES")

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg := devserver.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
		Logger:       log,
	}

	// If services are configured, use per-audience user sets.
	if servicesStr != "" {
		cfg.Services = devserver.ParseServicesEnv(servicesStr)
		if len(cfg.Services) == 0 {
			log.Error("no valid services parsed from DEV_AUTH_SERVICES")
			os.Exit(1)
		}
	} else {
		cfg.Users = devserver.ParseUsersEnv(usersStr)
		if len(cfg.Users) == 0 {
			log.Error("no valid users parsed from DEV_AUTH_USERS")
			os.Exit(1)
		}
	}

	srv := devserver.New(cfg)

	addr := ":" + port
	log.Info("dev-auth server starting",
		"addr", addr,
		"client_id", clientID,
		"issuer", issuer,
		"users", len(cfg.Users),
		"services", len(cfg.Services),
	)
	if len(cfg.Services) > 0 {
		for _, svc := range cfg.Services {
			log.Info("registered service", "audience", svc.Audience, "users", len(svc.Users))
		}
	} else {
		for _, u := range cfg.Users {
			log.Info("registered dev user", "name", u.Name, "email", u.Email, "scope", u.Scope)
		}
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
