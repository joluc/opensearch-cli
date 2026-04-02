/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

// Package oidc provides OpenID Connect authentication via the authorization code flow.
// On first use a browser is opened (or a URL printed) for the user to authenticate.
// The local HTTP server captures the redirect callback, exchanges the code for a token,
// and caches it in memory. The refresh token is used transparently on subsequent calls.
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"opensearch-cli/entity"
)

const (
	// tokenLeeway triggers a refresh this long before actual expiry.
	tokenLeeway = 30 * time.Second

	// callbackAddr is where the local redirect server listens.
	callbackAddr = "127.0.0.1:0" // port 0 = OS picks a free port

	// callbackTimeout is how long we wait for the user to complete the browser flow.
	callbackTimeout = 5 * time.Minute
)

var (
	mu    sync.Mutex
	cache = map[string]cachedToken{}
)

type cachedToken struct {
	token  *oauth2.Token
	source oauth2.TokenSource
}

// GetToken returns a valid Bearer access token for the given OIDC profile.
// The first call opens a browser for the authorization code flow. Subsequent
// calls return the cached token, refreshing silently when it is about to expire.
func GetToken(cfg entity.OIDC) (string, error) {
	key := cfg.IssuerURL + "|" + cfg.ClientID

	mu.Lock()
	ct, ok := cache[key]
	mu.Unlock()

	if ok {
		tok, err := ct.source.Token()
		if err == nil && tok.Valid() {
			mu.Lock()
			cache[key] = cachedToken{token: tok, source: ct.source}
			mu.Unlock()
			return tok.AccessToken, nil
		}
	}

	tok, src, err := authCodeFlow(cfg)
	if err != nil {
		return "", err
	}

	mu.Lock()
	cache[key] = cachedToken{token: tok, source: src}
	mu.Unlock()

	return tok.AccessToken, nil
}

// authCodeFlow runs the OIDC authorization code flow with PKCE.
// It starts a local HTTP server, opens the browser, and waits for the redirect.
func authCodeFlow(cfg entity.OIDC) (*oauth2.Token, oauth2.TokenSource, error) {
	ctx := context.Background()

	endpoint, err := discoverEndpoint(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discover: %w", err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "offline_access"}
	}

	// Start local callback server on a random free port.
	listener, err := net.Listen("tcp", callbackAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc local server: %w", err)
	}
	redirectURL := fmt.Sprintf("http://127.0.0.1:%d/callback", listener.Addr().(*net.TCPAddr).Port)

	oc := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		Endpoint:     endpoint,
		Scopes:       scopes,
		RedirectURL:  redirectURL,
	}

	// PKCE: code verifier + challenge.
	verifier, challenge, err := pkce()
	if err != nil {
		return nil, nil, fmt.Errorf("oidc pkce: %w", err)
	}

	// Random state to prevent CSRF.
	state, err := randomState()
	if err != nil {
		return nil, nil, fmt.Errorf("oidc state: %w", err)
	}

	authURL := oc.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	fmt.Printf("\nOpening browser for authentication...\n%s\n\nWaiting for callback (timeout: %s)...\n", authURL, callbackTimeout)
	openBrowser(authURL)

	// Wait for the callback.
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	srv := &http.Server{ReadHeaderTimeout: 10 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/callback" {
			http.NotFound(w, r)
			return
		}
		if got := r.URL.Query().Get("state"); got != state {
			http.Error(w, "invalid state", http.StatusBadRequest)
			errCh <- fmt.Errorf("oidc: state mismatch (possible CSRF)")
			return
		}
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			desc := r.URL.Query().Get("error_description")
			http.Error(w, "authentication failed", http.StatusBadRequest)
			errCh <- fmt.Errorf("oidc: IdP error: %s - %s", errParam, desc)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "missing code", http.StatusBadRequest)
			errCh <- fmt.Errorf("oidc: no code in callback")
			return
		}
		fmt.Fprintln(w, "<html><body><h2>Authentication successful. You may close this tab.</h2></body></html>")
		codeCh <- code
	})

	go func() { _ = srv.Serve(listener) }()

	// Wait for code or timeout.
	var code string
	select {
	case code = <-codeCh:
	case err = <-errCh:
		_ = srv.Close()
		return nil, nil, err
	case <-time.After(callbackTimeout):
		_ = srv.Close()
		return nil, nil, fmt.Errorf("oidc: timed out waiting for browser callback")
	}
	_ = srv.Close()

	tok, err := oc.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc exchange: %w", err)
	}

	src := oauth2.ReuseTokenSourceWithExpiry(tok, oc.TokenSource(ctx, tok), tokenLeeway)
	return tok, src, nil
}

// pkce generates a PKCE code_verifier and its S256 code_challenge.
func pkce() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err = rand.Read(b); err != nil {
		return
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

// randomState generates a random OAuth2 state parameter.
func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// openBrowser tries to open the URL in the default browser.
// If it fails it does nothing — the URL is already printed to stdout.
func openBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd, args = "open", []string{url}
	case "linux":
		cmd, args = "xdg-open", []string{url}
	case "windows":
		cmd, args = "cmd", []string{"/c", "start", url}
	default:
		return
	}
	_ = exec.Command(cmd, args...).Start()
}

// TokenInfo contains decoded claims from the token for display purposes.
type TokenInfo struct {
	Subject string
	Email   string
	Expiry  time.Time
}

// ParseTokenInfo extracts basic claims from the access token without validation.
// Useful for displaying who is currently authenticated.
func ParseTokenInfo(accessToken string) (*TokenInfo, error) {
	parts := splitToken(accessToken)
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a JWT")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims struct {
		Sub   string  `json:"sub"`
		Email string  `json:"email"`
		Name  string  `json:"name"`
		Exp   float64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}
	info := &TokenInfo{
		Subject: claims.Name,
		Email:   claims.Email,
		Expiry:  time.Unix(int64(claims.Exp), 0),
	}
	if info.Subject == "" {
		info.Subject = claims.Sub
	}
	return info, nil
}

func splitToken(token string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts = append(parts, token[start:i])
			start = i + 1
		}
	}
	parts = append(parts, token[start:])
	return parts
}
