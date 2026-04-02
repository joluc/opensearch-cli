/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// providerMetadata is a subset of the OIDC discovery document.
type providerMetadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	DeviceEndpoint        string `json:"device_authorization_endpoint"`
}

// discoverEndpoint fetches the OIDC discovery document and returns an oauth2.Endpoint.
func discoverEndpoint(ctx context.Context, issuerURL string) (oauth2.Endpoint, error) {
	wellKnown := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("build discovery request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("fetch discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return oauth2.Endpoint{}, fmt.Errorf("discovery document returned %d for %s", resp.StatusCode, wellKnown)
	}

	var meta providerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return oauth2.Endpoint{}, fmt.Errorf("decode discovery document: %w", err)
	}

	if meta.TokenEndpoint == "" {
		return oauth2.Endpoint{}, fmt.Errorf("discovery document missing token_endpoint")
	}

	return oauth2.Endpoint{
		AuthURL:       meta.AuthorizationEndpoint,
		TokenURL:      meta.TokenEndpoint,
		DeviceAuthURL: meta.DeviceEndpoint,
	}, nil
}
