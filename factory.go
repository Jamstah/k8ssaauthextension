// SPDX-License-Identifier: Apache-2.0

package k8ssaauthextension

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"github.com/jamstah/otel-k8ssaauth/internal/k8sconfig"
	"github.com/jamstah/otel-k8ssaauth/internal/metadata"
)

const (
	defaultHeader      = "Authorization"
	defaultScheme      = "Bearer"
	defaultK8sAudience = "https://kubernetes.default.svc"
)

// NewFactory creates a factory for the Kubernetes service account authenticator extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		createDefaultConfig,
		createExtension,
		metadata.ExtensionStability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		APIConfig: k8sconfig.APIConfig{
			AuthType: k8sconfig.AuthTypeServiceAccount,
		},
		Header:    defaultHeader,
		Scheme:    defaultScheme,
		Audiences: []string{defaultK8sAudience},
	}
}

func createExtension(_ context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	return newK8sSAAuth(cfg.(*Config), set.Logger)
}

// Made with Bob
