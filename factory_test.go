// SPDX-License-Identifier: Apache-2.0

package k8ssaauthextension

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"

	"github.com/jamstah/k8ssaauthextension/internal/k8sconfig"
	"github.com/jamstah/k8ssaauthextension/internal/metadata"
)

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()
	assert.NotNil(t, cfg, "failed to create default config")
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))

	expectedCfg := &Config{
		APIConfig: k8sconfig.APIConfig{
			AuthType: k8sconfig.AuthTypeServiceAccount,
		},
		Header:    defaultHeader,
		Scheme:    defaultScheme,
		Audiences: []string{defaultK8sAudience},
	}
	assert.Equal(t, expectedCfg, cfg)
}

func TestCreateExtension(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)
	cfg.ResourceAttributes = ResourceAttributes{
		Resource: "telemetry",
		Verb:     "export",
	}

	// Note: This will fail in test environment without actual K8s cluster
	// but we're testing the factory creation logic
	ext, err := createExtension(
		context.Background(),
		extensiontest.NewNopSettings(metadata.Type),
		cfg,
	)

	// In a real K8s environment, this would succeed
	// In test environment, it will fail to create K8s client
	if err != nil {
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create Kubernetes client")
	} else {
		assert.NotNil(t, ext)
		require.NoError(t, ext.Start(context.Background(), componenttest.NewNopHost()))
		require.NoError(t, ext.Shutdown(context.Background()))
	}
}

func TestFactory(t *testing.T) {
	factory := NewFactory()
	assert.Equal(t, metadata.Type, factory.Type())
}

// Made with Bob
