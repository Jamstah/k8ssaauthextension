// SPDX-License-Identifier: Apache-2.0

package k8ssaauthextension

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap/confmaptest"

	"github.com/jamstah/k8ssaauthextension/internal/k8sconfig"
	"github.com/jamstah/k8ssaauthextension/internal/metadata"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id           component.ID
		expected     component.Config
		errorMessage string
	}{
		{
			id: component.NewIDWithName(metadata.Type, ""),
			expected: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeServiceAccount,
				},
				ResourceAttributes: ResourceAttributes{
					Group:    "telemetry.opentelemetry.io",
					Version:  "v1",
					Resource: "telemetry",
					Verb:     "export",
				},
				Header:    "Authorization",
				Scheme:    "Bearer",
				Audiences: []string{"https://kubernetes.default.svc"},
			},
		},
		{
			id: component.NewIDWithName(metadata.Type, "with_namespace"),
			expected: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeServiceAccount,
				},
				ResourceAttributes: ResourceAttributes{
					Group:     "telemetry.opentelemetry.io",
					Version:   "v1",
					Resource:  "telemetry",
					Verb:      "export",
					Namespace: "observability",
				},
				Header:    "Authorization",
				Scheme:    "Bearer",
				Audiences: []string{"https://kubernetes.default.svc"},
			},
		},
		{
			id: component.NewIDWithName(metadata.Type, "kubeconfig"),
			expected: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeKubeConfig,
				},
				ResourceAttributes: ResourceAttributes{
					Group:    "apps",
					Version:  "v1",
					Resource: "deployments",
					Verb:     "get",
				},
				Header:    "Authorization",
				Scheme:    "Bearer",
				Audiences: []string{"https://kubernetes.default.svc"},
			},
		},
		{
			id: component.NewIDWithName(metadata.Type, "custom_audience"),
			expected: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeServiceAccount,
				},
				ResourceAttributes: ResourceAttributes{
					Group:    "telemetry.opentelemetry.io",
					Version:  "v1",
					Resource: "telemetry",
					Verb:     "export",
				},
				Header:    "Authorization",
				Scheme:    "Bearer",
				Audiences: []string{"custom-audience"},
			},
		},
		{
			id: component.NewIDWithName(metadata.Type, "multiple_audiences"),
			expected: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeServiceAccount,
				},
				ResourceAttributes: ResourceAttributes{
					Group:    "telemetry.opentelemetry.io",
					Version:  "v1",
					Resource: "telemetry",
					Verb:     "export",
				},
				Header:    "Authorization",
				Scheme:    "Bearer",
				Audiences: []string{"audience1", "audience2", "https://kubernetes.default.svc"},
			},
		},
		{
			id:           component.NewIDWithName(metadata.Type, "missing_resource"),
			errorMessage: "resource_attributes.resource must be specified",
		},
		{
			id:           component.NewIDWithName(metadata.Type, "missing_verb"),
			errorMessage: "resource_attributes.verb must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
			require.NoError(t, err)

			factory := NewFactory()
			cfg := factory.CreateDefaultConfig()

			sub, err := cm.Sub(tt.id.String())
			require.NoError(t, err)
			require.NoError(t, sub.Unmarshal(cfg))

			if tt.errorMessage != "" {
				assert.EqualError(t, cfg.(*Config).Validate(), tt.errorMessage)
			} else {
				assert.NoError(t, cfg.(*Config).Validate())
				assert.Equal(t, tt.expected, cfg)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{
			name: "valid config",
			config: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeServiceAccount,
				},
				ResourceAttributes: ResourceAttributes{
					Resource: "telemetry",
					Verb:     "export",
				},
				Header: "Authorization",
				Scheme: "Bearer",
			},
			wantErr: "",
		},
		{
			name: "missing resource",
			config: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeServiceAccount,
				},
				ResourceAttributes: ResourceAttributes{
					Verb: "export",
				},
			},
			wantErr: "resource_attributes.resource must be specified",
		},
		{
			name: "missing verb",
			config: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: k8sconfig.AuthTypeServiceAccount,
				},
				ResourceAttributes: ResourceAttributes{
					Resource: "telemetry",
				},
			},
			wantErr: "resource_attributes.verb must be specified",
		},
		{
			name: "invalid auth type",
			config: &Config{
				APIConfig: k8sconfig.APIConfig{
					AuthType: "invalid",
				},
				ResourceAttributes: ResourceAttributes{
					Resource: "telemetry",
					Verb:     "export",
				},
			},
			wantErr: "invalid authType for kubernetes: invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tt.wantErr)
			}
		})
	}
}

// Made with Bob
