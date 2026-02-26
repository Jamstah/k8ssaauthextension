// SPDX-License-Identifier: Apache-2.0

package k8ssaauthextension

import (
	"errors"

	"go.opentelemetry.io/collector/component"

	"github.com/jamstah/otel-k8ssaauth/internal/k8sconfig"
)

// ResourceAttributes defines the Kubernetes resource and action to check for authorization
type ResourceAttributes struct {
	// Group is the API group of the resource (e.g., "telemetry.opentelemetry.io")
	Group string `mapstructure:"group"`

	// Version is the API version of the resource (e.g., "v1")
	Version string `mapstructure:"version"`

	// Resource is the resource type (e.g., "telemetry")
	Resource string `mapstructure:"resource"`

	// Verb is the action to check (e.g., "export", "create", "get")
	Verb string `mapstructure:"verb"`

	// Namespace is the namespace to check permissions in. Empty string means cluster-scoped.
	Namespace string `mapstructure:"namespace,omitempty"`

	// Name is the specific resource name to check. Empty string means any resource of this type.
	Name string `mapstructure:"name,omitempty"`
}

// Config specifies the configuration for the Kubernetes service account token authenticator
type Config struct {
	k8sconfig.APIConfig `mapstructure:",squash"`

	// ResourceAttributes defines what resource and action to check for authorization
	ResourceAttributes ResourceAttributes `mapstructure:"resource_attributes"`

	// Header specifies the auth-header for the token. Defaults to "Authorization"
	Header string `mapstructure:"header,omitempty"`

	// Scheme specifies the auth-scheme for the token. Defaults to "Bearer"
	Scheme string `mapstructure:"scheme,omitempty"`
}

var (
	_ component.Config = (*Config)(nil)

	errNoResourceSpecified = errors.New("resource_attributes.resource must be specified")
	errNoVerbSpecified     = errors.New("resource_attributes.verb must be specified")
)

// Validate checks if the extension configuration is valid
func (cfg *Config) Validate() error {
	if err := cfg.APIConfig.Validate(); err != nil {
		return err
	}

	if cfg.ResourceAttributes.Resource == "" {
		return errNoResourceSpecified
	}

	if cfg.ResourceAttributes.Verb == "" {
		return errNoVerbSpecified
	}

	return nil
}

// Made with Bob
