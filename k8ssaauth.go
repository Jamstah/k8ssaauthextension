// SPDX-License-Identifier: Apache-2.0

package k8ssaauthextension

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/jamstah/otel-k8ssaauth/internal/k8sconfig"
)

var (
	_ extension.Extension  = (*k8sSAAuth)(nil)
	_ extensionauth.Server = (*k8sSAAuth)(nil)

	errMissingAuthHeader     = errors.New("missing or empty authorization header")
	errInvalidAuthHeader     = errors.New("invalid authorization header format")
	errTokenReviewFailed     = errors.New("token review failed")
	errTokenNotAuthenticated = errors.New("token is not authenticated")
	errPermissionDenied      = errors.New("permission denied")
)

// k8sSAAuth implements server-side authentication using Kubernetes service account tokens
type k8sSAAuth struct {
	cfg    *Config
	client kubernetes.Interface
	logger *zap.Logger
}

// newK8sSAAuth creates a new Kubernetes service account authenticator
func newK8sSAAuth(cfg *Config, logger *zap.Logger) (extension.Extension, error) {
	client, err := k8sconfig.MakeClient(cfg.APIConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return &k8sSAAuth{
		cfg:    cfg,
		client: client,
		logger: logger,
	}, nil
}

// Start does nothing for this extension
func (k *k8sSAAuth) Start(_ context.Context, _ component.Host) error {
	k.logger.Info("Starting Kubernetes service account authenticator",
		zap.String("resource", k.cfg.ResourceAttributes.Resource),
		zap.String("verb", k.cfg.ResourceAttributes.Verb),
		zap.String("namespace", k.cfg.ResourceAttributes.Namespace),
	)
	return nil
}

// Shutdown does nothing for this extension
func (k *k8sSAAuth) Shutdown(_ context.Context) error {
	k.logger.Info("Shutting down Kubernetes service account authenticator")
	return nil
}

// Authenticate validates the bearer token and checks RBAC permissions
func (k *k8sSAAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	// Extract token from headers
	token, err := k.extractToken(headers)
	if err != nil {
		return ctx, err
	}

	// Validate token using TokenReview API
	userInfo, err := k.validateToken(ctx, token)
	if err != nil {
		return ctx, err
	}

	// Check RBAC permissions using SubjectAccessReview API
	if err := k.checkPermission(ctx, userInfo); err != nil {
		return ctx, err
	}

	k.logger.Debug("Authentication successful",
		zap.String("username", userInfo.Username),
		zap.String("uid", userInfo.UID),
	)

	return ctx, nil
}

// extractToken extracts the bearer token from the authorization header
func (k *k8sSAAuth) extractToken(headers map[string][]string) (string, error) {
	// Try lowercase header first (gRPC metadata is lowercase)
	auth, ok := headers[strings.ToLower(k.cfg.Header)]
	if !ok {
		// Try original case (HTTP headers)
		auth, ok = headers[k.cfg.Header]
	}

	if !ok || len(auth) == 0 {
		return "", errMissingAuthHeader
	}

	// Extract token from "Bearer <token>" or "<scheme> <token>"
	authValue := auth[0]
	expectedPrefix := k.cfg.Scheme + " "

	if !strings.HasPrefix(authValue, expectedPrefix) {
		return "", fmt.Errorf("%w: expected scheme '%s'", errInvalidAuthHeader, k.cfg.Scheme)
	}

	token := strings.TrimPrefix(authValue, expectedPrefix)
	if token == "" {
		return "", fmt.Errorf("%w: token is empty", errInvalidAuthHeader)
	}

	return token, nil
}

// validateToken validates the token using Kubernetes TokenReview API
func (k *k8sSAAuth) validateToken(ctx context.Context, token string) (*authenticationv1.UserInfo, error) {
	// Create TokenReview request
	tokenReview := &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}

	// Call TokenReview API
	result, err := k.client.AuthenticationV1().TokenReviews().Create(ctx, tokenReview, metav1.CreateOptions{})
	if err != nil {
		k.logger.Error("TokenReview API call failed", zap.Error(err))
		return nil, fmt.Errorf("%w: %v", errTokenReviewFailed, err)
	}

	// Check if token is authenticated
	if !result.Status.Authenticated {
		k.logger.Warn("Token authentication failed",
			zap.String("error", result.Status.Error),
		)
		return nil, fmt.Errorf("%w: %s", errTokenNotAuthenticated, result.Status.Error)
	}

	return &result.Status.User, nil
}

// checkPermission checks if the user has permission using SubjectAccessReview API
func (k *k8sSAAuth) checkPermission(ctx context.Context, userInfo *authenticationv1.UserInfo) error {
	// Build resource attributes for the access review
	resourceAttrs := &authorizationv1.ResourceAttributes{
		Verb:     k.cfg.ResourceAttributes.Verb,
		Group:    k.cfg.ResourceAttributes.Group,
		Version:  k.cfg.ResourceAttributes.Version,
		Resource: k.cfg.ResourceAttributes.Resource,
	}

	// Add namespace if specified
	if k.cfg.ResourceAttributes.Namespace != "" {
		resourceAttrs.Namespace = k.cfg.ResourceAttributes.Namespace
	}

	// Add resource name if specified
	if k.cfg.ResourceAttributes.Name != "" {
		resourceAttrs.Name = k.cfg.ResourceAttributes.Name
	}

	// Create SubjectAccessReview request
	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:               userInfo.Username,
			UID:                userInfo.UID,
			Groups:             userInfo.Groups,
			ResourceAttributes: resourceAttrs,
		},
	}

	// Call SubjectAccessReview API
	result, err := k.client.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
	if err != nil {
		k.logger.Error("SubjectAccessReview API call failed", zap.Error(err))
		return fmt.Errorf("authorization check failed: %w", err)
	}

	// Check if access is allowed
	if !result.Status.Allowed {
		k.logger.Warn("Permission denied",
			zap.String("username", userInfo.Username),
			zap.String("reason", result.Status.Reason),
			zap.String("verb", k.cfg.ResourceAttributes.Verb),
			zap.String("resource", k.cfg.ResourceAttributes.Resource),
		)
		return fmt.Errorf("%w: %s", errPermissionDenied, result.Status.Reason)
	}

	return nil
}

// Made with Bob
