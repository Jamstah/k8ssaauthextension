// SPDX-License-Identifier: Apache-2.0

package k8ssaauthextension

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/jamstah/otel-k8ssaauth/internal/k8sconfig"
)

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string][]string
		headerName  string
		scheme      string
		wantToken   string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid bearer token lowercase header",
			headers: map[string][]string{
				"authorization": {"Bearer test-token-123"},
			},
			headerName: "Authorization",
			scheme:     "Bearer",
			wantToken:  "test-token-123",
			wantErr:    false,
		},
		{
			name: "valid bearer token uppercase header",
			headers: map[string][]string{
				"Authorization": {"Bearer test-token-456"},
			},
			headerName: "Authorization",
			scheme:     "Bearer",
			wantToken:  "test-token-456",
			wantErr:    false,
		},
		{
			name: "custom scheme",
			headers: map[string][]string{
				"authorization": {"Token custom-token"},
			},
			headerName: "Authorization",
			scheme:     "Token",
			wantToken:  "custom-token",
			wantErr:    false,
		},
		{
			name:        "missing header",
			headers:     map[string][]string{},
			headerName:  "Authorization",
			scheme:      "Bearer",
			wantErr:     true,
			errContains: "missing or empty authorization header",
		},
		{
			name: "wrong scheme",
			headers: map[string][]string{
				"authorization": {"Basic dXNlcjpwYXNz"},
			},
			headerName:  "Authorization",
			scheme:      "Bearer",
			wantErr:     true,
			errContains: "expected scheme 'Bearer'",
		},
		{
			name: "empty token",
			headers: map[string][]string{
				"authorization": {"Bearer "},
			},
			headerName:  "Authorization",
			scheme:      "Bearer",
			wantErr:     true,
			errContains: "token is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth := &k8sSAAuth{
				cfg: &Config{
					Header: tt.headerName,
					Scheme: tt.scheme,
				},
				logger: zaptest.NewLogger(t),
			}

			token, err := auth.extractToken(tt.headers)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantToken, token)
			}
		})
	}
}

func TestValidateToken(t *testing.T) {
	tests := []struct {
		name            string
		token           string
		authenticated   bool
		userInfo        authenticationv1.UserInfo
		tokenAudiences  []string
		configAudiences []string
		reviewError     string
		wantErr         bool
		errContains     string
		expectedUser    *authenticationv1.UserInfo
	}{
		{
			name:          "valid token with default audience",
			token:         "valid-token",
			authenticated: true,
			userInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
			tokenAudiences:  []string{"https://kubernetes.default.svc"},
			configAudiences: []string{"https://kubernetes.default.svc"},
			wantErr:         false,
			expectedUser: &authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
		},
		{
			name:          "valid token with custom audience",
			token:         "valid-token",
			authenticated: true,
			userInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
			tokenAudiences:  []string{"custom-audience"},
			configAudiences: []string{"custom-audience"},
			wantErr:         false,
			expectedUser: &authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
		},
		{
			name:          "valid token with multiple audiences - match first",
			token:         "valid-token",
			authenticated: true,
			userInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
			tokenAudiences:  []string{"audience1", "audience2"},
			configAudiences: []string{"audience1", "audience3"},
			wantErr:         false,
			expectedUser: &authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
		},
		{
			name:          "valid token with multiple audiences - match second",
			token:         "valid-token",
			authenticated: true,
			userInfo: authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
			tokenAudiences:  []string{"audience1", "audience2"},
			configAudiences: []string{"audience3", "audience2"},
			wantErr:         false,
			expectedUser: &authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts", "system:authenticated"},
			},
		},
		{
			name:            "token with wrong audience",
			token:           "valid-token",
			authenticated:   false,
			configAudiences: []string{"https://kubernetes.default.svc"},
			reviewError:     "[invalid bearer token, token audiences [\"telemetry\"] is invalid for the target audiences [\"https://kubernetes.default.svc\"], token lookup failed]",
			wantErr:         true,
			errContains:     "invalid for the target audiences",
		},
		{
			name:          "invalid token",
			token:         "invalid-token",
			authenticated: false,
			reviewError:   "token is invalid",
			wantErr:       true,
			errContains:   "token is not authenticated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientset()

			// Mock TokenReview response
			fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				obj := action.(k8stesting.CreateAction).GetObject()
				tokenreview, _ := obj.(*authenticationv1.TokenReview)
				assert.Equal(t, tt.token, tokenreview.Spec.Token)
				assert.Equal(t, tt.configAudiences, tokenreview.Spec.Audiences)
				review := &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: tt.authenticated,
						User:          tt.userInfo,
						Error:         tt.reviewError,
						Audiences:     tt.tokenAudiences,
					},
				}
				return true, review, nil
			})

			auth := &k8sSAAuth{
				cfg: &Config{
					ResourceAttributes: ResourceAttributes{
						Resource: "telemetry",
						Verb:     "export",
					},
					Audiences: tt.configAudiences,
				},
				client: fakeClient,
				logger: zaptest.NewLogger(t),
			}

			userInfo, err := auth.validateToken(context.Background(), tt.token)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUser, userInfo)
			}
		})
	}
}

func TestCheckPermission(t *testing.T) {
	tests := []struct {
		name        string
		userInfo    *authenticationv1.UserInfo
		allowed     bool
		reason      string
		wantErr     bool
		errContains string
	}{
		{
			name: "permission granted",
			userInfo: &authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:test-sa",
				UID:      "test-uid",
				Groups:   []string{"system:serviceaccounts"},
			},
			allowed: true,
			wantErr: false,
		},
		{
			name: "permission denied",
			userInfo: &authenticationv1.UserInfo{
				Username: "system:serviceaccount:default:unauthorized-sa",
				UID:      "test-uid-2",
				Groups:   []string{"system:serviceaccounts"},
			},
			allowed:     false,
			reason:      "no RBAC policy matched",
			wantErr:     true,
			errContains: "permission denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientset()

			// Mock SubjectAccessReview response
			fakeClient.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				review := &authorizationv1.SubjectAccessReview{
					Status: authorizationv1.SubjectAccessReviewStatus{
						Allowed: tt.allowed,
						Reason:  tt.reason,
					},
				}
				return true, review, nil
			})

			auth := &k8sSAAuth{
				cfg: &Config{
					ResourceAttributes: ResourceAttributes{
						Group:     "telemetry.opentelemetry.io",
						Version:   "v1",
						Resource:  "telemetry",
						Verb:      "export",
						Namespace: "observability",
					},
				},
				client: fakeClient,
				logger: zaptest.NewLogger(t),
			}

			err := auth.checkPermission(context.Background(), tt.userInfo)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name          string
		headers       map[string][]string
		authenticated bool
		allowed       bool
		wantErr       bool
		errContains   string
	}{
		{
			name: "successful authentication and authorization",
			headers: map[string][]string{
				"authorization": {"Bearer valid-token"},
			},
			authenticated: true,
			allowed:       true,
			wantErr:       false,
		},
		{
			name: "authentication fails",
			headers: map[string][]string{
				"authorization": {"Bearer invalid-token"},
			},
			authenticated: false,
			allowed:       false,
			wantErr:       true,
			errContains:   "token is not authenticated",
		},
		{
			name: "authorization fails",
			headers: map[string][]string{
				"authorization": {"Bearer valid-token"},
			},
			authenticated: true,
			allowed:       false,
			wantErr:       true,
			errContains:   "permission denied",
		},
		{
			name:        "missing header",
			headers:     map[string][]string{},
			wantErr:     true,
			errContains: "missing or empty authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fakeClient := fake.NewClientset()

			// Mock TokenReview response
			fakeClient.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				review := &authenticationv1.TokenReview{
					Status: authenticationv1.TokenReviewStatus{
						Authenticated: tt.authenticated,
						User: authenticationv1.UserInfo{
							Username: "system:serviceaccount:default:test-sa",
							UID:      "test-uid",
							Groups:   []string{"system:serviceaccounts"},
						},
					},
				}
				if !tt.authenticated {
					review.Status.Error = "invalid token"
				}
				return true, review, nil
			})

			// Mock SubjectAccessReview response
			fakeClient.PrependReactor("create", "subjectaccessreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
				review := &authorizationv1.SubjectAccessReview{
					Status: authorizationv1.SubjectAccessReviewStatus{
						Allowed: tt.allowed,
						Reason:  "test reason",
					},
				}
				return true, review, nil
			})

			auth := &k8sSAAuth{
				cfg: &Config{
					APIConfig: k8sconfig.APIConfig{
						AuthType: k8sconfig.AuthTypeServiceAccount,
					},
					ResourceAttributes: ResourceAttributes{
						Group:    "telemetry.opentelemetry.io",
						Version:  "v1",
						Resource: "telemetry",
						Verb:     "export",
					},
					Header: "Authorization",
					Scheme: "Bearer",
				},
				client: fakeClient,
				logger: zaptest.NewLogger(t),
			}

			ctx, err := auth.Authenticate(context.Background(), tt.headers)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, ctx)
			}
		})
	}
}

func TestStartShutdown(t *testing.T) {
	fakeClient := fake.NewClientset()

	auth := &k8sSAAuth{
		cfg: &Config{
			ResourceAttributes: ResourceAttributes{
				Resource: "telemetry",
				Verb:     "export",
			},
		},
		client: fakeClient,
		logger: zaptest.NewLogger(t),
	}

	err := auth.Start(context.Background(), nil)
	require.NoError(t, err)

	err = auth.Shutdown(context.Background())
	require.NoError(t, err)
}

// Made with Bob
