// SPDX-License-Identifier: Apache-2.0

// Package k8ssaauthextension implements an extension that validates Kubernetes
// service account tokens and checks RBAC permissions for incoming requests.
//
// This extension uses the Kubernetes TokenReview API to validate bearer tokens
// and the SubjectAccessReview API to verify that the authenticated service account
// has permission to perform a specified action on a resource.
package k8ssaauthextension

// Made with Bob
