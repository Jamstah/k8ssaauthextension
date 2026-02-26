# Kubernetes Service Account Auth Extension

| Status        |           |
| ------------- |-----------|
| Stability     | [development] |
| Distributions |  |
| Issues        | [![Open issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aopen%20label%3Aextension%2Fk8ssaauth%20&label=open&color=orange&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aopen+is%3Aissue+label%3Aextension%2Fk8ssaauth) [![Closed issues](https://img.shields.io/github/issues-search/open-telemetry/opentelemetry-collector-contrib?query=is%3Aissue%20is%3Aclosed%20label%3Aextension%2Fk8ssaauth%20&label=closed&color=blue&logo=opentelemetry)](https://github.com/open-telemetry/opentelemetry-collector-contrib/issues?q=is%3Aclosed+is%3Aissue+label%3Aextension%2Fk8ssaauth) |

[development]: https://github.com/open-telemetry/opentelemetry-collector/blob/main/docs/component-stability.md#development

## Overview

This extension implements server-side authentication for the OpenTelemetry Collector using Kubernetes service account tokens with RBAC (Role-Based Access Control) authorization. It validates incoming bearer tokens against the Kubernetes API and checks if the authenticated service account has permission to perform a specified action on a resource.

## How It Works

The extension performs two-step authentication and authorization:

1. **Token Validation**: Uses the Kubernetes [TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/) to validate that the bearer token is a legitimate Kubernetes service account token.

2. **RBAC Authorization**: Uses the Kubernetes [SubjectAccessReview API](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/) to check if the authenticated service account has permission to perform the configured action on the specified resource.

## Configuration

### Parameters

- `auth_type` (default: `serviceAccount`): How to authenticate to the Kubernetes API server. Options:
  - `serviceAccount`: Use the service account token mounted in the pod
  - `kubeConfig`: Use credentials from `~/.kube/config`
  - `none`: No authentication (insecure, for testing only)

- `resource_attributes` (required): Defines the Kubernetes resource and action to check for authorization
  - `group` (optional): API group of the resource (e.g., `"opentelemetry.io"`)
  - `version` (optional): API version (e.g., `"v1"`)
  - `resource` (required): Resource type to check (e.g., `"collector"`)
  - `verb` (required): Action to authorize (e.g., `"export"`)
  - `namespace` (optional): Namespace for namespaced resources. Empty means cluster-scoped.
  - `name` (optional): Specific resource name. Empty means any resource of this type.

- `header` (default: `"Authorization"`): HTTP header name containing the bearer token

- `scheme` (default: `"Bearer"`): Authentication scheme prefix

### Example Configuration

```yaml
extensions:
  k8ssaauth:
    # Kubernetes API configuration
    auth_type: serviceAccount
    
    # RBAC check configuration
    resource_attributes:
      group: "telemetry.opentelemetry.io"
      version: "v1"
      resource: "telemetry"
      verb: "export"
      namespace: "observability"  # Optional: check permissions in specific namespace
      name: "mytelemetry"  # Optional: check permissions for a specific resource

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
        auth:
          authenticator: k8ssaauth
      http:
        endpoint: 0.0.0.0:4318
        auth:
          authenticator: k8ssaauth

service:
  extensions: [k8ssaauth]
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [...]
    metrics:
      receivers: [otlp]
      exporters: [...]
```

## Kubernetes Setup

### 1. Create Custom Resource Definition (Optional)

If using a custom resource for semantic authorization:

```yaml
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: collectors.opentelemetry.io
spec:
  group: opentelemetry.io
  versions:
    - name: v1
      served: true
      storage: true
      schema:
        openAPIV3Schema:
          type: object
          properties:
            spec:
              type: object
  scope: Namespaced
  names:
    plural: collectors
    singular: collector
    kind: Collector
```

### 2. Create RBAC Resources

Create a Role (or ClusterRole for cluster-wide permissions):

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: telemetry-exporter
  namespace: observability
rules:
- apiGroups: ["opentelemetry.io"]
  resources: ["collectors"]
  verbs: ["export"]  # Custom verb for semantic clarity
```

### 3. Create RoleBinding

Bind the role to service accounts that should be allowed to send telemetry:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-telemetry-exporter
  namespace: observability
subjects:
- kind: ServiceAccount
  name: my-app
  namespace: default
roleRef:
  kind: Role
  name: telemetry-exporter
  apiGroup: rbac.authorization.k8s.io
```

### 4. Collector Deployment

The collector needs permissions to perform TokenReview and SubjectAccessReview:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: otel-collector
  namespace: observability
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: otel-collector-auth
rules:
- apiGroups: ["authentication.k8s.io"]
  resources: ["tokenreviews"]
  verbs: ["create"]
- apiGroups: ["authorization.k8s.io"]
  resources: ["subjectaccessreviews"]
  verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: otel-collector-auth
subjects:
- kind: ServiceAccount
  name: otel-collector
  namespace: observability
roleRef:
  kind: ClusterRole
  name: otel-collector-auth
  apiGroup: rbac.authorization.k8s.io
```

## Client Configuration

Applications sending telemetry to the collector must include their service account token in the Authorization header:

### Go Example

```go
import (
    "context"
    "os"
    
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/metadata"
)

// Read service account token
token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
if err != nil {
    // handle error
}

// Create interceptor to add token to requests
authInterceptor := func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
    ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+string(token))
    return invoker(ctx, method, req, reply, cc, opts...)
}

// Create exporter with auth
exporter, err := otlptracegrpc.New(
    context.Background(),
    otlptracegrpc.WithEndpoint("otel-collector.observability.svc.cluster.local:4317"),
    otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
    otlptracegrpc.WithDialOption(grpc.WithUnaryInterceptor(authInterceptor)),
)
```

### Python Example

```python
import os
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

# Read service account token
with open('/var/run/secrets/kubernetes.io/serviceaccount/token', 'r') as f:
    token = f.read().strip()

# Create exporter with auth headers
exporter = OTLPSpanExporter(
    endpoint="otel-collector.observability.svc.cluster.local:4317",
    headers={"authorization": f"Bearer {token}"},
)

# Setup tracer
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(exporter))
```

## Use Cases

* Multi-Tenant Observability - Ensure that applications can only send telemetry data if they have the appropriate RBAC permissions, preventing unauthorized data injection.
* Namespace Isolation - Configure different RBAC rules per namespace to isolate telemetry data between teams or environments.
* Audit Trail - Leverage Kubernetes audit logs to track which service accounts are sending telemetry data.
* Zero-Trust Security - Implement defense-in-depth by requiring both network policies and RBAC authorization for telemetry ingestion.

## Security Considerations

1. **Token Rotation**: Service account tokens are automatically rotated by Kubernetes. Ensure your applications reload tokens periodically.

2. **TLS**: Always use TLS for the collector endpoints when using bearer token authentication.

3. **Least Privilege**: Grant only the minimum required permissions to service accounts. Consider using a [projected service account token](https://kubernetes.io/docs/concepts/storage/projected-volumes/#serviceaccounttoken) with a defined audience.

4. **Audit Logging**: Enable Kubernetes audit logging to track authentication and authorization events.

## Troubleshooting

### Authentication Failures

Check collector logs for detailed error messages:

```bash
kubectl logs -n observability deployment/otel-collector | grep k8ssaauth
```

Common issues:
- **"missing or empty authorization header"**: Client not sending token
- **"token is not authenticated"**: Invalid or expired token
- **"permission denied"**: Service account lacks required RBAC permissions

### Verify RBAC Configuration

Test if a service account has the required permissions:

```bash
kubectl auth can-i export telemetries.telemetry.opentelemetry.io \
  --as=system:serviceaccount:default:my-app \
  -n observability
```

### Debug Mode

Enable debug logging in the collector to see detailed authentication flow:

```yaml
service:
  telemetry:
    logs:
      level: debug
```

## References

- [Kubernetes Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
- [Kubernetes Authorization](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)
- [TokenReview API](https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-review-v1/)
- [SubjectAccessReview API](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/subject-access-review-v1/)