# HTTP callout response metadata

An HTTP model callout can export selected values for later response transformations. Nothing is exported by default. The router still returns JSON; it does not proxy inference responses.

Add this to a standalone virtual model's `routing.callout`:

```yaml
host: http://router:9002/route
transformation:
  model: callout.body.model
metadata:
  model_router: >-
    {'model': callout.body.model,
     'reason': callout.body.reason,
     'fallback': callout.body.fallback}
```

Add this to `llm.policies`:

```yaml
transformations:
  response:
    set:
      x-model-router-model: metadata.model_router.model
      x-model-router-reason: metadata.model_router.reason
      x-model-router-fallback: string(metadata.model_router.fallback)
```

For Kubernetes, the same `metadata` map belongs under `AgentgatewayModel.spec.virtualModel.callout`. Use an `AgentgatewayPolicy` targeting the Gateway to expose headers:

```yaml
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: routing-headers
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: agentgateway
  traffic:
    transformation:
      response:
        set:
        - name: x-model-router-model
          value: metadata.model_router.model
        - name: x-model-router-reason
          value: metadata.model_router.reason
        - name: x-model-router-fallback
          value: string(metadata.model_router.fallback)
```

Metadata expressions have the same `callout.body`, `callout.headers`, and request context as the callout transformation. They are reevaluated on cache hits. Errors and null results are omitted; diagnostics do not make an otherwise valid routing decision fail. Metadata is committed only when the callout selects a configured model. Failed callouts and unknown-model fallback do not export success metadata.

The metadata is request-scoped and available as `metadata.<configured-key>` in response transformations and CEL logging. Existing keys with the same name are overwritten by successful exports. Choose a namespace such as `model_router` to avoid unrelated metadata collisions. Explicit model requests that bypass the callout produce no callout metadata.

Only configured values are retained, and they are never inserted into the inference request body. Expose only suitable public diagnostics. Response headers are available before an SSE stream begins; they cannot report the eventual success or failure of the whole stream. The model identifies the routing selection, not proof of successful inference.
