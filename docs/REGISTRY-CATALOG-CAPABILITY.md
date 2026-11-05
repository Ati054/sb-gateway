# Registry image catalog capability

Registry updates inspect the candidate's immutable metadata before trusting its
subscription-catalog capability. The check verifies the SHA256 of the requested
manifest or index, the selected `linux/arm64` image manifest and its config blob.
Descriptor sizes are checked as well. This follows the content-addressed chain
defined by the [OCI descriptor specification](https://github.com/opencontainers/image-spec/blob/main/descriptor.md)
and [OCI image manifest](https://github.com/opencontainers/image-spec/blob/main/manifest.md).

The verified config must match the requested version, ARM64/Linux platform and
existing release compatibility labels. The additional label
`io.sb-gateway.data.subscription-catalog.schema` declares catalog support:
absent or `0` means legacy state, `1` means catalog schema 1, and any unknown value
rejects verification. A version number is never evidence of this capability.

OCI and Docker schema-2 manifests and indexes are supported. Exactly one baseline
Linux ARM64 candidate must match, with an absent or `v8` variant. Unknown other
platforms, including attestation entries, are skipped. Ambiguous ARM64 entries,
nested matching indexes and unsupported variants require a verified TAR instead.
These are deliberately conservative client restrictions, not claims that such
indexes violate the [OCI index specification](https://github.com/opencontainers/image-spec/blob/main/image-index.md).

Metadata requests use HTTPS, accept at most 4 MiB per manifest
or config, and share one 30-second inspection deadline. Layers are not downloaded;
the result proves digest-bound declared compatibility, not layer integrity or
successful runtime readiness. Endpoint failures do not fall back to guessing.

Anonymous Bearer authentication can follow a registry challenge for the exact
repository's `pull` scope. Tokens exist only during inspection and are sent only
to the original registry. A token realm must share that HTTPS origin, except for
the explicit standard Docker Hub mapping from `registry-1.docker.io` to
`https://auth.docker.io/token`. Authentication follows the
[Distribution token flow](https://distribution.github.io/distribution/spec/auth/token/)
with these stricter origin and redirect restrictions.

Manifest and token redirects are rejected. Config blobs can follow at most two
HTTPS redirects to public addresses, with no Authorization, Cookie, Referer or
client certificate forwarded. Redirected connections resolve once and dial only
checked public IP literals while TLS verifies the CDN hostname. Private, loopback,
link-local and mixed public/private DNS answers are rejected. Final size and
digest checks still apply. This accommodates the redirect behavior allowed by the
[OCI Distribution API](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#api)
without trusting the redirect destination for capability labels.

Private credentials and arbitrary external authentication services are
unsupported by this metadata verifier. Use a verified local TAR
when inspection cannot be completed. RouterOS management API credentials are not
registry credentials and are never reused for this purpose.

Synthetic TLS fixtures cover direct/indexed metadata, digest and size mismatch,
platform/version/label incompatibility, oversized responses, scoped anonymous
authentication, rejected foreign realms/redirects and request cancellation.
Live registry interoperability is a separate verification step.
