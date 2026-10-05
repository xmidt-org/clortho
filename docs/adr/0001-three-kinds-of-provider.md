<!-- SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Three kinds of provider, not one

clortho makes three separate kinds of provider. A Key Set Provider reads whole key sets on a schedule, a Per-Key Provider fetches one key by the key ID a token names, and a Fixed Key Provider serves keys written into configuration. The redesign that produced the Key Set Provider removed per-key fetching on purpose, so that a token could never cause a request. Per-key fetching came back because themis, as deployed, serves single keys and no key set, and the services that depend on it could not wait for themis to change. It came back as its own permanent kind, and not as a mode of one provider, so that the Key Set Provider's promise stays true whatever a service configures, and so that anyone reading a service's wiring can tell whether tokens can trigger requests by seeing which kinds are listed. A service combines kinds by listing them in the jwx options, which asks them in order.

## Considered Options

- **One provider with a per-key mode.** Rejected because the promise that a token cannot cause a request would then depend on configuration, and could not be read off the type.
- **Wait for themis to serve a key set.** Rejected because the tr1d1um rollout could not wait, and because some deployments use the per-key pattern for good.
- **Point key set sources at fixed per-key URLs.** Rejected as the only answer because every verifier would then need a configuration change at each key rotation, where today rotation needs none.
