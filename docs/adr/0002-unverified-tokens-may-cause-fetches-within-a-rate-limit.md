<!-- SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# Unverified tokens may cause fetches, within a rate limit

A Per-Key Provider fetches a key because a token named it, before anyone has verified that token, so a flood of invented key IDs could become a flood of requests to the key server. We bound that with a Fetch Rate Limit on key IDs that are not Allowed Key IDs: by default one fetch every ten seconds, and a lookup that is refused fails at once. We chose to protect the key server over finding a new key quickly, and accept that a real new key may be delayed for as long as a flood lasts, because an unverified caller should not be able to turn a verifier into a load generator against the server every other service depends on. Allowed Key IDs are exempt, so a flood cannot crowd out a key the operator listed, and an operator who lists every key can turn fetching for all others off.

## Consequences

- Every key ID, allowed or not, also has a Cool-Down after a failed fetch: long when the server says there is no such key, short when the server could not answer.
- The rate limit and the long Cool-Down together bound what a provider remembers about invented key IDs, so there is no separate cap on memory.
- The rate limit is imperfect by design. It cannot tell an invented key ID from a real one that has not been seen yet, which is why listing the real ones is the complete fix.
