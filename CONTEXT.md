<!-- SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# clortho

The client-side library a service uses to obtain the public keys that verify JWS signatures, such as those on JWTs. It runs inside the verifying service: it reads key sets, keeps them current, and hands keys to jwx. It never issues a token and never serves a key.

## Language

### The parties

**clortho**:
This library, running inside a service that verifies tokens. In prose it names the client side as a whole.
_Avoid_: the provider (ambiguous, see **Provider**), the client, the verifier

**Provider**:
The `clortho.Provider` value a service builds with `clortho.New`: the in-process object that owns the **Ring**, runs every **Refresh**, and answers each **Lookup**. It is named for the jwx interface it satisfies, `jws.KeyProvider`, and is never the remote end. Wherever a bare "provider" could be read as the **Key Set Server**, write "clortho" or "the clortho.Provider".
_Avoid_: provider for the server that publishes keys, service provider, key provider

**Key Set Source**:
One configured location that clortho reads a **Key Set** from: an http or https URL, or a file path. It is one `RefreshSource` entry in `Config.Sources`, and almost always a **Key Set Server**. "Source" alone means this.
_Avoid_: provider, endpoint, origin, upstream, location

**Key Set Server**:
The HTTP server behind an http or https **Key Set Source**; for xmidt, themis. The word is used in place of "source" only for behavior that needs HTTP, such as `Retry-After` and `Cache-Control`, since a file source has no server. "Server" alone means this.
_Avoid_: provider, issuer, upstream

**Issuer**:
The party that signs tokens and publishes the matching public keys. For xmidt that is themis, which is also the **Key Set Server**, but the roles are distinct: clortho only ever talks to the key set server.
_Avoid_: provider, signer

**Token**:
A JWS, in practice a JWT, that the service is verifying. clortho never parses or validates one. It sees only the `kid` and `alg` of the protected header, which jwx passes in at a **Lookup**.
_Avoid_: request, credential

### Keys

**Key**:
The key material itself, always in its public form by the time it is on the **Ring**. Never a string.
_Avoid_: key for a **Key ID**

**Key ID**:
The string that names one **Key**: the `kid` member of a JWK and of a token's protected header. Every string identifier in the package is a key ID. `kid` is the JSON member name, "key ID" is the concept.
_Avoid_: key (for the string), key name, thumbprint (a key with no `kid` is an error, not given a computed one)

**Key Set**:
The complete document a **Key Set Source** serves: a JWK set, or a single JWK treated as a set of one. clortho always reads the whole set and never asks a source for one key.
_Avoid_: keys file, key list, content, body (the body is the bytes, the key set is what they parse to)

**Ring**:
The **Provider**'s in-memory cache of **Keys**: one map from **Key ID** to key, fed by every **Key Set Source**. A key ID names exactly one key on it, so two sources may not supply the same one.
_Avoid_: key ring (the injectable `KeyRing` type is gone), cache, store

**Last Good Keys**:
The **Keys** a source put on the **Ring** at its most recent successful **Refresh**. They keep serving, with no time limit, for as long as later refreshes of that source fail.
_Avoid_: stale keys, cached keys

### Refreshing

**Refresh**:
One read of one **Key Set Source** and the application of what it served to the **Ring**, whether or not it succeeds. Each one ends in a **Refresh Event**, unless it is an **Abandoned Refresh**.
_Avoid_: fetch (see **Lookup**), poll, resolve (the per-key request that no longer exists)

**Normal Schedule**:
The timing of refreshes when nothing has gone wrong: the **Key Set Server**'s `Cache-Control` max-age if it sent one, otherwise `RefreshInterval`, spread by **Jitter** and kept between `MinRefreshInterval` and `MaxRefreshInterval`.
_Avoid_: polling interval, regular interval

**Scheduled Refresh**:
A **Refresh** that runs because the **Normal Schedule** came due.

**Failed Refresh**:
A **Refresh** that reports an error and leaves the **Ring** untouched. Either the source could not be read, or it served a **Rejected Key Set**.
_Avoid_: failed fetch, miss (a miss is an **Unknown Key ID**)

**Retry**:
The **Refresh** that follows a **Failed Refresh** sooner than the **Normal Schedule** would have run it. It comes after `MinRefreshInterval`, or after the **Server's Wait** when the server asked for one.
_Avoid_: backoff (the wait does not grow with repeated failures)

**Server's Wait**:
The pause a **Key Set Server** asks for with a `Retry-After` header on a 429 or 503 response. clortho honors it even when it is shorter than `MinRefreshInterval`, and caps it at `MaxRefreshInterval`.
_Avoid_: backoff, cooldown, rate limit (that is the limit on an **Early Refresh**)

**Rejected Key Set**:
A **Key Set** the source served in full and clortho would not accept. It holds a symmetric key, a key with no **Key ID**, or a key ID that appears twice or that another source already supplies, or it is larger than `MaxResponseBytes`. It gets no **Retry**, because the source would serve the same set again, unless the source has **Never Loaded**.
_Avoid_: refused key set, bad set, invalid content, policy failure

**Never Loaded**:
The state of a **Key Set Source** that has had no successful **Refresh** since its **Provider** was built, so it has no **Last Good Keys**. Every **Failed Refresh** of such a source gets a **Retry**, a **Rejected Key Set** included.
_Avoid_: cold, empty, uninitialized

**Early Refresh**:
A **Refresh** triggered by a **Lookup** for an **Unknown Key ID**, when `VerifyConfig.RefreshOnUnknownKeyID` is on. It is limited to one per source per `MinRefreshInterval`, never runs inside a **Server's Wait**, and is the only way a **Token** can cause a request.
_Avoid_: on-demand fetch, resolve, lazy load

**Abandoned Refresh**:
A **Refresh** that `Stop` interrupted. It is not a **Failed Refresh**: nothing is recorded in **Status** and no **Refresh Event** is sent.
_Avoid_: canceled refresh, failed refresh

**Jitter**:
The random spread applied to every wait so that a fleet that started together does not reach the **Key Set Server** in lockstep. On the **Normal Schedule** it runs either side of the interval, on a server's max-age only earlier, and on a **Retry** only later.
_Avoid_: fuzz, randomization

### Verifying

**Lookup**:
jwx asking the **Provider**, through `FetchKeys`, for the **Key** that matches a **Token**'s **Key ID**. It is answered from the **Ring** and reads no source.
_Avoid_: fetch (despite the method name), resolve

**Unknown Key ID**:
A **Key ID** from a **Token** that is not on the **Ring**. The **Lookup** fails with `ErrKeyNotFound`, unless an **Early Refresh** puts the key there first.
_Avoid_: missing key, cache miss

**Verify Policy**:
The checks a **Key** must pass at a **Lookup** before it is offered to jwx: its `use`, when present, is `sig`, and its `alg`, when present, matches the token's. `VerifyConfig` can turn each check off.
_Avoid_: key validation, key filter

### Observing

**Refresh Event**:
The report of one **Refresh**, delivered to every **Listener**: the source, the error if there was one, the **Key IDs** the source now supplies, added, and removed, and the size of the **Key Set** those keys came from. It carries key IDs, never **Keys**.
_Avoid_: notification, callback

**Listener**:
A sink for **Refresh Events**. `clorthozap` logs them and `clorthometrics` counts them.
_Avoid_: observer, subscriber, hook

**Status**:
The per-source record of the most recent **Refresh**: when the source last succeeded, the last HTTP status, and the last error. It is what a readiness check reads to decide whether the **Provider** has keys.
_Avoid_: health, state

## Relationships

- A service builds one **Provider**. A **Provider** has exactly one **Ring** and one or more **Key Set Sources**.
- A **Key Set Source** serves one **Key Set**, which holds one or more **Keys**. Each **Key** has one **Key ID**, unique across the whole **Ring**.
- Each **Key Set Source** has its own refresh loop. Every **Refresh** it runs is a **Scheduled Refresh**, a **Retry**, or an **Early Refresh**.
- A **Failed Refresh** is followed by a **Retry**. The one exception is a **Rejected Key Set** from a source that has loaded before, which waits for the **Normal Schedule**.
- A **Lookup** reads the **Ring** and nothing else. Only an **Early Refresh** connects a **Token** to a **Key Set Source**.
- The **Issuer** and the **Key Set Server** are often the same system. The **Provider** is never either of them.

## Example dialogue

> **Dev:** "themis answered our refresh with a 503 and `Retry-After: 30`. Does the provider know best there, or do we still wait out `MinRefreshInterval`?"
> **Maintainer:** "Careful with 'provider'. The **Provider** is clortho, in our process. You mean the **Key Set Server**. And it does know best: that is a **Server's Wait**, so clortho makes its **Retry** in thirty seconds even though the minimum is ten minutes."
> **Dev:** "What if themis publishes a set with a symmetric key in it?"
> **Maintainer:** "Then the source answered and clortho has a **Rejected Key Set**. There is no **Retry**, because asking again gets the same set. The **Last Good Keys** keep serving and the next **Scheduled Refresh** comes on the **Normal Schedule**."
> **Dev:** "And if the service started while that bad set was published?"
> **Maintainer:** "Then the source has **Never Loaded** and there are no keys to serve, so it does get a **Retry** after the minimum, and keeps getting one until someone fixes the set."
> **Dev:** "Could a flood of tokens with made-up key IDs make us hammer themis?"
> **Maintainer:** "No. A **Lookup** reads the **Ring** and makes no request. With `RefreshOnUnknownKeyID` on, an **Unknown Key ID** can trigger an **Early Refresh**, but at most one per source per minimum interval, and none during a **Server's Wait**."

## Flagged ambiguities

- "provider" was used for both the `clortho.Provider` and the server that publishes keys, as in "the provider probably knows best". Resolved: **Provider** is always the clortho object. The remote end is the **Key Set Source**, or the **Key Set Server** when HTTP is the point. Prose that could be misread says "clortho" or "the clortho.Provider".
- "source" and "server" are not synonyms. A **Key Set Source** may be a file. "Server" is used only where the behavior needs HTTP.
- "fetch" suggests a network request, but `FetchKeys` is jwx's name for a **Lookup** and makes none. Reading a source is a **Refresh**.
- "key" was used for both the material and its identifier. Resolved: **Key** is the material and **Key ID** is the string.
- "refused" and "rejected" were both used for a key set clortho would not accept. Resolved: **Rejected Key Set**. A single **Key** can also fail the **Verify Policy** at a **Lookup**; that is a failed lookup, not a **Failed Refresh**.
- "retry" is not backoff. The wait before a **Retry** is the same after the tenth failure as after the first, unless the server sends a different **Server's Wait**.
- "the minimum" and "the maximum" always mean the `MinRefreshInterval` and `MaxRefreshInterval` of the source in question, never a package-wide value.
