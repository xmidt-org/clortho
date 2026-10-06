<!-- SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# No default HTTP client

Anything clortho reaches over http or https must be given its `*http.Client`, and clortho uses that client exactly as given. An earlier version built a default client, with a timeout and no redirects, whenever none was supplied. That hid a wiring mistake: a service that forgot to pass its client got one with none of its TLS, proxy, or authorization setup, and found out when fetches failed at runtime. A missing client now fails when the provider is built. The cost is that clortho no longer enforces a timeout or refuses redirects on its own. Those protections are the caller's to configure, and the example on the constructor shows a client suited to fetching keys.

## Consequences

- A client that follows redirects is followed, so the server and not the configured URL can decide where key material comes from. Refusing redirects is the caller's choice.
- A client given to a file source is also an error, since it nearly always means a URL was written without its scheme and so reads as a file path.
