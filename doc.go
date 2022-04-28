/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Package clortho provides key management for clients.
//
// The two most important types in this package are the Resolver and the KeyRing.
// A KeyRing is essentially a local cache of keys, accessible via the key's kid (key ID)
// attribute.  A Resolver resolves keys by key ID from an external source, optionally
// using a KeyRing as a cache.
//
// A Refresher can be used to asynchronously update keys in one or more KeyRing instances
// or arbitrary client code that handles refresh events.
package clortho
