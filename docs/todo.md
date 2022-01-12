Implementation
===

There is 3 parts to implement 'independently'

Crypto
---

We are goind to base our encryption scheme on the elliptic curve [`ed25519`](https://www.cryptopp.com/wiki/Ed25519) because it's one of the fastest elliptic curve available.

- At node initialization
  - [ ] Generate the private, public key pair
  - [ ] Broadcast its own public key with the whole network
- When sending a message through the network
  - [ ] Encode each layer with the public key corresponding to the correct node on the path
- ...

Onion behavior
---

- ...

GUI
---

Question: Should we do a `socks5 proxy` and force the browser to use the proxy to reach internet or do a complete interface?

- [ ] Create a page to visualize the path
- ...


Structure
===

A proposition would be the one below so we can create any file we want in each package

``` bash
.
├── crypto
│   ├── ed25519.go
│   └── mod.go
├── gui
│   └── mod.go
└── onion
    └── mod.go
```
