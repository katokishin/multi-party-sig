# Instructions for AndGo

To build C shared library, run:

`go build -buildmode=c-shared -o andgo-mpc.so main.go`

This repository wraps the 0.6.0 release of taurusgroup/multi-party-sig and adds some convenience:

- The ability to execute rounds of `cmp/keygen` and `cmp/sign` asynchronously
- The ability to derive BIP32 addresses for keys derived in the above manner
- A 'main' package that contains sample code
- The ability to compile core parts of this library to C Shared Output (.so)
- Some bug fixes and feature additions that were added to main branch after alpha 0.6.0 release

Ultimately this repository is to be used to create .so files to be used in NodeJS libraries and Expo modules.

## How the code works

Keygen and Sign are both 5-round processes. Each round can begin once the messages from the previous round have been exchanged.

### Keygen

Assuming a 2-of-3 threshold keygen between Alice, Bob, and Charlie:

- Round 1 starts with initialization (list of names, self name, threshold, session ID, etc.)
- Folowed by exchange of broadcast messages
- Rounds 2 - 4 start with a `Session` object with all requisite messages, and may be followed by both broadcast and targeted messages to be exchanged among users.
- After key share messages are exchanged in Round 4, Round 5 results in a `Config` object for each user containing their keyshare and public key information for the group. This MUST be saved for future use when signing.

Glossary:

`Session ID`: Must be shared when initializing the keygen, used to identify the `Session` objects across users. Can be a counter, esp. if initiator is always the same.

`Session` object: Contains information on the session, including private key material unique to the owner. Must be secure & NOT sent to other participants! May be worth exporting if coordination among users takes some time.

`Config` object: Also unique to the owner and confidential, the config object stores information on a MPC group and persists across sessions.

### Derive BIP32 keypairs

`Config` object can be tweaked to derive shares for a BIP32 derivation path e.g. `c.DeriveBIP32(i)` where `i = derivation index`.

Derivation path `m/84/0/1` for example is the result of three derivations of 32 bit integers `84`, `0`, then `1`. This library only supports unhardened derivation, e.g. ones without `'`s in the derivation path (`m/84'/0'/1'` won't work).

Should be used along with deriving BIP32 addresses from the master public key.

### Sign

Assuming a 2-of-3 between Alice, Bob, and Charlie where Alice and Bob are the signers:

- Each round consists of message exchange (either broadcast or P2P)
- At the end of execution, we get a signature in 2 formats: `{R: {X, Y, (Z)}, S}` or `base64(concat(byte, R.X, S, yParity))`.

## Sample code explanation

See sample code in `main.go` for Go native example.