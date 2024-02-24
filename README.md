# Instructions for AndGo

## About
This repository wraps the 0.6.0 release of taurusgroup/multi-party-sig and adds some convenience:

- The ability to execute rounds of `cmp/keygen` and `cmp/sign` asynchronously
- The ability to derive BIP32 addresses for keys derived in the above manner
- A 'main' package that contains sample code
- The ability to compile core parts of this library to C Shared Output (.so)
- Some bug fixes and feature additions that were added to main branch after alpha 0.6.0 release

Ultimately this repository is to be used to create .so files to be used in NodeJS libraries and Expo modules.

## Build Instructions
To build C libraries, run:

### For Linux (amd64, arm64)
This one works natively on an x86_64 linux device without issue
`CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build -buildmode=c-shared -o andgo-mpc-linux-amd64.so main.go`
Get cross compiler for arm64 linux with `apt install gcc-aarch64-linux-gnu`
`CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-gcc CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build -buildmode=c-shared -o andgo-mpc-linux-arm64.so main.go`
No binary provided for armv7 (32 bit support requires in-depth adjustments to Go code)

### For Android (amd64, arm64) -- NO armv7
The following require NDK & CMake to be installed via Android Studio SDK Manager.
See best answer to https://stackoverflow.com/questions/65366107/go-with-networking-on-android
`CC=$(HOME)/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android34-clang CXX=$(HOME)/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android34-clang CGO_ENABLED=1 GOOS=android GOARCH=amd64 go build -buildmode=c-shared -o andgo-mpc-android-amd64.so main.go`
`CC=/home/kishin/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang CXX=/home/kishin/Android/Sdk/ndk/26.2.11394342/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android34-clang CGO_ENABLED=1 GOOS=android GOARCH=arm64 go build -buildmode=c-shared -o andgo-mpc-android-arm64.so main.go`
No binary provided for armv7 (32 bit support requires in-depth adjustments to Go code)

### For iOS (amd64, arm64) -- NO armv7
The following require XCode (& MacOS) !!! buildmode c-shared not supported on ios/amd64, ios/arm64
`CC='xcrun --sdk iphoneos -f clang' CXX='xcrun --sdk iphoneos -f clang' CGO_ENABLED=1 GOOS=ios GOARCH=amd64 go build -buildmode=c-archive -o andgo-mpc-ios-amd64.a main.go`
`CC='xcrun --sdk iphoneos -f clang' CXX='xcrun --sdk iphoneos -f clang' CGO_ENABLED=1 GOOS=ios GOARCH=arm64 go build -buildmode=c-archive -o andgo-mpc-ios-arm64.a main.go`
No binary provided for armv7 (32 bit support requires in-depth adjustments to Go code)

### For MacOS & Windows (TODO)
Mac and Windows not supported by default. The following commands have not yet been adapted or tested.
The following require ???
`CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -buildmode=c-shared -o andgo-mpc-darwin-amd64.dylib main.go`
`CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -buildmode=c-shared -o andgo-mpc-darwin-arm64.dylib main.go`
The following require ???
`CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -buildmode=c-shared -o andgo-mpc.dll main.go`

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