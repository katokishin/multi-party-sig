package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
)

func sample() {
	// Exchange of data can occur concurrently or asynchronously
	// Communications between participants is left to the library user,
	// e.g. REST API, websockets, email, QR codes

	// Keygen example
	// First party (alice) initiates keygen
	// All parties share the same parameters except for "Self"
	opts := KeygenOptions{
		Participants: []party.ID{"alice", "bob", "charlie"},
		Self:         "alice",
		Threshold:    1,
		SessionId:    []byte("abc-2of3-test"),
	}
	// Create a handler for Alice
	aliceHandler, err := StartKeygen(opts)
	if err != nil {
		fmt.Println(err)
		return
	}
	// aliceHandler.PrintCurrentRound() // 1
	// Create a handler for Bob and Charlie
	// In reality, this happens on a different machine
	opts.Self = "bob"
	bobHandler, err := StartKeygen(opts)
	if err != nil {
		fmt.Println(err)
		return
	}
	opts.Self = "charlie"
	charlieHandler, err := StartKeygen(opts)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Each handler is now in "round1" state.
	// The progression loop is as follows:
	// 1. ProcessRound() to generate messages to broadcast/send.
	// This should also update the current roundNumber if successful
	// 2. AddReceivedMsgs() to add those messages to the handler.
	// Once all required messages are added, it returns bool 'true'

	// Declare a few variables for the Keygen loop
	n := len(opts.Participants)
	aRes := ContKeygenResult{
		Handler: aliceHandler,
		Msgs:    make([]*protocol.Message, 0, n),
	}
	bRes := ContKeygenResult{
		Handler: bobHandler,
		Msgs:    make([]*protocol.Message, 0, n),
	}
	cRes := ContKeygenResult{
		Handler: charlieHandler,
		Msgs:    make([]*protocol.Message, 0, n),
	}
	// Message accumulator
	messages := make([]*protocol.Message, 0, n*n)

	for {
		aRes, err = ContKeygen(ContKeygenParams{Handler: aRes.Handler, Msgs: messages})
		if err != nil {
			fmt.Println(err)
			return
		}

		aj, e2 := json.Marshal(aRes)
		if e2 != nil {
			fmt.Println(e2)
			return
		}
		e2 = json.Unmarshal(aj, &aliceHandler)

		// fmt.Println(aliceProcessResult)  // [message: round 2, from: alice, to , protocol: cmp/keygen-threshold]
		// aliceHandler.PrintCurrentRound() // 2, 3, 4, 5, 5

		// Advance bob and charlie's rounds as well
		bRes, err = ContKeygen(ContKeygenParams{Handler: bRes.Handler, Msgs: messages})
		if err != nil {
			fmt.Println(err)
			return
		}
		cRes, err = ContKeygen(ContKeygenParams{Handler: cRes.Handler, Msgs: messages})
		if err != nil {
			fmt.Println(err)
			return
		}
		// Clear and accumulate messages to send to each other
		messages = make([]*protocol.Message, 0, n*n)
		messages = append(messages, aRes.Msgs...)
		messages = append(messages, bRes.Msgs...)
		messages = append(messages, cRes.Msgs...)

		if aRes.Config != nil && bRes.Config != nil && cRes.Config != nil {
			fmt.Println("Keygen complete")
			break
		}
	}
	// These config files hold each keyshare and other info
	fmt.Printf("Alice's config: %+v\n", aRes.Config)
	fmt.Printf("Bob's config: %+v\n", bRes.Config)
	fmt.Printf("Charlie's config: %+v\n", cRes.Config)

	// Derive child keys BIP32-style example
	// These return new *cmp.Config
	fmt.Println("Attempting BIP32 child key derivation...")
	aliceBip32Child, err := aRes.Config.DerivePath("m/0/0/0")
	bobBip32Child, err := bRes.Config.DerivePath("m/0/0/0")

	// Sign example
	// Sign a message with these child shares
	signopts := SignOptions{
		Config:     aliceBip32Child,
		Signers:    []party.ID{"alice", "bob"}, // Only those who will sign
		HashToSign: sha256.Sum256([]byte("dummy message")),
		SessionId:  []byte("sign-session-ab"),
	}
	// Create round 1 for alice and bob
	aliceSignHandler, err := StartSign(signopts)
	if err != nil {
		fmt.Println(err)
		return
	}
	signopts.Config = bobBip32Child
	bobSignHandler, err := StartSign(signopts)
	if err != nil {
		fmt.Println(err)
		return
	}

	// Each handler is in round1 state (as with keygen)
	// Now to start the signing loop...
	m := len(signopts.Signers)
	aSRes := ContSignResult{
		Handler:     aliceSignHandler,
		Msgs:        make([]*protocol.Message, 0, m),
		Sig:         nil,
		SigEthereum: nil,
	}
	bSRes := ContSignResult{
		Handler:     bobSignHandler,
		Msgs:        make([]*protocol.Message, 0, m),
		Sig:         nil,
		SigEthereum: nil,
	}
	// Message accumulator
	messages = make([]*protocol.Message, 0, m*m)

	for {
		aSRes, err = ContSign(ContSignParams{Handler: aSRes.Handler, Msgs: messages})
		if err != nil {
			fmt.Println(err)
			return
		}
		bSRes, err = ContSign(ContSignParams{Handler: bSRes.Handler, Msgs: messages})
		if err != nil {
			fmt.Println(err)
			return
		}

		// Clear and accumulate messages to send to each other
		messages = make([]*protocol.Message, 0, m*m)
		messages = append(messages, aSRes.Msgs...)
		messages = append(messages, bSRes.Msgs...)

		if aSRes.Sig != nil && bSRes.Sig != nil {
			fmt.Println("Signing complete!")
			break
		}
	}

	// Returns an ecdsa.Signature object with 32 byte R & 32 byte S value
	// Should be the same for both?
	fmt.Printf("%+v %+v\n", aSRes.Sig, aSRes.SigEthereum)
	fmt.Printf("%+v %+v\n", bSRes.Sig, bSRes.SigEthereum)

}
