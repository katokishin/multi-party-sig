package main

// #cgo CFLAGS: -g -Wall
// #include <stdio.h>
// #include <stdlib.h>
import "C"

// `GOOS=wasip1 GOARCH=wasm go build -o main.wasm` to build to wasi

import (
	"encoding/json"
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/keygen"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/sign"
)

func main() {
}

// Put sample() in main to run Golang example

func init() {
	runtime.GOMAXPROCS(1)
	debug.SetGCPercent(-1)
}

type KeygenOptions struct {
	Participants []party.ID
	Self         party.ID
	Threshold    int
	SessionId    []byte
}

type ContKeygenParams struct {
	Handler *protocol.MultiHandler
	Msgs    []*protocol.Message
}

type ContKeygenParamsJSON struct {
	Handler protocol.MultiHandler
	Msgs    []protocol.Message
}

func (p *ContKeygenParams) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	e := json.Unmarshal(j, &tmp)
	if e != nil {
		return e
	}

	var h protocol.MultiHandler
	if err := json.Unmarshal(tmp["Handler"], &h); err != nil {
		return err
	}
	var ms []*protocol.Message
	if err := json.Unmarshal(tmp["Msgs"], &ms); err != nil {
		return err
	}
	return nil
}

type ContKeygenResult struct {
	Handler     *protocol.MultiHandler
	Config      *cmp.Config
	AllReceived bool
	Msgs        []*protocol.Message
}

//export StartKeygenC
func StartKeygenC(opts *C.char) *C.char {
	// Convert JSON params to object
	var optStruct KeygenOptions
	o := C.GoString(opts)
	e := json.Unmarshal([]byte(o), &optStruct)
	if e != nil {
		fmt.Println("JSON Unmarshal Error:", e)
		return C.CString(e.Error())
	}
	h, e := StartKeygen(optStruct)
	if e != nil {
		fmt.Println("StartKeygen Error:", e)
		return C.CString(e.Error())
	}

	// Using handler, run ContKeygen one time
	p := ContKeygenParams{
		Handler: h,
		Msgs:    make([]*protocol.Message, 0),
	}
	rr, e := ContKeygen(p)
	if e != nil {
		fmt.Println("ContKeygen Error:", e)
		return C.CString(e.Error())
	}

	// Return results
	rrJson, e := json.Marshal(rr)
	if e != nil {
		fmt.Println("JSON Marshal Error:", e)
		return C.CString(e.Error())
	}
	return C.CString(string(rrJson))
}

//export ContKeygenC
func ContKeygenC(opts *C.char) *C.char {
	// Convert JSON params to object
	var optString map[string]json.RawMessage
	o := C.GoString(opts)
	e := json.Unmarshal([]byte(o), &optString)
	if e != nil {
		fmt.Println("JSON Unmarshal Error at optString:", e)
		return C.CString(e.Error())
	}

	optStruct := ContKeygenParams{}
	messages := make([]*protocol.Message, 0)
	e = json.Unmarshal(optString["Msgs"], &messages)
	if e != nil {
		fmt.Println("JSON Unmarshal Error getting Msgs:", e)
		return C.CString(e.Error())
	}
	optStruct.Msgs = messages

	h, e := MultiHandlerFromJSON(optString["Handler"])
	if e != nil {
		fmt.Println("JSON Unmarshal Error getting Handler:", e)
		return C.CString(e.Error())
	}
	optStruct.Handler = h

	r, e := ContKeygen(optStruct)
	if e != nil {
		fmt.Println("ContKeygen Error:", e)
		return C.CString(e.Error())
	}
	rJson, e := json.Marshal(r)
	if e != nil {
		fmt.Println("JSON Marshal Error:", e)
		return C.CString(e.Error())
	}
	return C.CString(string(rJson))
}

func StartKeygen(opts KeygenOptions) (*protocol.MultiHandler, error) {
	h, e := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, opts.Self, opts.Participants, opts.Threshold, nil), opts.SessionId)
	if e != nil {
		return nil, e
	}
	return h, nil
}

// Continuing the keygen handling.
// Case 1: Pass it a handler & messages to add & process
// -> If sufficient: Returns updated handler & messages to
// send/broadcast.
// -> If sufficient & protocol complete: Returns Config
// along with updated handler
// -> If insufficient: Returns updated handler with
// AllReceived set to false.
// Case 2: Pass it a handler & empty messages slice
// -> Attempts to advance round with what we already have
// -> Successful: Returns updated handler & messages to
// send/broadcast
// -> If unsuccessful: Error
// Case 3: No handler is passed -> Error
func ContKeygen(params ContKeygenParams) (r ContKeygenResult, e error) {
	if params.Handler == nil {
		return ContKeygenResult{}, fmt.Errorf("No handler found")
	}
	r.Handler = params.Handler
	// If no message params, attempt to process round
	if len(params.Msgs) == 0 {
		// Get messages to send/broadcast, if any
		r.Msgs = r.Handler.ProcessRound()
		// If the protocol has completed, return config file
		res, e := returnConfigIfDone(r)
		if e == nil {
			return res, nil
		} else {
			return r, e
		}
	}
	// If message(s) in params, add to handler
	// also attempt to process round if .ReceivedAll()
	bool := r.Handler.AddReceivedMsgs(params.Msgs)
	r.AllReceived = bool
	if r.AllReceived == true {
		// Get messages to send/broadcast, if any
		r.Msgs = r.Handler.ProcessRound()
		// If the protocol has completed, return config file
		res, e := returnConfigIfDone(r)
		if e == nil {
			return res, nil
		} else {
			return r, e
		}
	}

	// r.AllReceived is false; need to receive more
	// messages to continue
	fmt.Println("Still missing some messages")
	r.Msgs = params.Msgs
	return r, nil
}

func returnConfigIfDone(r ContKeygenResult) (res ContKeygenResult, e error) {
	// If the protocol has completed, return config file
	if len(r.Msgs) == 0 && r.Handler.GetCurrentRound() == 5 {
		r.AllReceived = true
		r.Config, e = r.Handler.GetConfigOrErr()
		if e != nil {
			fmt.Println("returnConfigIfDone error:", e)
		}
		return r, e
	}
	// Else, set receivedAll bool and return
	if r.Handler.ReceivedAll() {
		r.AllReceived = true
	} else {
		r.AllReceived = false
	}
	return r, e
}

// StartSignC and ContSignC take a string (serialized object)
// and returns a string (serialized object)
// Errors should be included in the response object

type SignOptions struct {
	Signers    []party.ID
	Config     *cmp.Config
	HashToSign []byte
	SessionId  []byte
}

type ContSignParams struct {
	Handler *protocol.MultiHandler
	Msgs    []*protocol.Message
}

type ContSignResult struct {
	Handler     *protocol.MultiHandler
	Msgs        []*protocol.Message
	AllReceived bool
	Sig         *ecdsa.Signature
	SigEthereum []byte
}

//export StartSignC
func StartSignC(opts *C.char) *C.char {
	var optStruct SignOptions
	o := C.GoString(opts)
	e := json.Unmarshal([]byte(o), &optStruct)
	if e != nil {
		fmt.Println("JSON.Unmarshal Error:", e)
		return C.CString(e.Error())
	}
	h, e := StartSign(optStruct)
	if e != nil {
		fmt.Println("StartSign Error:", e)
		return C.CString(e.Error())
	}

	// Run ContSign one time using handler
	p := ContSignParams{
		Handler: h,
		Msgs:    make([]*protocol.Message, 0),
	}
	rr, e := ContSign(p)
	if e != nil {
		fmt.Println("ContSign Error:", e)
		return C.CString(e.Error())
	}
	// Return JSON
	rrJson, e := json.Marshal(rr)
	if e != nil {
		fmt.Println(e)
		return C.CString(e.Error())
	}
	return C.CString(string(rrJson))
}

//export ContSignC
func ContSignC(opts *C.char) *C.char {
	var optString map[string]json.RawMessage
	o := C.GoString(opts)
	e := json.Unmarshal([]byte(o), &optString)
	if e != nil {
		fmt.Println("JSON.Unmarshal Error:", e)
		return C.CString(e.Error())
	}

	optStruct := ContSignParams{}
	messages := make([]*protocol.Message, 0)
	e = json.Unmarshal(optString["Msgs"], &messages)
	if e != nil {
		fmt.Println("JSON Unmarshal Error getting Msgs:", e)
		return C.CString(e.Error())
	}
	optStruct.Msgs = messages

	h, e := MultiHandlerFromJSON(optString["Handler"])
	if e != nil {
		fmt.Println("JSON Unmarshal Error getting Handler:", e)
		return C.CString(e.Error())
	}
	optStruct.Handler = h

	r, e := ContSign(optStruct)
	if e != nil {
		fmt.Println("ContSign Error:", e)
		return C.CString(e.Error())
	}
	rJson, e := json.Marshal(r)
	if e != nil {
		fmt.Println(e)
		return C.CString(e.Error())
	}
	return C.CString(string(rJson))
}

func StartSign(opts SignOptions) (*protocol.MultiHandler, error) {
	h, e := protocol.NewMultiHandler(cmp.Sign(opts.Config, opts.Signers, opts.HashToSign[:], nil), opts.SessionId)
	if e != nil {
		return nil, e
	}
	return h, nil
}

func ContSign(params ContSignParams) (r ContSignResult, e error) {
	if params.Handler == nil {
		return ContSignResult{}, fmt.Errorf("No handler found")
	}
	r.Handler = params.Handler
	// If no message params, attempt to process round
	if len(params.Msgs) == 0 {
		// Get messages to send/broadcast, if any
		r.Msgs = r.Handler.ProcessRound()
		// If the protocol has completed, return signatures
		res, e := returnSigIfDone(r)
		if e == nil {
			return res, nil
		} else {
			return r, e
		}
	}
	// If message(s) in params, add to handler
	// also attempt to process round if .ReceivedAll()
	r.AllReceived = r.Handler.AddReceivedMsgs(params.Msgs)
	if r.AllReceived == true {
		// Get messages to send/broadcast, if any
		r.Msgs = r.Handler.ProcessRound()
		// If the protocol has completed, return signatures
		res, e := returnSigIfDone(r)
		if e == nil {
			return res, nil
		} else {
			return r, e
		}
	}
	return r, nil
}

func returnSigIfDone(r ContSignResult) (res ContSignResult, e error) {
	// If the protocol has completed, return signatures
	if len(r.Msgs) == 0 && r.Handler.GetCurrentRound() == 5 {
		r.AllReceived = true
		r.Sig, e = r.Handler.GetSignatureOrErr()
		if e != nil {
			return r, e
		}
		r.SigEthereum, e = r.Sig.SigEthereum()
		return r, e
	}
	// Else, set receivedAll bool and return
	if r.Handler.ReceivedAll() {
		r.AllReceived = true
	} else {
		r.AllReceived = false
	}
	return r, e
}

type DeriveParams struct {
	Config         cmp.Config
	DerivationPath string
}

//export deriveC
func deriveC(opts *C.char) *C.char {
	var dStruct DeriveParams
	o := C.GoString(opts)
	if e := json.Unmarshal([]byte(o), &dStruct); e != nil {
		fmt.Println("Failed to unmarhal DeriveParams @ dStruct:", e)
		return C.CString(e.Error())
	}
	bip32Child, e := dStruct.Config.DerivePath(dStruct.DerivationPath)
	if e != nil {
		fmt.Println("Failed to derive BIP32 child @ deriveC:", e)
		return C.CString(e.Error())
	}

	cJson, e := json.Marshal(bip32Child)
	if e != nil {
		fmt.Println("Failed to marshalJSON BIP32 child @ deriveC:", e)
		return C.CString(e.Error())
	}

	return C.CString(string(cJson))
}

func MultiHandlerFromJSON(j []byte) (*protocol.MultiHandler, error) {
	fmt.Println("=======================")

	h := protocol.MultiHandler{}

	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		return nil, err
	}

	// First determine what kind of round.Session it is
	// Then call the right kind of unmarshaller
	var crRaw map[string]json.RawMessage
	if err := json.Unmarshal(tmp["CurrentRound"], &crRaw); err != nil {
		return nil, err
	}

	var (
		crK1 keygen.Kround1
		crK2 keygen.Kround2
		crK3 keygen.Kround3
		crK4 keygen.Kround4
		crK5 keygen.Kround5
		crS1 sign.Sround1
		crS2 sign.Sround2
		crS3 sign.Sround3
		crS4 sign.Sround4
		crS5 sign.Sround5
	)

	if crRaw["UpdatedConfig"] != nil {
		// kg rd5
		if err := json.Unmarshal(tmp["CurrentRound"], &crK5); err != nil {
			return nil, err
		}
		h.CurrentRound = &crK5
		goto after_cr_judgement
	} else if crRaw["SigmaShares"] != nil {
		// sg rd 5
		if err := json.Unmarshal(tmp["CurrentRound"], &crS5); err != nil {
			return nil, err
		}
		h.CurrentRound = &crS5
		goto after_cr_judgement
	} else if crRaw["ChainKey"] != nil {
		// kg rd 4
		if err := json.Unmarshal(tmp["CurrentRound"], &crK4); err != nil {
			return nil, err
		}
		h.CurrentRound = &crK4
		goto after_cr_judgement
	} else if crRaw["DeltaShares"] != nil {
		// sg rd 4
		if err := json.Unmarshal(tmp["CurrentRound"], &crS4); err != nil {
			return nil, err
		}
		h.CurrentRound = &crS4
		goto after_cr_judgement
	} else if crRaw["SchnorrCommitments"] != nil {
		// kg rd 3
		if err := json.Unmarshal(tmp["CurrentRound"], &crK3); err != nil {
			return nil, err
		}
		h.CurrentRound = &crK3
		goto after_cr_judgement
	} else if crRaw["DeltaShareAlpha"] != nil {
		// sg rd 3
		if err := json.Unmarshal(tmp["CurrentRound"], &crS3); err != nil {
			return nil, err
		}
		h.CurrentRound = &crS3
		goto after_cr_judgement
	} else if crRaw["VSSPolynomials"] != nil {
		// kg rd 2
		if err := json.Unmarshal(tmp["CurrentRound"], &crK2); err != nil {
			return nil, err
		}
		h.CurrentRound = &crK2
		goto after_cr_judgement
	} else if crRaw["GammaShare"] != nil {
		// sg rd 2
		if err := json.Unmarshal(tmp["CurrentRound"], &crS2); err != nil {
			return nil, err
		}
		h.CurrentRound = &crS2
		goto after_cr_judgement
	} else if crRaw["VSSSecret"] != nil {
		// kg rd 1
		if err := json.Unmarshal(tmp["CurrentRound"], &crK1); err != nil {
			return nil, err
		}
		h.CurrentRound = &crK1
		goto after_cr_judgement
	} else if crRaw["ECDSA"] != nil {
		// sg rd 1
		if err := json.Unmarshal(tmp["CurrentRound"], &crS1); err != nil {
			return nil, err
		}
		h.CurrentRound = &crS1
		goto after_cr_judgement
	}

after_cr_judgement:

	// Next, we will populate Rounds
	// First determine what kind of round.Session each is
	// hint: simply check the round number??
	var (
		rdsK1 keygen.Kround1
		rdsK2 keygen.Kround2
		rdsK3 keygen.Kround3
		rdsK4 keygen.Kround4
		rdsK5 keygen.Kround5
		rdsS1 sign.Sround1
		rdsS2 sign.Sround2
		rdsS3 sign.Sround3
		rdsS4 sign.Sround4
		rdsS5 sign.Sround5
	)
	var rdsRaw map[round.Number]json.RawMessage
	if err := json.Unmarshal(tmp["Rounds"], &rdsRaw); err != nil {
		return nil, err
	}
	// map is unordered; let us order rounds properly for simplicity
	rdsRawArranged := make([]json.RawMessage, len(rdsRaw))
	for k, r := range rdsRaw {
		rdsRawArranged[k-1] = r
	}
	var rounds = make(map[round.Number]round.Session, 5)
	var tmpRd map[string]json.RawMessage
	for i, r := range rdsRawArranged {
		switch i {
		case 0:
			if err := json.Unmarshal(r, &tmpRd); err != nil {
				return nil, err
			}
			if tmpRd["VSSSecret"] != nil {
				if err := json.Unmarshal(r, &rdsK1); err != nil {
					fmt.Println("Unmarshaling Kround1 failed", err)
					return nil, err
				}
				var rdHelper round.Helper
				if err := json.Unmarshal(r, &rdHelper); err != nil {
					fmt.Println("Unmarshaling Kround1(Helper) failed", err)
					return nil, err
				}
				rdsK1.Helper = &rdHelper
				rounds[1] = &rdsK1
			} else if tmpRd["ECDSA"] != nil {
				if err := json.Unmarshal(r, &rdsS1); err != nil {
					fmt.Println(err)
					return nil, err
				}
				var rdHelper round.Helper
				if err := json.Unmarshal(r, &rdHelper); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rdsS1.Helper = &rdHelper
				rounds[1] = &rdsS1
			} else {
				return nil, fmt.Errorf("Could not unmarshal rounds[1]")
			}
		case 1:
			if err := json.Unmarshal(r, &tmpRd); err != nil {
				return nil, err
			}
			if tmpRd["VSSPolynomials"] != nil {
				if err := json.Unmarshal(r, &rdsK2); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rounds[2] = &rdsK2
			} else if tmpRd["GammaShare"] != nil {
				if err := json.Unmarshal(r, &rdsS2); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rounds[2] = &rdsS2
			} else {
				return nil, fmt.Errorf("Could not unmarshal rounds[2]")
			}
		case 2:
			if err := json.Unmarshal(r, &tmpRd); err != nil {
				return nil, err
			}
			if tmpRd["SchnorrCommitments"] != nil {
				if err := json.Unmarshal(r, &rdsK3); err != nil {
					fmt.Println("Could not unmarshal Kround3", err)
					return nil, err
				}
				rounds[3] = &rdsK3
			} else if tmpRd["DeltaShareAlpha"] != nil {
				if err := json.Unmarshal(r, &rdsS3); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rounds[3] = &rdsS3
			} else {
				return nil, fmt.Errorf("Could not unmarshal rounds[3]")
			}
		case 3:
			if err := json.Unmarshal(r, &tmpRd); err != nil {
				return nil, err
			}
			if tmpRd["ChainKey"] != nil {
				if err := json.Unmarshal(r, &rdsK4); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rounds[4] = &rdsK4
			} else if tmpRd["DeltaShares"] != nil {
				if err := json.Unmarshal(r, &rdsS4); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rounds[4] = &rdsS4
			} else {
				return nil, fmt.Errorf("Could not unmarshal rounds[4]")
			}
		case 4:
			if err := json.Unmarshal(r, &tmpRd); err != nil {
				return nil, err
			}
			if tmpRd["UpdatedConfig"] != nil {
				if err := json.Unmarshal(r, &rdsK5); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rounds[5] = &rdsK5
			} else if tmpRd["SigmaShares"] != nil {
				if err := json.Unmarshal(r, &rdsS5); err != nil {
					fmt.Println(err)
					return nil, err
				}
				rounds[5] = &rdsS5
			} else {
				return nil, fmt.Errorf("Could not unmarshal rounds[5]")
			}
		default:
			fmt.Println("Unknown round")
		}
	}

	var e *protocol.Error
	if err := json.Unmarshal(tmp["Err"], &e); err != nil {
		fmt.Printf("%+v\n", tmp["Err"])
		fmt.Println("Error unmarshalling e", err)
		return nil, err
	}

	var res interface{}
	if err := json.Unmarshal(tmp["ResultObj"], &res); err != nil {
		fmt.Println("Error unmarshalling res", err)
		return nil, err
	}

	msgs := make(map[round.Number]map[party.ID]*protocol.Message)
	if err := json.Unmarshal(tmp["Messages"], &msgs); err != nil {
		fmt.Println("Error unmarshalling messages", err)
		return nil, err
	}

	b := make(map[round.Number]map[party.ID]*protocol.Message)
	if err := json.Unmarshal(tmp["Broadcast"], &b); err != nil {
		fmt.Println("Error unmarshalling b", err)
		return nil, err
	}

	bh := make(map[round.Number][]byte)
	if err := json.Unmarshal(tmp["BroadcastHashes"], &bh); err != nil {
		fmt.Println("Error unmarshalling bh", err)
		return nil, err
	}

	var o []*protocol.Message
	if err := json.Unmarshal(tmp["Out"], &o); err != nil {
		fmt.Println("Error unmarshalling o", err)
		return nil, err
	}
	h.Rounds = rounds
	h.Err = e
	h.ResultObj = res
	h.Messages = msgs
	h.Broadcast = b
	h.BroadcastHashes = bh
	h.Out = o

	return &h, nil
}

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
			fmt.Println("==============Keygen complete===============")
			break
		}
	}
	// These config files hold each keyshare and other info
	fmt.Printf("Alice's config: %+v\n", aRes.Config)
	fmt.Printf("Bob's config: %+v\n", bRes.Config)
	fmt.Printf("Charlie's config: %+v\n", cRes.Config)
	/* Write configs to file to use separately
	aliceKeyJson, _ := json.Marshal(aRes)
	bobKeyJson, _ := json.Marshal(bRes)
	charlieKeyJson, _ := json.Marshal(cRes)
	os.WriteFile("aliceKey.json", aliceKeyJson, 0666)
	os.WriteFile("bobKey.json", bobKeyJson, 0666)
	os.WriteFile("charlieKey.json", charlieKeyJson, 0666)
	*/

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
		HashToSign: []byte("dummy message"),
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
