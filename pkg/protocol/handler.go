package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/config"
)

// StartFunc is function that creates the first round of a protocol.
// It returns the first round initialized with the session information.
// If the creation fails (likely due to misconfiguration), and error is returned.
//
// An optional sessionID can be provided, which should unique among all protocol executions.
type StartFunc func(sessionID []byte) (round.Session, error)

// Handler represents some kind of handler for a protocol.
type Handler interface {
	// Result should return the result of running the protocol, or an error
	Result() (interface{}, error)
	// Listen returns a channel which will receive new messages
	Listen() []*Message
	// Stop should abort the protocol execution.
	Stop()
	// CanAccept checks whether or not a message can be accepted at the current point in the protocol.
	CanAccept(msg *Message) bool
	// Accept advances the protocol execution after receiving a message.
	Accept(msg *Message)
}

// MultiHandler represents an execution of a given protocol.
// It provides a simple interface for the user to receive/deliver protocol messages.
type MultiHandler struct {
	CurrentRound    round.Session
	Rounds          map[round.Number]round.Session
	Err             *Error
	ResultObj       interface{}
	Messages        map[round.Number]map[party.ID]*Message
	Broadcast       map[round.Number]map[party.ID]*Message
	BroadcastHashes map[round.Number][]byte
	Out             []*Message
	mtx             sync.Mutex
}

func (h *MultiHandler) GetCurrentRound() round.Number {
	return h.CurrentRound.Number()
}

func (h *MultiHandler) GetConfigOrErr() (*config.Config, error) {
	c, err := h.Result()
	if err != nil {
		return nil, err
	}
	return c.(*config.Config), nil
}
func (h *MultiHandler) GetSignatureOrErr() (*ecdsa.Signature, error) {
	s, err := h.Result()
	if err != nil {
		return nil, err
	}
	return s.(*ecdsa.Signature), nil
}

// NewMultiHandler expects a StartFunc for the desired protocol. It returns a handler that the user can interact with.
func NewMultiHandler(create StartFunc, sessionID []byte) (*MultiHandler, error) {
	r, err := create(sessionID)
	if err != nil {
		return nil, fmt.Errorf("protocol: failed to create round: %w", err)
	}
	h := &MultiHandler{
		CurrentRound:    r,
		Rounds:          map[round.Number]round.Session{r.Number(): r},
		Messages:        newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		Broadcast:       newQueue(r.OtherPartyIDs(), r.FinalRoundNumber()),
		BroadcastHashes: map[round.Number][]byte{},
		Out:             make([]*Message, 0, 2*r.N()),
	}
	// h.finalize()
	return h, nil
}

// Result returns the protocol result if the protocol completed successfully. Otherwise an error is returned.
func (h *MultiHandler) Result() (interface{}, error) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	if h.ResultObj != nil {
		return h.ResultObj, nil
	}
	if h.Err != nil {
		return nil, *h.Err
	}
	return nil, errors.New("protocol: not finished")
}

// Listen returns a channel with outgoing messages that must be sent to other parties.
// The message received should be _reliably_ Broadcast if msg.Broadcast is true.
// The channel is closed when either an error occurs or the protocol detects an error.
func (h *MultiHandler) Listen() []*Message {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.Out
}

// CanAccept returns true if the message is designated for this protocol protocol execution.
func (h *MultiHandler) CanAccept(msg *Message) bool {
	r := h.CurrentRound
	if msg == nil {
		fmt.Println("Message cannot be accepted as it is nil")
		return false
	}
	// are we the intended recipient
	if !msg.IsFor(r.SelfID()) {
		fmt.Println("We are not the recipient for this message")
		return false
	}
	// is the protocol ID correct
	if msg.Protocol != r.ProtocolID() {
		fmt.Println("Message cannot be accepted as it is not for the correct protocol")
		return false
	}
	// check for same SSID
	if !bytes.Equal(msg.SSID, r.SSID()) {
		fmt.Printf("msg.SSID %+v, r.SSID %+v\n", msg.SSID, r.SSID())
		fmt.Println("Message cannot be accepted as it does not have the same SSID")
		return false
	}
	// do we know the sender
	if !r.PartyIDs().Contains(msg.From) {
		fmt.Println("Message cannot be accepted as we do not know the sender")
		return false
	}

	// data is cannot be nil
	if msg.Data == nil {
		fmt.Println("Message cannot be accepted as message data is nil")
		return false
	}

	// check if message for unexpected round
	if msg.RoundNumber > r.FinalRoundNumber() {
		fmt.Println("Message cannot be accepted as round number is greater than final")
		return false
	}

	if msg.RoundNumber < r.Number() && msg.RoundNumber > 0 {
		fmt.Println("Message cannot be accepted as round number is from past round")
		return false
	}

	return true
}

// Accept tries to process the given message. If an abort occurs, the channel returned by Listen() is closed,
// and an error is returned by Result().
//
// This function may be called concurrently from different threads but may block until all previous calls have finished.
func (h *MultiHandler) Accept(msg *Message) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	// exit early if the message is bad, or if we are already done
	// I removed !h.CanAccept(msg) from the following condition since we already check
	if h.Err != nil || h.ResultObj != nil || h.duplicate(msg) {
		return
	}

	// a msg with roundNumber 0 is considered an abort from another party
	if msg.RoundNumber == 0 {
		h.abort(fmt.Errorf("aborted by other party with error: \"%s\"", msg.Data), msg.From)
		return
	}

	h.store(msg)
	if h.CurrentRound.Number() != msg.RoundNumber {
		return
	}

	if msg.Broadcast {
		if err := h.verifyBroadcastMessage(msg); err != nil {
			fmt.Println("verifyBroadcastMessage failed in handler.Accept(); message:", msg)
			h.abort(err, msg.From)
			return
		}
	} else {
		if err := h.verifyMessage(msg); err != nil {
			fmt.Println("verifyMessage failed in handler.Accept(); message:", msg)

			// h.abort(err, msg.From)
			return
		}
	}

	// h.finalize()
}

func (h *MultiHandler) verifyBroadcastMessage(msg *Message) error {
	r, ok := h.Rounds[msg.RoundNumber]
	if !ok {
		fmt.Println("verifyBroadcastMessage: relevant round not found in h.Rounds")
		return nil
	}

	// try to convert the raw message into a round.Message
	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		fmt.Println("verifyBroadcastMessage: could not convert raw message into round.Message")
		return err
	}

	// store the Broadcast message for this round
	if err = r.(round.BroadcastRound).StoreBroadcastMessage(roundMsg); err != nil {
		fmt.Println("verifyBroadcastMessage: error storing broadcast message")
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}
	// r now contains any updates made by broadcast message
	// Update round / currentRound with changes made by message
	h.Rounds[msg.RoundNumber] = r
	if msg.RoundNumber == h.CurrentRound.Number() {
		h.CurrentRound = r
	}

	// if the round only expected a Broadcast message, we can safely return
	if !expectsNormalMessage(r) {
		return nil
	}

	/*
		// otherwise, we can try to handle the p2p message that may be stored.
		msg = h.Messages[msg.RoundNumber][msg.From]
		if msg == nil {
			return nil
		}

		return h.verifyMessage(msg)
	*/
	return nil
}

// verifyMessage tries to handle a normal (non reliably Broadcast) message for this current round.
func (h *MultiHandler) verifyMessage(msg *Message) error {
	// we simply return if we haven't reached the right round.
	r, ok := h.Rounds[msg.RoundNumber]
	if !ok {
		fmt.Println("handler.verifyMessage: relevant round not found in h.Rounds")
		return nil
	}

	// exit if we don't yet have the Broadcast message
	if _, ok = r.(round.BroadcastRound); ok {
		q := h.Broadcast[msg.RoundNumber]
		if q == nil || q[msg.From] == nil {
			fmt.Println("handler.verifyMessage: waiting for the broadcast message first")
			return nil
		}
	}

	roundMsg, err := getRoundMessage(msg, r)
	if err != nil {
		fmt.Println("getRoundMessage (unmarshal raw message) failed in handler.verifyMessage")
		return err
	}

	// verify message for round
	if err = r.VerifyMessage(roundMsg); err != nil {
		fmt.Println("verifyMessage for round failed in handler.verifyMessage")
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	if err = r.StoreMessage(roundMsg); err != nil {
		fmt.Println("storeMessage for round failed in handler.verifyMessage")
		return fmt.Errorf("round %d: %w", r.Number(), err)
	}

	return nil
}

// Add received messages to handler
// Returns true if all messages received, otherwise returns false
func (h *MultiHandler) AddReceivedMsgs(msgs []*Message) bool {
	if len(msgs) == 0 || msgs[0] == nil {
		return false
	}

	// If messages can be accepted to handler, do so
	// This stores them in h.messages and h.Broadcast
	// Side effects may (should) update the current round as necessary
	for _, msg := range msgs {
		if h.CanAccept(msg) {
			h.Accept(msg)
		}
	}

	return h.ReceivedAll()
}

// Processes the round using messages added via AddReceivedMsgs()
// Returns a list of messages to Broadcast / send to peers
// May update the roundNumber
func (h *MultiHandler) ProcessRound() []*Message {
	if !h.ReceivedAll() {
		// Not ready to process round yet
		fmt.Println(h.CurrentRound.SelfID(), "is not ready to process the round yet")
		return nil
	}
	if !h.checkBroadcastHash() {
		h.abort(errors.New("Broadcast verification failed"))
		return nil
	}
	fmt.Printf("%+v is processing round %d\n", h.CurrentRound.SelfID(), h.CurrentRound.Number())
	// Create slice to contain all messages to be sent for next round
	out := make([]*round.Message, 0, h.CurrentRound.N()+1)
	// Get Broadcast and direct messages and store in slice
	// This calls Finalize() defined for each round
	// Make sure it is not a recursive call!
	r, out, err := h.CurrentRound.Finalize(out)

	// either we got an error due to some problem on our end (sampling etc)
	// or the new round is nil (should not happen)
	if err != nil || r == nil {
		fmt.Println("Some error happened or round was nil (should not happen):", err)
		h.abort(err, h.CurrentRound.SelfID())
		return nil
	}

	// Return here if we are done!
	// either we get the current round, the next one, or one of the two final ones
	switch R := r.(type) {
	// An abort happened
	case *round.Abort:
		h.abort(R.Err, R.Culprits...)
		fmt.Printf("Round was aborted; error %+v culprit %+v\n", R.Err, R.Culprits)
		return nil
	// We have the result
	case *round.Output:
		h.ResultObj = R.Result
		h.abort(nil)
		return nil
	default:
	}

	// Update roundNumber and CurrentRound with new one
	h.Rounds[r.Number()] = r
	h.CurrentRound = r

	// forward messages with the correct header.
	// First, clear the list of messages to be sent outbound
	h.Out = nil
	for _, roundMsg := range out {
		// If slice is empty, exit loop
		if roundMsg == nil {
			break
		}
		data, err := cbor.Marshal(roundMsg.Content)
		if err != nil {
			panic(fmt.Errorf("failed to marshal round message: %w", err))
		}
		msg := &Message{
			SSID:                  r.SSID(),
			From:                  r.SelfID(),
			To:                    roundMsg.To,
			Protocol:              r.ProtocolID(),
			RoundNumber:           roundMsg.Content.RoundNumber(),
			Data:                  data,
			Broadcast:             roundMsg.Broadcast,
			BroadcastVerification: h.BroadcastHashes[r.Number()-1],
		}
		if msg.Broadcast {
			h.store(msg)
		}
		h.Out = append(h.Out, msg)
	}
	return h.Out
}

func (h *MultiHandler) finalize() {
	// only finalize if we have received all messages
	if !h.ReceivedAll() {
		return
	}
	if !h.checkBroadcastHash() {
		h.abort(errors.New("Broadcast verification failed"))
		return
	}
	fmt.Printf("%+v is finalizing round %d\n", h.CurrentRound.SelfID(), h.CurrentRound.Number())
	out := make([]*round.Message, 0, h.CurrentRound.N()+1)
	// since we pass a large enough channel, we should never get an error
	r, out, err := h.CurrentRound.Finalize(out)
	// close(out)
	// either we got an error due to some problem on our end (sampling etc)
	// or the new round is nil (should not happen)
	if err != nil || r == nil {
		fmt.Println("new round is nil (should not happen) in handler.finalize()")
		h.abort(err, h.CurrentRound.SelfID())
		return
	}

	// forward messages with the correct header.
	for _, roundMsg := range out {
		if roundMsg == nil {
			break
		}
		fmt.Printf("%+v\n", roundMsg)
		data, err := cbor.Marshal(roundMsg.Content)
		if err != nil {
			panic(fmt.Errorf("failed to marshal round message: %w", err))
		}
		msg := &Message{
			SSID:                  r.SSID(),
			From:                  r.SelfID(),
			To:                    roundMsg.To,
			Protocol:              r.ProtocolID(),
			RoundNumber:           roundMsg.Content.RoundNumber(),
			Data:                  data,
			Broadcast:             roundMsg.Broadcast,
			BroadcastVerification: h.BroadcastHashes[r.Number()-1],
		}
		if msg.Broadcast {
			h.store(msg)
		}
		h.Out = append(h.Out, msg)
	}

	roundNumber := r.Number()
	// if we get a round with the same number, we can safely assume that we got the same one.
	if _, ok := h.Rounds[roundNumber]; ok {
		return
	}
	h.Rounds[roundNumber] = r
	h.CurrentRound = r

	// either we get the current round, the next one, or one of the two final ones
	switch R := r.(type) {
	// An abort happened
	case *round.Abort:
		h.abort(R.Err, R.Culprits...)
		return
	// We have the result
	case *round.Output:
		h.ResultObj = R.Result
		h.abort(nil)
		return
	default:
	}

	if _, ok := r.(round.BroadcastRound); ok {
		// handle queued Broadcast messages, which will then check the subsequent normal message
		for id, m := range h.Broadcast[roundNumber] {
			if m == nil || id == r.SelfID() {
				continue
			}
			// if false, we aborted and so we return
			if err = h.verifyBroadcastMessage(m); err != nil {
				fmt.Println("verifyBroadcastMessage failed in handler.finalize()")
				h.abort(err, m.From)
				return
			}
		}
	} else {
		// handle simple queued messages
		for _, m := range h.Messages[roundNumber] {
			if m == nil {
				continue
			}
			// if false, we aborted and so we return
			if err = h.verifyMessage(m); err != nil {
				fmt.Println("verifyMessage failed in handler.finalize()")
				h.abort(err, m.From)
				return
			}
		}
	}

	// we only do this if the current round has changed
	h.finalize()
}

func (h *MultiHandler) abort(err error, culprits ...party.ID) {
	if err != nil {
		h.Err = &Error{
			Culprits: culprits,
			Err:      err,
		}
		h.Out = append(h.Out, &Message{
			SSID:     h.CurrentRound.SSID(),
			From:     h.CurrentRound.SelfID(),
			Protocol: h.CurrentRound.ProtocolID(),
			Data:     []byte(h.Err.Error()),
		})
	}
}

// Stop cancels the current execution of the protocol, and alerts the other users.
func (h *MultiHandler) Stop() {
	if h.Err != nil || h.ResultObj != nil {
		h.abort(errors.New("aborted by user"), h.CurrentRound.SelfID())
	}
}

func expectsNormalMessage(r round.Session) bool {
	return r.MessageContent() != nil
}

func (h *MultiHandler) ReceivedAll() bool {
	r := h.CurrentRound
	number := r.Number()
	// check all Broadcast messages
	if _, ok := r.(round.BroadcastRound); ok {
		if h.Broadcast[number] == nil {
			// fmt.Println("Not a broadcast round; ReceivedAll() = true")
			return true
		}
		for _, id := range r.PartyIDs() {
			msg := h.Broadcast[number][id]
			if msg == nil {
				// fmt.Println("Message from", id, "is missing, ReceivedAll() = false")
				return false
			}
		}

		// create hash of all message for this round
		if h.BroadcastHashes[number] == nil {
			hashState := r.Hash()
			for _, id := range r.PartyIDs() {
				msg := h.Broadcast[number][id]
				_ = hashState.WriteAny(&hash.BytesWithDomain{
					TheDomain: "Message",
					Bytes:     msg.Hash(),
				})
			}
			h.BroadcastHashes[number] = hashState.Sum()
		}
	}

	// check all normal messages
	if expectsNormalMessage(r) {
		if h.Messages[number] == nil {
			fmt.Println("List of messages is empty; ReceivedAll() = true")
			return true
		}
		for _, id := range r.OtherPartyIDs() {
			if h.Messages[number][id] == nil {
				fmt.Println("Message from", id, "is missing; ReceivedAll() = false")
				return false
			}
		}
	}
	return true
}

func (h *MultiHandler) duplicate(msg *Message) bool {
	if msg.RoundNumber == 0 {
		return false
	}
	var q map[party.ID]*Message
	if msg.Broadcast {
		q = h.Broadcast[msg.RoundNumber]
	} else {
		q = h.Messages[msg.RoundNumber]
	}
	// technically, we already received the nil message since it is not expected :)
	if q == nil {
		return true
	}
	return q[msg.From] != nil
}

func (h *MultiHandler) store(msg *Message) {
	if msg == nil {
		return
	}
	if msg.Broadcast {
		h.Broadcast[msg.RoundNumber][msg.From] = msg
		return
	} else {
		h.Messages[msg.RoundNumber][msg.From] = msg
		return
	}
}

// getRoundMessage attempts to unmarshal a raw Message for round `r` in a round.Message.
// If an error is returned, we should abort.
func getRoundMessage(msg *Message, r round.Session) (round.Message, error) {
	var content round.Content

	// there are two possible content messages
	if msg.Broadcast {
		b, ok := r.(round.BroadcastRound)
		if !ok {
			return round.Message{}, errors.New("got Broadcast message when none was expected")
		}
		content = b.BroadcastContent()
	} else {
		content = r.MessageContent()
	}

	// unmarshal message
	if err := cbor.Unmarshal(msg.Data, content); err != nil {
		return round.Message{}, fmt.Errorf("failed to unmarshal: %w", err)
	}
	//fmt.Printf("getRoundMessage() was passed this msg.Data: %+v\n", msg.Data)
	//fmt.Printf("getRoundMessage() returned this content: %+v\n", content)
	roundMsg := round.Message{
		From:      msg.From,
		To:        msg.To,
		Content:   content,
		Broadcast: msg.Broadcast,
	}
	return roundMsg, nil
}

// checkBroadcastHash is run after ReceivedAll() and checks whether all provided verification hashes are correct.
func (h *MultiHandler) checkBroadcastHash() bool {
	number := h.CurrentRound.Number()
	// check BroadcastVerification
	previousHash := h.BroadcastHashes[number-1]
	if previousHash == nil {
		return true
	}

	for _, msg := range h.Messages[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			fmt.Println("BroadcastHash is incorrect")
			return false
		}
	}
	for _, msg := range h.Broadcast[number] {
		if msg != nil && !bytes.Equal(previousHash, msg.BroadcastVerification) {
			fmt.Println("BroadcastHash is incorrect")
			return false
		}
	}
	return true
}

func newQueue(senders []party.ID, rounds round.Number) map[round.Number]map[party.ID]*Message {
	n := len(senders)
	q := make(map[round.Number]map[party.ID]*Message, rounds)
	for i := round.Number(2); i <= rounds; i++ {
		q[i] = make(map[party.ID]*Message, n)
		for _, id := range senders {
			q[i][id] = nil
		}
	}
	return q
}

func (h *MultiHandler) String() string {
	return fmt.Sprintf("party: %s, protocol: %s", h.CurrentRound.SelfID(), h.CurrentRound.ProtocolID())
}

func (h *MultiHandler) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"CurrentRound":    h.CurrentRound,
		"Rounds":          h.Rounds,
		"Err":             h.Err,
		"ResultObj":       h.ResultObj,
		"Messages":        h.Messages,
		"Broadcast":       h.Broadcast,
		"BroadcastHashes": h.BroadcastHashes,
		"Out":             h.Out,
	})
}
