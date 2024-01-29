package round

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/hash"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
)

// Helper implements Session without Round, and can therefore be embedded in the first round of a protocol
// in order to satisfy the Session interface.
type Helper struct {
	Info Info

	// Pool allows us to parallelize certain operations
	Pool *pool.Pool

	// PartyIDsSlice is a sorted slice of Info.PartyIDs.
	PartyIDsSlice party.IDSlice
	// OtherPartyIDsSlice is the same as PartyIDsSlice without selfID
	OtherPartyIDsSlice party.IDSlice

	// Ssid the unique identifier for this protocol execution
	Ssid []byte

	HashData *hash.Hash

	mtx sync.Mutex
}

// NewSession creates a new *Helper which can be embedded in the first Round,
// so that the full struct implements Session.
// `sessionID` is an optional byte slice that can be provided by the user.
// When used, it should be unique for each execution of the protocol.
// It could be a simple counter which is incremented after execution,  or a common random string.
// `auxInfo` is a variable list of objects which should be included in the session's hash state.
func NewSession(Info Info, sessionID []byte, pl *pool.Pool, auxInfo ...hash.WriterToWithDomain) (*Helper, error) {
	PartyIDsSlice := party.NewIDSlice(Info.PartyIDs)
	if !PartyIDsSlice.Valid() {
		return nil, errors.New("session: PartyIDsSlice invalid")
	}

	// verify our ID is present
	if !PartyIDsSlice.Contains(Info.SelfID) {
		return nil, errors.New("session: selfID not included in PartyIDsSlice")
	}

	// make sure the threshold is correct
	if Info.Threshold < 0 || Info.Threshold > math.MaxUint32 {
		return nil, fmt.Errorf("session: threshold %d is invalid", Info.Threshold)
	}

	// the number of users satisfies the threshold
	if n := len(PartyIDsSlice); n <= 0 || Info.Threshold > n-1 {
		return nil, fmt.Errorf("session: threshold %d is invalid for number of parties %d", Info.Threshold, n)
	}

	var err error
	h := hash.New()
	if sessionID != nil {
		if err = h.WriteAny(&hash.BytesWithDomain{
			TheDomain: "Session ID",
			Bytes:     sessionID,
		}); err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
	}

	if err = h.WriteAny(&hash.BytesWithDomain{
		TheDomain: "Protocol ID",
		Bytes:     []byte(Info.ProtocolID),
	}); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	if Info.Group != nil {
		if err = h.WriteAny(&hash.BytesWithDomain{
			TheDomain: "Group Name",
			Bytes:     []byte(Info.Group.Name()),
		}); err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
	}

	if err = h.WriteAny(PartyIDsSlice); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	if err = h.WriteAny(types.ThresholdWrapper(Info.Threshold)); err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}

	for _, a := range auxInfo {
		if a == nil {
			continue
		}
		if err = h.WriteAny(a); err != nil {
			return nil, fmt.Errorf("session: %w", err)
		}
	}

	return &Helper{
		Info:               Info,
		Pool:               pl,
		PartyIDsSlice:      PartyIDsSlice,
		OtherPartyIDsSlice: PartyIDsSlice.Remove(Info.SelfID),
		Ssid:               h.Clone().Sum(),
		HashData:           h,
	}, nil
}

// HashForID returns a clone of the hash.Hash for this session, initialized with the given id.
func (h *Helper) HashForID(id party.ID) *hash.Hash {
	h.mtx.Lock()
	defer h.mtx.Unlock()

	cloned := h.HashData.Clone()
	if id != "" {
		_ = cloned.WriteAny(id)
	}

	return cloned
}

// UpdateHashState writes additional data to the hash state.
func (h *Helper) UpdateHashState(value hash.WriterToWithDomain) {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	_ = h.HashData.WriteAny(value)
}

// BroadcastMessage constructs a Message from the broadcast Content, and sets the header correctly.
// An error is returned if the message cannot be sent to the out channel.
func (h *Helper) BroadcastMessage(out []*Message, broadcastContent Content) []*Message {
	msg := &Message{
		From:      h.Info.SelfID,
		To:        "",
		Broadcast: true,
		Content:   broadcastContent,
	}
	out = append(out, msg)
	return out
}

// SendMessage is a convenience method for safely sending content to some party. If the message is
// intended for all participants (but does not require reliable broadcast), the `to` field may be empty ("").
// Returns an error if the message failed to send over out channel.
// `out` is expected to be a buffered channel with enough capacity to store all messages.
func (h *Helper) SendMessage(out []*Message, content Content, to party.ID) []*Message {
	msg := &Message{
		From:    h.Info.SelfID,
		To:      to,
		Content: content,
	}
	out = append(out, msg)
	return out
}

// Hash returns copy of the hash function of this protocol execution.
func (h *Helper) Hash() *hash.Hash {
	h.mtx.Lock()
	defer h.mtx.Unlock()
	return h.HashData.Clone()
}

// ResultRound returns a round that contains only the result of the protocol.
// This indicates to the used that the protocol is finished.
func (h *Helper) ResultRound(result interface{}) Session {
	return &Output{
		Helper: h,
		Result: result,
	}
}

// AbortRound returns a round that contains only the culprits that were able to be identified during
// a faulty execution of the protocol. The error returned by Round.Finalize() in this case should still be nil.
func (h *Helper) AbortRound(err error, culprits ...party.ID) Session {
	return &Abort{
		Helper:   h,
		Culprits: culprits,
		Err:      err,
	}
}

// ProtocolID is an identifier for this protocol.
func (h *Helper) ProtocolID() string { return h.Info.ProtocolID }

// FinalRoundNumber is the number of rounds before the output round.
func (h *Helper) FinalRoundNumber() Number { return h.Info.FinalRoundNumber }

// SSID the unique identifier for this protocol execution.
func (h *Helper) SSID() []byte { return h.Ssid }

// SelfID is this party's ID.
func (h *Helper) SelfID() party.ID { return h.Info.SelfID }

// PartyIDs is a sorted slice of participating parties in this protocol.
func (h *Helper) PartyIDs() party.IDSlice { return h.PartyIDsSlice }

// OtherPartyIDs returns a sorted list of parties that does not contain SelfID.
func (h *Helper) OtherPartyIDs() party.IDSlice { return h.OtherPartyIDsSlice }

// Threshold is the maximum number of parties that are assumed to be corrupted during the execution of this protocol.
func (h *Helper) Threshold() int { return h.Info.Threshold }

// N returns the number of participants.
func (h *Helper) N() int { return len(h.Info.PartyIDs) }

// Group returns the curve used for this protocol.
func (h *Helper) Group() curve.Curve { return h.Info.Group }

func (h *Helper) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"Info":               h.Info,
		"Pool":               h.Pool,
		"PartyIDsSlice":      h.PartyIDsSlice,
		"OtherPartyIDsSlice": h.OtherPartyIDsSlice,
		"Ssid":               h.Ssid,
		"HashData":           h.HashData,
	})
}

func (h *Helper) UnmarshalJSON(j []byte) error {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal(j, &tmp); err != nil {
		return err
	}

	var i Info
	if err := json.Unmarshal(tmp["Info"], &i); err != nil {
		return err
	}
	/*
		var p *pool.Pool
		if err := json.Unmarshal(tmp["Pool"], &p); err != nil {
			return err
		}
	*/

	var pids party.IDSlice
	if err := json.Unmarshal(tmp["PartyIDsSlice"], &pids); err != nil {
		return err
	}

	var opids party.IDSlice
	if err := json.Unmarshal(tmp["OtherPartyIDsSlice"], &opids); err != nil {
		return err
	}

	var Ssid []byte
	if err := json.Unmarshal(tmp["Ssid"], &Ssid); err != nil {
		return err
	}

	var hash *hash.Hash
	if err := json.Unmarshal(tmp["HashData"], &hash); err != nil {
		return err
	}

	h.Info = i
	h.Pool = pool.NewPool(1)
	h.PartyIDsSlice = pids
	h.OtherPartyIDsSlice = opids
	h.Ssid = Ssid
	h.HashData = hash
	return nil
}
