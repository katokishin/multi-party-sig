package roundtools

import (
	"encoding/json"
	"fmt"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/keygen"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp/sign"
)

func RoundMessageFromJSON(from party.ID, to party.ID, broadcast bool, j []byte) (round.Message, error) {
	var tmp map[string]json.RawMessage
	if err := json.Unmarshal([]byte(j), &tmp); err != nil {
		return round.Message{}, fmt.Errorf("failed to unmarshal: %w", err)
	}

	var KeyB2 keygen.Broadcast2
	var KeyB3 keygen.Broadcast3
	var KeyB4 keygen.Broadcast4
	var KeyM4 keygen.Message4
	var KeyB5 keygen.Broadcast5
	var SigB2 sign.Broadcast2
	var SigM2 sign.Message2
	var SigB3 sign.Broadcast3
	var SigM3 sign.Message3
	var SigB4 sign.Broadcast4
	var SigM4 sign.Message4
	var SigB5 sign.Broadcast5

	if tmp["Commitment"] != nil {
		// KeyB2
		if e := json.Unmarshal(j, &KeyB2); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   KeyB2,
		}, nil
	}

	if tmp["Decommitment"] != nil {
		// KeyB3
		if e := json.Unmarshal(j, &KeyB3); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   KeyB3,
		}, nil
	}

	if tmp["Mod"] != nil {
		// KeyB4
		if e := json.Unmarshal(j, &KeyB4); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   KeyB4,
		}, nil
	}

	if tmp["Share"] != nil {
		// KeyM4
		if e := json.Unmarshal(j, &KeyM4); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   KeyM4,
		}, nil
	}

	if tmp["SchnorrResponse"] != nil {
		// KeyB5
		if e := json.Unmarshal(j, &KeyB5); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   KeyB5,
		}, nil
	}

	if tmp["K"] != nil {
		// SigB2
		if e := json.Unmarshal(j, &SigB2); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   SigB2,
		}, nil
	}

	if tmp["ProofEnc"] != nil {
		// SigM2
		if e := json.Unmarshal(j, &SigM2); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   SigM2,
		}, nil
	}

	if tmp["BigGammaShare"] != nil {
		// SigB3
		if e := json.Unmarshal(j, &SigB3); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   SigB3,
		}, nil
	}

	if tmp["DeltaD"] != nil {
		// SigM3
		if e := json.Unmarshal(j, &SigM3); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   SigM3,
		}, nil
	}

	if tmp["DeltaShare"] != nil {
		// SigB4
		if e := json.Unmarshal(j, &SigB4); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   SigB4,
		}, nil
	}

	if tmp["ProofLog"] != nil {
		// SigM4
		if e := json.Unmarshal(j, &SigM4); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   SigM4,
		}, nil
	}

	if tmp["SigmaShare"] != nil {
		// SigB5
		if e := json.Unmarshal(j, &SigB5); e != nil {
			return round.Message{}, e
		}
		return round.Message{
			From:      from,
			To:        to,
			Broadcast: broadcast,
			Content:   SigB5,
		}, nil
	}

	// Else, something is wrong
	fmt.Println("Unable to determine message type")
	return round.Message{}, fmt.Errorf("Roundtools.go unable to determine message type")
}
