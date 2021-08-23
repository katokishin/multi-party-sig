package broadcast

import (
	"bytes"
	"errors"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
)

type Round2 struct {
	round.Round
	EchoHash []byte
}

type Message2 struct {
	round.Content

	// EchoHash is a hash of all previous hashes of broadcast data.
	// May be empty when no data was broadcast in the previous round.
	EchoHash []byte
}

func (b *Round2) VerifyMessage(msg round.Message) error {
	body, ok := msg.Content.(*Message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	if !bytes.Equal(body.EchoHash, b.EchoHash) {
		return errors.New("echo broadcast failed")
	}
	return b.Round.VerifyMessage(round.Message{
		From:    msg.From,
		To:      msg.To,
		Content: body.Content,
	})
}

func (b *Round2) StoreMessage(msg round.Message) error {
	body, ok := msg.Content.(*Message2)
	if !ok {
		return round.ErrInvalidContent
	}
	return b.Round.StoreMessage(round.Message{
		From:    msg.From,
		To:      msg.To,
		Content: body.Content,
	})
}

func (b *Round2) MessageContent() round.Content {
	return &Message2{
		Content: b.Round.MessageContent(),
	}
}

func (b *Message2) Init(group curve.Curve) {
	b.Content.Init(group)
}
