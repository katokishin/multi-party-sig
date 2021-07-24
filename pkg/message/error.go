package message

// Error indicates that the message does not pass validation.
type Error string

const (
	ErrMessageDuplicate          Error = "message was already handled"
	ErrMessageUnknownSender      Error = "unknown sender"
	ErrMessageNilContent         Error = "content is nil"
	ErrMessageWrongSSID          Error = "SSID mismatch"
	ErrMessageWrongProtocolID    Error = "wrong protocol ID"
	ErrMessageFromSelf           Error = "message is from Self"
	ErrMessageNotSorted          Error = "msg.To field is not sorted"
	ErrMessageContainsDuplicates Error = "msg.To field contains duplicates"
	ErrMessageWrongDestination   Error = "message is not intended for selfID"
	ErrMessageInvalidRoundNumber Error = "round number is invalid for this protocol"
	ErrMessageFirstRound         Error = "no message expected in first round"
	ErrMessageLastRound          Error = "no message expected in output round"
	ErrMessageInconsistentRound  Error = "given RoundNumber is inconsistent with content"
)

// Error implements error.
func (err Error) Error() string {
	return "message: " + string(err)
}
