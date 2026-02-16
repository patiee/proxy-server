package errors

// BlockedRequestError indicates a request was blocked by a filter.
type BlockedRequestError struct {
	Message string
}

func (e *BlockedRequestError) Error() string {
	return e.Message
}

// NewBlockedRequestError creates a new BlockedRequestError.
func NewBlockedRequestError(msg string) *BlockedRequestError {
	return &BlockedRequestError{Message: msg}
}
