package log

import (
	"io"
	"log"
	"os"
)

// New creates a new logger.
func New(out *io.Writer, prefix string, flag int) *log.Logger {
	var w io.Writer = os.Stdout
	if out != nil {
		w = *out
	}
	return log.New(w, prefix, flag)
}

func DefaultLogger() *log.Logger {
	return log.New(os.Stdout, "[proxy] ", log.LstdFlags)
}
