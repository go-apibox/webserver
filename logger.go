package main

import (
	"github.com/go-apibox/logging"
)

var logger *logging.Logger

func init() {
	logger = logging.NewLogger("webserver")
}
