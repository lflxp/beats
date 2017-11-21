package sflow

import (
	"fmt"
)

// All sflow protocol errors are defined here.

type sflowError struct {
	message string
}

func (e *sflowError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return e.message
}

func (e *sflowError) responseError() string {
	return "Response: " + e.Error()
}

// Common
var (
	duplicateQueryMsg = &sflowError{message: "Another query with the same SFLOW ID from this client " +
		"was received so this query was closed without receiving a response"}
	noResponse       = &sflowError{message: "No response to this query was received"}
)

// SFLOW
var (
	udpPacketTooLarge  = &sflowError{message: fmt.Sprintf("Non-SFLOW packet has size greater than %d", maxSFLOWPacketSize)}
)
