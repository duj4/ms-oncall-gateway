package httpapi

import (
	"context"
	"errors"
)

// EventType identifies a supported Core webhook event.
type EventType string

const (
	EventTypeTest         EventType = "Test"
	EventTypeVerification EventType = "Verification"
	EventTypeAlert        EventType = "Alert"
	EventTypeAlertStatus  EventType = "AlertStatus"
)

// AlertState is the machine-readable Core alert state carried on AlertStatus.
type AlertState string

const (
	AlertStateUnacknowledged AlertState = "Unacknowledged"
	AlertStateAcknowledged   AlertState = "Acknowledged"
	AlertStateClosed         AlertState = "Closed"
)

// Event is a validated, typed Core webhook event.
type Event interface {
	Kind() EventType
}

type TestEvent struct {
	AppName string
}

func (TestEvent) Kind() EventType { return EventTypeTest }

type VerificationEvent struct {
	AppName string
	Code    string
}

func (VerificationEvent) Kind() EventType { return EventTypeVerification }

type AlertEvent struct {
	AppName     string
	AlertID     int64
	Summary     string
	Details     string
	ServiceID   string
	ServiceName string
	Meta        map[string]string
}

func (AlertEvent) Kind() EventType { return EventTypeAlert }

type AlertStatusEvent struct {
	AppName    string
	AlertID    int64
	LogEntry   string
	AlertState AlertState
}

func (AlertStatusEvent) Kind() EventType { return EventTypeAlertStatus }

// Delivery is the validated handoff from HTTP intake to durable acceptance.
// Token and Identity remain opaque after transport validation.
type Delivery struct {
	Token    string
	Identity string
	Event    Event
}

// Acceptance describes a delivery that a sink has durably accepted.
type Acceptance struct {
	ReceiptID string
	Duplicate bool
}

// Sink accepts validated deliveries. Implementations must not return success
// until the delivery is durably recoverable.
type Sink interface {
	Enqueue(context.Context, Delivery) (Acceptance, error)
}

var ErrSinkUnavailable = errors.New("delivery sink unavailable")

// UnavailableSink is the safe runtime default until durable persistence exists.
type UnavailableSink struct{}

func (UnavailableSink) Enqueue(context.Context, Delivery) (Acceptance, error) {
	return Acceptance{}, ErrSinkUnavailable
}
