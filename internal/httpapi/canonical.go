package httpapi

import (
	"crypto/sha256"
	"errors"
	"sort"
	"strconv"
	"unicode/utf8"
)

const CanonicalEventFormatVersion int64 = 1

var ErrCanonicalEvent = errors.New("canonical event invalid")

// CanonicalEvent is an immutable canonical representation of a validated
// webhook event. Its bytes and digest contain event data and must not be logged.
type CanonicalEvent struct {
	formatVersion int64
	data          []byte
	digest        [sha256.Size]byte
}

func (event CanonicalEvent) FormatVersion() int64 {
	return event.formatVersion
}

func (event CanonicalEvent) Bytes() []byte {
	return append([]byte(nil), event.data...)
}

func (event CanonicalEvent) Digest() [sha256.Size]byte {
	return event.digest
}

// CanonicalizeEvent produces Canonical Event Format V1. The event type is
// derived exclusively from the known concrete Go type.
func CanonicalizeEvent(event Event) (CanonicalEvent, error) {
	var (
		data []byte
		err  error
	)

	switch value := event.(type) {
	case TestEvent:
		data, err = canonicalizeTest(value)
	case *TestEvent:
		if value == nil {
			return CanonicalEvent{}, ErrCanonicalEvent
		}
		data, err = canonicalizeTest(*value)
	case VerificationEvent:
		data, err = canonicalizeVerification(value)
	case *VerificationEvent:
		if value == nil {
			return CanonicalEvent{}, ErrCanonicalEvent
		}
		data, err = canonicalizeVerification(*value)
	case AlertEvent:
		data, err = canonicalizeAlert(value)
	case *AlertEvent:
		if value == nil {
			return CanonicalEvent{}, ErrCanonicalEvent
		}
		data, err = canonicalizeAlert(*value)
	case AlertStatusEvent:
		data, err = canonicalizeAlertStatus(value)
	case *AlertStatusEvent:
		if value == nil {
			return CanonicalEvent{}, ErrCanonicalEvent
		}
		data, err = canonicalizeAlertStatus(*value)
	default:
		return CanonicalEvent{}, ErrCanonicalEvent
	}
	if err != nil {
		return CanonicalEvent{}, ErrCanonicalEvent
	}

	return CanonicalEvent{
		formatVersion: CanonicalEventFormatVersion,
		data:          data,
		digest:        sha256.Sum256(data),
	}, nil
}

func canonicalizeTest(event TestEvent) ([]byte, error) {
	data := []byte(`{"AppName":`)
	data, err := appendCanonicalString(data, event.AppName)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"Type":"Test"}`...)
	return data, nil
}

func canonicalizeVerification(event VerificationEvent) ([]byte, error) {
	data := []byte(`{"AppName":`)
	data, err := appendCanonicalString(data, event.AppName)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"Type":"Verification","Code":`...)
	data, err = appendCanonicalString(data, event.Code)
	if err != nil {
		return nil, err
	}
	data = append(data, '}')
	return data, nil
}

func canonicalizeAlert(event AlertEvent) ([]byte, error) {
	if event.Meta == nil {
		return nil, ErrCanonicalEvent
	}

	data := []byte(`{"AppName":`)
	data, err := appendCanonicalString(data, event.AppName)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"Type":"Alert","AlertID":`...)
	data = strconv.AppendInt(data, event.AlertID, 10)
	data = append(data, `,"Summary":`...)
	data, err = appendCanonicalString(data, event.Summary)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"Details":`...)
	data, err = appendCanonicalString(data, event.Details)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"ServiceID":`...)
	data, err = appendCanonicalString(data, event.ServiceID)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"ServiceName":`...)
	data, err = appendCanonicalString(data, event.ServiceName)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"Meta":{`...)

	keys := make([]string, 0, len(event.Meta))
	for key, value := range event.Meta {
		if !printableASCII(key) || !utf8.ValidString(value) {
			return nil, ErrCanonicalEvent
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for index, key := range keys {
		if index > 0 {
			data = append(data, ',')
		}
		data, err = appendCanonicalString(data, key)
		if err != nil {
			return nil, err
		}
		data = append(data, ':')
		data, err = appendCanonicalString(data, event.Meta[key])
		if err != nil {
			return nil, err
		}
	}
	data = append(data, '}', '}')
	return data, nil
}

func canonicalizeAlertStatus(event AlertStatusEvent) ([]byte, error) {
	data := []byte(`{"AppName":`)
	data, err := appendCanonicalString(data, event.AppName)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"Type":"AlertStatus","AlertID":`...)
	data = strconv.AppendInt(data, event.AlertID, 10)
	data = append(data, `,"LogEntry":`...)
	data, err = appendCanonicalString(data, event.LogEntry)
	if err != nil {
		return nil, err
	}
	data = append(data, `,"AlertState":`...)
	data, err = appendCanonicalString(data, string(event.AlertState))
	if err != nil {
		return nil, err
	}
	data = append(data, '}')
	return data, nil
}

func appendCanonicalString(data []byte, value string) ([]byte, error) {
	if !utf8.ValidString(value) {
		return nil, ErrCanonicalEvent
	}

	const hex = "0123456789abcdef"
	data = append(data, '"')
	start := 0
	for index := 0; index < len(value); {
		character := value[index]
		if character >= utf8.RuneSelf {
			runeValue, size := utf8.DecodeRuneInString(value[index:])
			if runeValue != '\u2028' && runeValue != '\u2029' {
				index += size
				continue
			}
			data = append(data, value[start:index]...)
			data = append(data, '\\', 'u', '2', '0', '2', hex[byte(runeValue)&0xf])
			index += size
			start = index
			continue
		}

		if character >= 0x20 && character != '"' && character != '\\' && character != '<' && character != '>' && character != '&' {
			index++
			continue
		}

		data = append(data, value[start:index]...)
		switch character {
		case '"', '\\':
			data = append(data, '\\', character)
		case '\b':
			data = append(data, '\\', 'b')
		case '\f':
			data = append(data, '\\', 'f')
		case '\n':
			data = append(data, '\\', 'n')
		case '\r':
			data = append(data, '\\', 'r')
		case '\t':
			data = append(data, '\\', 't')
		default:
			data = append(data, '\\', 'u', '0', '0', hex[character>>4], hex[character&0xf])
		}
		index++
		start = index
	}
	data = append(data, value[start:]...)
	return append(data, '"'), nil
}
