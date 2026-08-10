package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"unicode/utf8"
)

var (
	errInvalidEvent     = errors.New("invalid event")
	errUnsupportedEvent = errors.New("unsupported event type")
	uuidPattern         = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	digitsPattern       = regexp.MustCompile(`^[0-9]{6}$`)
	positiveIntPattern  = regexp.MustCompile(`^[1-9][0-9]*$`)
	serviceNamePattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 _'-]*[A-Za-z0-9_'-]$`)
)

func validCanonicalUUID(value string) bool {
	return uuidPattern.MatchString(value)
}

func decodeEvent(data []byte) (Event, error) {
	if !utf8.Valid(data) {
		return nil, errInvalidEvent
	}
	if err := validateJSONObject(data); err != nil {
		return nil, errInvalidEvent
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		return nil, errInvalidEvent
	}

	typeName, err := requiredString(fields, "Type")
	if err != nil {
		return nil, errInvalidEvent
	}

	switch EventType(typeName) {
	case EventTypeTest:
		return decodeTest(fields)
	case EventTypeVerification:
		return decodeVerification(fields)
	case EventTypeAlert:
		return decodeAlert(fields)
	case EventTypeAlertStatus:
		return decodeAlertStatus(fields)
	default:
		return nil, errUnsupportedEvent
	}
}

func decodeTest(fields map[string]json.RawMessage) (Event, error) {
	if !hasExactFields(fields, "AppName", "Type") {
		return nil, errInvalidEvent
	}
	appName, err := requiredString(fields, "AppName")
	if err != nil || !validAppName(appName) {
		return nil, errInvalidEvent
	}
	return TestEvent{AppName: appName}, nil
}

func decodeVerification(fields map[string]json.RawMessage) (Event, error) {
	if !hasExactFields(fields, "AppName", "Type", "Code") {
		return nil, errInvalidEvent
	}
	appName, err := requiredString(fields, "AppName")
	if err != nil || !validAppName(appName) {
		return nil, errInvalidEvent
	}
	code, err := requiredString(fields, "Code")
	if err != nil || !digitsPattern.MatchString(code) {
		return nil, errInvalidEvent
	}
	return VerificationEvent{AppName: appName, Code: code}, nil
}

func decodeAlert(fields map[string]json.RawMessage) (Event, error) {
	if !hasExactFields(fields, "AppName", "Type", "AlertID", "Summary", "Details", "ServiceID", "ServiceName", "Meta") {
		return nil, errInvalidEvent
	}
	appName, err := requiredString(fields, "AppName")
	if err != nil || !validAppName(appName) {
		return nil, errInvalidEvent
	}
	alertID, err := requiredPositiveInt(fields, "AlertID")
	if err != nil {
		return nil, errInvalidEvent
	}
	summary, err := requiredString(fields, "Summary")
	if err != nil || utf8.RuneCountInString(summary) > 1024 {
		return nil, errInvalidEvent
	}
	details, err := requiredString(fields, "Details")
	if err != nil || utf8.RuneCountInString(details) > 6144 {
		return nil, errInvalidEvent
	}
	serviceID, err := requiredString(fields, "ServiceID")
	if err != nil || !validCanonicalUUID(serviceID) {
		return nil, errInvalidEvent
	}
	serviceName, err := requiredString(fields, "ServiceName")
	if err != nil || !validServiceName(serviceName) {
		return nil, errInvalidEvent
	}
	meta, err := requiredMeta(fields, "Meta")
	if err != nil {
		return nil, errInvalidEvent
	}

	return AlertEvent{
		AppName:     appName,
		AlertID:     alertID,
		Summary:     summary,
		Details:     details,
		ServiceID:   serviceID,
		ServiceName: serviceName,
		Meta:        meta,
	}, nil
}

func decodeAlertStatus(fields map[string]json.RawMessage) (Event, error) {
	if !hasExactFields(fields, "AppName", "Type", "AlertID", "LogEntry", "AlertState") {
		return nil, errInvalidEvent
	}
	appName, err := requiredString(fields, "AppName")
	if err != nil || !validAppName(appName) {
		return nil, errInvalidEvent
	}
	alertID, err := requiredPositiveInt(fields, "AlertID")
	if err != nil {
		return nil, errInvalidEvent
	}
	logEntry, err := requiredString(fields, "LogEntry")
	if err != nil || logEntry == "" {
		return nil, errInvalidEvent
	}
	stateValue, err := requiredString(fields, "AlertState")
	if err != nil {
		return nil, errInvalidEvent
	}
	state := AlertState(stateValue)
	switch state {
	case AlertStateUnacknowledged, AlertStateAcknowledged, AlertStateClosed:
	default:
		return nil, errInvalidEvent
	}

	return AlertStatusEvent{
		AppName:    appName,
		AlertID:    alertID,
		LogEntry:   logEntry,
		AlertState: state,
	}, nil
}

func hasExactFields(fields map[string]json.RawMessage, names ...string) bool {
	if len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func requiredString(fields map[string]json.RawMessage, name string) (string, error) {
	raw, ok := fields[name]
	if !ok {
		return "", errInvalidEvent
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '"' {
		return "", errInvalidEvent
	}
	var value string
	if err := json.Unmarshal(trimmed, &value); err != nil {
		return "", errInvalidEvent
	}
	return value, nil
}

func requiredPositiveInt(fields map[string]json.RawMessage, name string) (int64, error) {
	raw, ok := fields[name]
	if !ok {
		return 0, errInvalidEvent
	}
	trimmed := bytes.TrimSpace(raw)
	if !positiveIntPattern.Match(trimmed) {
		return 0, errInvalidEvent
	}
	value, err := strconv.ParseInt(string(trimmed), 10, 64)
	if err != nil {
		return 0, errInvalidEvent
	}
	return value, nil
}

func requiredMeta(fields map[string]json.RawMessage, name string) (map[string]string, error) {
	raw, ok := fields[name]
	if !ok {
		return nil, errInvalidEvent
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errInvalidEvent
	}
	var meta map[string]string
	if err := json.Unmarshal(trimmed, &meta); err != nil || meta == nil {
		return nil, errInvalidEvent
	}
	var size int
	for key, value := range meta {
		if len(key) < 1 || len(key) > 255 || !printableASCII(key) {
			return nil, errInvalidEvent
		}
		size += len(key) + len(value)
		if size > 32768 {
			return nil, errInvalidEvent
		}
	}
	return meta, nil
}

func validAppName(value string) bool {
	return len(value) >= 1 && len(value) <= 32 && printableASCII(value)
}

func validServiceName(value string) bool {
	return len(value) >= 2 && len(value) <= 64 && printableASCII(value) && serviceNamePattern.MatchString(value)
}

func printableASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func validateJSONObject(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return errInvalidEvent
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return errInvalidEvent
	}
	if err := consumeObject(decoder); err != nil {
		return errInvalidEvent
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errInvalidEvent
	}
	return nil
}

func consumeObject(decoder *json.Decoder) error {
	seen := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := token.(string)
		if !ok {
			return errInvalidEvent
		}
		if _, ok := seen[name]; ok {
			return errInvalidEvent
		}
		seen[name] = struct{}{}
		if err := consumeValue(decoder); err != nil {
			return err
		}
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '}' {
		return errInvalidEvent
	}
	return nil
}

func consumeValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		return consumeObject(decoder)
	case '[':
		for decoder.More() {
			if err := consumeValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		endDelim, ok := end.(json.Delim)
		if !ok || endDelim != ']' {
			return errInvalidEvent
		}
		return nil
	default:
		return errInvalidEvent
	}
}
