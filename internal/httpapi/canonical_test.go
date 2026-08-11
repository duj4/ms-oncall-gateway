package httpapi

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

type unsupportedCanonicalEvent struct {
	content string
}

func (unsupportedCanonicalEvent) Kind() EventType { return EventTypeTest }

func TestCanonicalEventGoldenVectors(t *testing.T) {
	tests := []struct {
		name      string
		event     Event
		bytes     string
		digestHex string
	}{
		{
			name:      "test",
			event:     TestEvent{AppName: "MS OnCall"},
			bytes:     `{"AppName":"MS OnCall","Type":"Test"}`,
			digestHex: "f2af9dcf05005b12331273216cda1a0696f0381460c570f39a5165d9f97056bf",
		},
		{
			name:      "verification",
			event:     VerificationEvent{AppName: "MS OnCall", Code: "123456"},
			bytes:     `{"AppName":"MS OnCall","Type":"Verification","Code":"123456"}`,
			digestHex: "7907d2d37813189a76c537ea382dce2b5daaefc51819da5c4844ecc67a2c83d5",
		},
		{
			name: "alert",
			event: AlertEvent{
				AppName:     "MS OnCall",
				AlertID:     42,
				Summary:     "CPU <high> & rising",
				Details:     "line 1\n\"quoted\" \\ path 😀",
				ServiceID:   "11111111-2222-4333-8444-555555555555",
				ServiceName: "Fixture Service",
				Meta: map[string]string{
					"zeta":  "值😀",
					"alpha": "<tag>&",
				},
			},
			bytes:     `{"AppName":"MS OnCall","Type":"Alert","AlertID":42,"Summary":"CPU \u003chigh\u003e \u0026 rising","Details":"line 1\n\"quoted\" \\ path 😀","ServiceID":"11111111-2222-4333-8444-555555555555","ServiceName":"Fixture Service","Meta":{"alpha":"\u003ctag\u003e\u0026","zeta":"值😀"}}`,
			digestHex: "8ba9865e0a355f0a96fc004f8290896ad8ee48a72009bef1378c5e8348e94b3a",
		},
		{
			name: "alert_status",
			event: AlertStatusEvent{
				AppName:    "MS OnCall",
				AlertID:    42,
				LogEntry:   "本地化 \"closed\"\nline",
				AlertState: AlertStateClosed,
			},
			bytes:     `{"AppName":"MS OnCall","Type":"AlertStatus","AlertID":42,"LogEntry":"本地化 \"closed\"\nline","AlertState":"Closed"}`,
			digestHex: "f65f8d6d9dfb893c7a662b9246866e30204a6981efb52bba61f5a44e76c7d45e",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for iteration := 0; iteration < 3; iteration++ {
				canonical, err := CanonicalizeEvent(test.event)
				if err != nil {
					t.Fatalf("canonicalize event: %v", err)
				}
				if canonical.FormatVersion() != CanonicalEventFormatVersion {
					t.Errorf("format version = %d, want %d", canonical.FormatVersion(), CanonicalEventFormatVersion)
				}
				if got := string(canonical.Bytes()); got != test.bytes {
					t.Errorf("canonical bytes = %q, want %q", got, test.bytes)
				}
				digest := canonical.Digest()
				if got := hex.EncodeToString(digest[:]); got != test.digestHex {
					t.Errorf("digest = %s, want %s", got, test.digestHex)
				}
			}
		})
	}
}

func TestCanonicalAlertMetaOrderingAndEmptyObject(t *testing.T) {
	base := AlertEvent{
		AppName:     "MS OnCall",
		AlertID:     7,
		Summary:     "summary",
		Details:     "details",
		ServiceID:   "11111111-2222-4333-8444-555555555555",
		ServiceName: "Fixture Service",
	}
	first := base
	first.Meta = map[string]string{"z": "last", "a": "first", "m": "middle"}
	second := base
	second.Meta = map[string]string{"m": "middle", "z": "last", "a": "first"}

	firstCanonical, err := CanonicalizeEvent(first)
	if err != nil {
		t.Fatalf("canonicalize first event: %v", err)
	}
	secondCanonical, err := CanonicalizeEvent(second)
	if err != nil {
		t.Fatalf("canonicalize second event: %v", err)
	}
	if !bytes.Equal(firstCanonical.Bytes(), secondCanonical.Bytes()) || firstCanonical.Digest() != secondCanonical.Digest() {
		t.Fatal("map insertion order changed canonical result")
	}
	if !strings.HasSuffix(string(firstCanonical.Bytes()), `"Meta":{"a":"first","m":"middle","z":"last"}}`) {
		t.Errorf("Meta keys are not in ASCII order: %s", firstCanonical.Bytes())
	}

	empty := base
	empty.Meta = map[string]string{}
	emptyCanonical, err := CanonicalizeEvent(empty)
	if err != nil {
		t.Fatalf("canonicalize empty Meta: %v", err)
	}
	if !strings.HasSuffix(string(emptyCanonical.Bytes()), `"Meta":{}}`) {
		t.Errorf("empty Meta encoding = %s", emptyCanonical.Bytes())
	}
}

func TestCanonicalUnicodeAndEscaping(t *testing.T) {
	literal, err := decodeEvent([]byte(`{"AppName":"MS OnCall","Type":"Alert","AlertID":7,"Summary":"😀","Details":"é","ServiceID":"11111111-2222-4333-8444-555555555555","ServiceName":"Fixture Service","Meta":{"emoji":"😀"}}`))
	if err != nil {
		t.Fatalf("decode literal Unicode: %v", err)
	}
	escaped, err := decodeEvent([]byte(`{"AppName":"MS OnCall","Type":"Alert","AlertID":7,"Summary":"\uD83D\uDE00","Details":"\u00e9","ServiceID":"11111111-2222-4333-8444-555555555555","ServiceName":"Fixture Service","Meta":{"emoji":"\uD83D\uDE00"}}`))
	if err != nil {
		t.Fatalf("decode escaped Unicode: %v", err)
	}
	literalCanonical, err := CanonicalizeEvent(literal)
	if err != nil {
		t.Fatalf("canonicalize literal Unicode: %v", err)
	}
	escapedCanonical, err := CanonicalizeEvent(escaped)
	if err != nil {
		t.Fatalf("canonicalize escaped Unicode: %v", err)
	}
	if !bytes.Equal(literalCanonical.Bytes(), escapedCanonical.Bytes()) || literalCanonical.Digest() != escapedCanonical.Digest() {
		t.Fatal("equivalent decoded Unicode produced different canonical output")
	}

	nfc := AlertStatusEvent{AppName: "MS OnCall", AlertID: 7, LogEntry: "é", AlertState: AlertStateAcknowledged}
	nfd := AlertStatusEvent{AppName: "MS OnCall", AlertID: 7, LogEntry: "e\u0301", AlertState: AlertStateAcknowledged}
	nfcCanonical, err := CanonicalizeEvent(nfc)
	if err != nil {
		t.Fatalf("canonicalize NFC event: %v", err)
	}
	nfdCanonical, err := CanonicalizeEvent(nfd)
	if err != nil {
		t.Fatalf("canonicalize NFD event: %v", err)
	}
	if bytes.Equal(nfcCanonical.Bytes(), nfdCanonical.Bytes()) || nfcCanonical.Digest() == nfdCanonical.Digest() {
		t.Fatal("canonicalization silently normalized distinct Unicode forms")
	}

	htmlEvent := AlertStatusEvent{
		AppName:    "MS OnCall",
		AlertID:    7,
		LogEntry:   "<script>&\u2028line\n\"quoted\"\\path",
		AlertState: AlertStateClosed,
	}
	htmlCanonical, err := CanonicalizeEvent(htmlEvent)
	if err != nil {
		t.Fatalf("canonicalize escaped event: %v", err)
	}
	wantFragment := `"LogEntry":"\u003cscript\u003e\u0026\u2028line\n\"quoted\"\\path"`
	if !strings.Contains(string(htmlCanonical.Bytes()), wantFragment) {
		t.Errorf("escaping is not fixed: %s", htmlCanonical.Bytes())
	}
}

func TestCanonicalEventRejectsInvalidInputsWithoutDisclosure(t *testing.T) {
	secret := "opaque-event-content-must-not-appear"
	tests := []struct {
		name  string
		event Event
	}{
		{name: "nil", event: nil},
		{name: "typed_nil", event: (*AlertEvent)(nil)},
		{name: "unsupported", event: unsupportedCanonicalEvent{content: secret}},
		{name: "nil_meta", event: AlertEvent{Summary: secret, Meta: nil}},
		{name: "non_ASCII_Meta_key", event: AlertEvent{Meta: map[string]string{"密钥": secret}}},
		{name: "invalid_UTF8", event: AlertStatusEvent{LogEntry: string([]byte{0xff}), AlertState: AlertStateClosed}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := CanonicalizeEvent(test.event)
			if !errors.Is(err, ErrCanonicalEvent) {
				t.Fatalf("error = %v, want ErrCanonicalEvent", err)
			}
			if err != ErrCanonicalEvent {
				t.Errorf("error must be the fixed sentinel, got %T", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Error("canonicalization error disclosed event content")
			}
		})
	}
}

func TestCanonicalEventDefensiveCopies(t *testing.T) {
	meta := map[string]string{"key": "original"}
	event := &AlertEvent{
		AppName:     "MS OnCall",
		AlertID:     7,
		Summary:     "summary",
		Details:     "details",
		ServiceID:   "11111111-2222-4333-8444-555555555555",
		ServiceName: "Fixture Service",
		Meta:        meta,
	}
	canonical, err := CanonicalizeEvent(event)
	if err != nil {
		t.Fatalf("canonicalize event pointer: %v", err)
	}
	originalBytes := canonical.Bytes()
	originalDigest := canonical.Digest()

	meta["key"] = "changed"
	meta["new"] = "value"
	if !bytes.Equal(canonical.Bytes(), originalBytes) || canonical.Digest() != originalDigest {
		t.Fatal("mutating input Meta changed canonical result")
	}

	exposed := canonical.Bytes()
	exposed[0] = '['
	exposed = append(exposed, 'x')
	if !bytes.Equal(canonical.Bytes(), originalBytes) || canonical.Digest() != originalDigest {
		t.Fatal("mutating getter result changed canonical state")
	}
}

func TestCanonicalEventConcurrentReadIsStable(t *testing.T) {
	event := AlertEvent{
		AppName:     "MS OnCall",
		AlertID:     7,
		Summary:     "summary",
		Details:     "details",
		ServiceID:   "11111111-2222-4333-8444-555555555555",
		ServiceName: "Fixture Service",
		Meta:        map[string]string{"z": "last", "a": "first"},
	}
	want, err := CanonicalizeEvent(event)
	if err != nil {
		t.Fatalf("canonicalize expected event: %v", err)
	}

	var waitGroup sync.WaitGroup
	errorsFound := make(chan struct{}, 32)
	for index := 0; index < cap(errorsFound); index++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			got, err := CanonicalizeEvent(event)
			if err != nil || !bytes.Equal(got.Bytes(), want.Bytes()) || got.Digest() != want.Digest() {
				errorsFound <- struct{}{}
			}
		}()
	}
	waitGroup.Wait()
	close(errorsFound)
	if len(errorsFound) != 0 {
		t.Fatalf("concurrent canonicalization failures = %d", len(errorsFound))
	}
}
