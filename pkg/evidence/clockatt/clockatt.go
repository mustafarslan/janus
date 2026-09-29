// Package clockatt produces clock attestation records: evidence about the state
// of the clock that timestamped the evidence.
//
// MiFID II RTS 25 requires firms to synchronise business clocks to UTC within a
// stated tolerance and to be able to demonstrate it. The EU AI Act's
// reconstructability duty has the same shape: a timestamp nobody can vouch for
// does not establish when something happened. Janus already orders events with a
// hybrid logical clock, which is immune to wall-clock movement — but ordering is
// not the same as time, and a regulator asks about time.
//
// So the wall-clock reading in each envelope points at an attestation: a record
// of what the clock was disciplined against, how far off it was, and how
// confident the source was, at a moment close to the reading. The attestation is
// itself an evidence event, chained like everything else, so the claim about the
// clock is as tamper-evident as the claim about the work.
//
// The honest failure mode matters here. When no time source can be reached the
// attestation records that fact rather than being omitted: an absent attestation
// is indistinguishable from one nobody bothered to take, while an attestation
// saying "unsynchronised" is a finding an auditor can act on.
package clockatt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"
)

// Attestation is a statement about the clock at a point in time.
type Attestation struct {
	// Source names what the clock was checked against.
	Source string `json:"source"`
	// Synchronised is false when the check failed or the source disclaimed
	// synchronisation. Everything below is meaningless when it is false.
	Synchronised bool `json:"synchronised"`
	// OffsetNanos is the local clock minus the reference, so a positive value
	// means the local clock is ahead.
	OffsetNanos int64 `json:"offset_nanos"`
	// RoundTripNanos bounds the uncertainty in OffsetNanos: the true offset is
	// within roughly half of it.
	RoundTripNanos int64 `json:"round_trip_nanos"`
	// Stratum is the NTP distance from a reference clock, where 1 is a clock
	// attached to a reference and 0 means unknown.
	Stratum uint8 `json:"stratum,omitempty"`
	// ReferenceID identifies the upstream source, as NTP reports it.
	ReferenceID string `json:"reference_id,omitempty"`
	// ToleranceNanos is the synchronisation bound the deployment claimed to be
	// holding the clock within at the moment this attestation was taken. Zero
	// means none was recorded, which is what every attestation written before
	// this field existed says, and is not the same as a declared zero.
	//
	// It is here rather than only in the monitor's configuration because a
	// bound nobody can read out of the log is a claim an auditor has to take on
	// trust. RTS 25 Art. 4 asks a firm to *demonstrate* traceability within its
	// stated tolerance; without the stated tolerance in the record, the strongest
	// thing a reader can check is the article's own one-second ceiling, and a
	// deployment that declared 100 ms reads as satisfied without that bound ever
	// having been tested.
	ToleranceNanos int64 `json:"tolerance_nanos,omitempty"`
	// TakenAt is the local time the attestation was made.
	TakenAt time.Time `json:"taken_at"`
	// Err records why an attestation failed, when it did.
	Err string `json:"error,omitempty"`
}

// Offset returns the measured offset as a duration.
func (a Attestation) Offset() time.Duration { return time.Duration(a.OffsetNanos) }

// DeclaredTolerance returns the bound the deployment claimed, and whether one
// was recorded at all. A caller that treated "not recorded" as zero would grade
// every attestation written before the field existed as breaching a bound of
// nothing.
func (a Attestation) DeclaredTolerance() (time.Duration, bool) {
	if a.ToleranceNanos <= 0 {
		return 0, false
	}
	return time.Duration(a.ToleranceNanos), true
}

// Uncertainty returns half the round trip, the usual bound on how wrong the
// offset measurement itself could be.
func (a Attestation) Uncertainty() time.Duration { return time.Duration(a.RoundTripNanos / 2) }

// WithinTolerance reports whether the clock is good enough for a stated
// tolerance, counting the measurement uncertainty against itself.
//
// The uncertainty is added rather than ignored because a claim of compliance
// should not depend on a measurement being luckier than it can prove to be.
// RTS 25 requires 1 ms for high-frequency trading and 1 s for most other
// activity; the caller supplies the figure that applies to it.
func (a Attestation) WithinTolerance(tolerance time.Duration) bool {
	if !a.Synchronised {
		return false
	}
	off := a.Offset()
	if off < 0 {
		off = -off
	}
	return off+a.Uncertainty() <= tolerance
}

// Payload renders the attestation for the evidence log.
func (a Attestation) Payload() ([]byte, error) { return json.Marshal(a) }

// Summary renders a one-line human description.
func (a Attestation) Summary() string {
	if !a.Synchronised {
		return fmt.Sprintf("clock UNSYNCHRONISED against %s: %s", a.Source, a.Err)
	}
	line := fmt.Sprintf("clock offset %s (±%s) against %s, stratum %d",
		a.Offset().Round(time.Microsecond), a.Uncertainty().Round(time.Microsecond), a.Source, a.Stratum)
	if tol, ok := a.DeclaredTolerance(); ok {
		line += fmt.Sprintf(", declared tolerance %s", tol)
	}
	return line
}

// Source measures the local clock against a reference.
type Source interface {
	Attest(ctx context.Context) Attestation
	Name() string
}

// NTPSource queries an NTP server over SNTP (RFC 4330).
type NTPSource struct {
	// Server is host:port; port defaults to 123.
	Server string
	// Timeout bounds one query.
	Timeout time.Duration
}

// Name implements Source.
func (s NTPSource) Name() string { return "ntp:" + s.Server }

// ntpEpochOffset converts between the NTP epoch (1900) and the Unix epoch.
const ntpEpochOffset = 2208988800

// Attest queries the server and reports the offset. A failure returns an
// unsynchronised attestation rather than an error, because the fact that the
// clock could not be checked is itself what needs recording.
func (s NTPSource) Attest(ctx context.Context) Attestation {
	att := Attestation{Source: s.Name(), TakenAt: time.Now().UTC()}

	server := s.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "123")
	}
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var d net.Dialer
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.DialContext(dialCtx, "udp", server)
	if err != nil {
		att.Err = "dial: " + err.Error()
		return att
	}
	defer func() { _ = conn.Close() }()

	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		att.Err = "set deadline: " + err.Error()
		return att
	}

	// SNTP client request: leap 0, version 4, mode 3.
	req := make([]byte, 48)
	req[0] = 0x1B

	t1 := time.Now()
	if _, err := conn.Write(req); err != nil {
		att.Err = "write: " + err.Error()
		return att
	}
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		att.Err = "read: " + err.Error()
		return att
	}
	t4 := time.Now()

	leap := resp[0] >> 6
	att.Stratum = resp[1]
	att.ReferenceID = refID(resp[12:16], att.Stratum)

	// Leap indicator 3 means the server itself is not synchronised, and
	// stratum 0 is a kiss-of-death packet. Either way its time is not evidence.
	if leap == 3 {
		att.Err = "server reports itself unsynchronised"
		return att
	}
	if att.Stratum == 0 || att.Stratum > 15 {
		att.Err = fmt.Sprintf("server reports unusable stratum %d", att.Stratum)
		return att
	}

	t2 := ntpTime(resp[32:40]) // server receive
	t3 := ntpTime(resp[40:48]) // server transmit
	if t2.IsZero() || t3.IsZero() {
		att.Err = "server returned a zero timestamp"
		return att
	}

	// The standard NTP estimates: offset averages out the path, round trip
	// bounds how wrong that average can be.
	offset := (t2.Sub(t1) + t3.Sub(t4)) / 2
	roundTrip := t4.Sub(t1) - t3.Sub(t2)
	if roundTrip < 0 {
		roundTrip = 0
	}

	att.Synchronised = true
	// Reported from the local clock's point of view: positive means local is
	// ahead of the reference, which is the direction an operator expects.
	att.OffsetNanos = -offset.Nanoseconds()
	att.RoundTripNanos = roundTrip.Nanoseconds()
	return att
}

// refID renders the NTP reference identifier, which is four ASCII characters
// for stratum 1 and an address otherwise.
func refID(b []byte, stratum uint8) string {
	if stratum == 1 {
		out := make([]byte, 0, 4)
		for _, c := range b {
			if c >= 0x20 && c < 0x7f {
				out = append(out, c)
			}
		}
		return string(out)
	}
	return net.IP(b).String()
}

// ntpTime converts an NTP 64-bit timestamp to a time.Time.
func ntpTime(b []byte) time.Time {
	secs := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	frac := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
	if secs == 0 && frac == 0 {
		return time.Time{}
	}
	nsec := (int64(frac) * 1e9) >> 32
	return time.Unix(int64(secs)-ntpEpochOffset, nsec)
}

// UnavailableSource is what a deployment with no reachable time source uses.
//
// It exists so that "we could not check the clock" is a recorded fact rather
// than a missing record. An air-gapped install genuinely cannot reach NTP, and
// the honest artefact is an attestation saying so.
type UnavailableSource struct {
	Reason string
}

// Name implements Source.
func (s UnavailableSource) Name() string { return "unavailable" }

// Attest implements Source.
func (s UnavailableSource) Attest(context.Context) Attestation {
	reason := s.Reason
	if reason == "" {
		reason = "no time source is configured for this deployment"
	}
	return Attestation{Source: s.Name(), TakenAt: time.Now().UTC(), Err: reason}
}

// ErrNoSources means a monitor was built with nothing to query.
var ErrNoSources = errors.New("clockatt: at least one source is required")
