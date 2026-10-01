// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Who the identity provider has taken back, and since when.
//
// A certificate has a revocation list -- the KRL, the CRL -- but most of
// what a provider hands out does not: an access token fileshare verifies on
// its own, an OpenPubkey certificate signed by the person's own key. They are
// valid until they expire, whatever happened to the person since.
//
// What closes that is the OpenID Shared Signals Framework (SSF 1.0) carrying a
// Continuous Access Evaluation Profile event (CAEP 1.0): session-revoked, "the
// session identified by the subject has been revoked". go-authn/bridge sends
// one when a person or an IdP is disabled; fileshare polls for them (RFC 8936,
// the SSF default) and keeps, per person, the moment everything issued to them
// stopped counting. From then on, every federated credential ISSUED BEFORE
// that moment is refused, whatever carried it -- a token over WebDAV, a
// provider or OpenPubkey certificate over SFTP, a client certificate over NFS
// -- and the sessions they opened stop being served, through the same gates
// as the KRL's. A credential issued AFTER is the person's new one: re-enabled,
// they are not locked out for as long as the entry is kept.
//
// ⛔ It fails closed, like the lists in revocation.go: while the transmitter
// has not been heard from for max_age, federated credentials are refused,
// because "no revocation arrived" and "none could" look the same.

// revocationStore is the revocations received, persisted, and how recently
// the transmitter answered.
type revocationStore struct {
	mu      sync.RWMutex
	path    string
	retain  time.Duration
	maxAge  time.Duration
	now     func() time.Time
	entries map[string]time.Time // "acct:alice@univ.fr" or "iss_sub:<iss> <sub>" -> revoked at
	stream  string               // the SSF stream id, kept across restarts
	heard   time.Time            // last successful poll
}

type storedRevocations struct {
	Version int                  `json:"version"`
	Stream  string               `json:"stream,omitempty"`
	Entries map[string]time.Time `json:"entries"`
}

func openRevocationStore(path string, retain, maxAge time.Duration) (*revocationStore, error) {
	s := &revocationStore{path: path, retain: retain, maxAge: maxAge, now: time.Now, entries: map[string]time.Time{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var st storedRevocations
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if st.Version != 1 {
		return nil, fmt.Errorf("%s is version %d, and this fileshare reads version 1", path, st.Version)
	}
	s.stream = st.Stream
	for k, v := range st.Entries {
		s.entries[k] = v
	}
	return s, nil
}

// subjectKeys are the ways one person is named: by account (the name the
// shares and the certificates use) and by the provider's issuer and subject.
func accountKey(name string) string    { return "acct:" + name }
func issSubKey(iss, sub string) string { return "iss_sub:" + iss + " " + sub }

// scopeKey is a whole institution revoked: every name ending @scope. It is
// what an IdP disabled at the provider becomes -- the people behind it the
// provider no longer remembers included.
func scopeKey(scope string) string { return "scope:" + strings.ToLower(scope) }

// domainOf is the scope part of a federated name, user@domain.
func domainOf(name string) string {
	if i := strings.LastIndexByte(name, '@'); i >= 0 {
		return name[i+1:]
	}
	return ""
}

// revoke records that everything issued to these subjects before at is void,
// and writes it down before returning: the poller acknowledges the event only
// then, so a revocation that was acknowledged is one that survives a restart.
func (s *revocationStore) revoke(keys []string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		if at.After(s.entries[k]) {
			s.entries[k] = at
		}
	}
	s.prune()
	return s.saveLocked()
}

// prune forgets revocations older than retain: every credential they could
// void has expired by then.
func (s *revocationStore) prune() {
	cutoff := s.now().Add(-s.retain)
	for k, v := range s.entries {
		if v.Before(cutoff) {
			delete(s.entries, k)
		}
	}
}

func (s *revocationStore) saveLocked() error {
	return writeJSONAtomically(s.path, storedRevocations{Version: 1, Stream: s.stream, Entries: s.entries})
}

func (s *revocationStore) setStream(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stream = id
	return s.saveLocked()
}

func (s *revocationStore) streamID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stream
}

// heardFrom records a successful poll.
func (s *revocationStore) heardFrom() {
	s.mu.Lock()
	s.heard = s.now()
	s.mu.Unlock()
}

// check says whether a credential issued at issued, to somebody named name
// (and, when known, iss/sub), still counts. An issue time that is not known
// is not "long ago": it is refused once there is any revocation for them.
func (s *revocationStore) check(name, iss, sub string, issued time.Time) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.heard.IsZero() || s.now().Sub(s.heard) > s.maxAge {
		return fmt.Errorf("%w: the shared signals transmitter has not been heard from within %s",
			errRevocationUnknown, s.maxAge)
	}
	keys := []string{accountKey(name)}
	if iss != "" && sub != "" {
		keys = append(keys, issSubKey(iss, sub))
	}
	if d := domainOf(name); d != "" {
		keys = append(keys, scopeKey(d))
	}
	for _, k := range keys {
		at, ok := s.entries[k]
		if !ok {
			continue
		}
		if issued.IsZero() || !issued.After(at) {
			return fmt.Errorf("%s's sessions were revoked by the provider at %s, and this was issued before",
				name, at.UTC().Format(time.RFC3339))
		}
	}
	return nil
}

// age is how long since the transmitter was last heard from, for the metrics;
// -1 when never.
func (s *revocationStore) age() float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.heard.IsZero() {
		return -1
	}
	return s.now().Sub(s.heard).Seconds()
}

// count is how many subjects are revoked now.
func (s *revocationStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// writeJSONAtomically replaces a file whole or not at all, as writeState
// does for the admin API's state.
func writeJSONAtomically(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomically(path, append(data, '\n'))
}

// caepEvent is one session-revoked event, as a SET's events claim carries it.
const eventSessionRevoked = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

// setClaims is the part of a Security Event Token (RFC 8417) this receiver
// reads.
type setClaims struct {
	Iss    string                     `json:"iss"`
	Aud    json.RawMessage            `json:"aud"`
	Iat    json.Number                `json:"iat"`
	Jti    string                     `json:"jti"`
	Sub    string                     `json:"sub"`
	Exp    json.RawMessage            `json:"exp"`
	Events map[string]json.RawMessage `json:"events"`
	SubID  json.RawMessage            `json:"sub_id"`
}

// subjectID is an RFC 9493 subject identifier, the formats this receiver can
// map onto a person: account, iss_sub, email, and aliases of them.
type subjectID struct {
	Format      string      `json:"format"`
	URI         string      `json:"uri"`
	Iss         string      `json:"iss"`
	Sub         string      `json:"sub"`
	Email       string      `json:"email"`
	Identifiers []subjectID `json:"identifiers"`
	// A CAEP complex subject: the person under "user", the institution
	// under "tenant" (then named by its scopes, in the event).
	User   *subjectID `json:"user"`
	Tenant *subjectID `json:"tenant"`
}

// keys are the store keys a subject names; an unmappable subject names none.
func (id subjectID) keys() []string {
	switch id.Format {
	case "account":
		if name, ok := strings.CutPrefix(id.URI, "acct:"); ok && name != "" {
			return []string{accountKey(name)}
		}
	case "iss_sub":
		if id.Iss != "" && id.Sub != "" {
			return []string{issSubKey(id.Iss, id.Sub)}
		}
	case "email":
		// The name the shares use is the provider's username, which for a
		// federation is user@domain; an email subject is matched as that.
		if id.Email != "" {
			return []string{accountKey(id.Email)}
		}
	case "aliases":
		var out []string
		for _, a := range id.Identifiers {
			out = append(out, a.keys()...)
		}
		return out
	}
	if id.User != nil {
		return id.User.keys()
	}
	return nil
}

// parseRevocation reads a verified SET's claims, checks it is addressed here
// by the transmitter this server trusts, and returns the subjects it revokes
// and since when -- or nothing, for an event this receiver does not act on.
func parseRevocation(payload []byte, issuer, audience string) (keys []string, at time.Time, err error) {
	var c setClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, time.Time{}, err
	}
	switch {
	case c.Iss != issuer:
		return nil, time.Time{}, fmt.Errorf("a SET from %q, and the transmitter is %q", c.Iss, issuer)
	case !audienceHas(c.Aud, audience):
		return nil, time.Time{}, fmt.Errorf("a SET not addressed to %q", audience)
	case len(c.Exp) > 0, c.Sub != "":
		// SSF 1.0: a SET carries neither; one that does is not an SSF SET.
		return nil, time.Time{}, errors.New("a SET with exp or sub, which SSF forbids")
	}
	raw, ok := c.Events[eventSessionRevoked]
	if !ok {
		return nil, time.Time{}, nil
	}
	var ev struct {
		EventTimestamp json.Number     `json:"event_timestamp"`
		SubID          json.RawMessage `json:"sub_id"`
		// Scopes are the domains of an IdP revoked whole: go-authn/bridge
		// puts its shibmd scopes here beside a tenant subject.
		Scopes []string `json:"scopes"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		return nil, time.Time{}, err
	}
	subRaw := c.SubID
	if len(subRaw) == 0 {
		subRaw = ev.SubID // CAEP drafts put it in the event
	}
	var id subjectID
	if err := json.Unmarshal(subRaw, &id); err != nil {
		return nil, time.Time{}, fmt.Errorf("the subject: %w", err)
	}
	keys = id.keys()
	if id.Tenant != nil && id.User == nil {
		// An institution: named by its scopes, not by who is in it.
		keys = nil
		for _, sc := range ev.Scopes {
			if sc = strings.TrimSpace(sc); sc != "" && !strings.ContainsAny(sc, "@ ") {
				keys = append(keys, scopeKey(sc))
			}
		}
		if len(keys) == 0 {
			return nil, time.Time{}, fmt.Errorf("an institution revoked with no scope to name its people by")
		}
		if at, err = eventTime(c.Iat, ev.EventTimestamp); err != nil {
			return nil, time.Time{}, err
		}
		return keys, at, nil
	}
	if len(keys) == 0 {
		return nil, time.Time{}, fmt.Errorf("a session-revoked event for a subject this server cannot name (%s)", subRaw)
	}
	if at, err = eventTime(c.Iat, ev.EventTimestamp); err != nil {
		return nil, time.Time{}, err
	}
	if !slices.ContainsFunc(keys, func(k string) bool { return strings.HasPrefix(k, "acct:") }) {
		// Only iss_sub: kept, and matched against tokens, which carry sub;
		// certificates carry only the name, and would not be matched. Said,
		// rather than silently half-applied.
		err = errIssSubOnly
	}
	return keys, at, err
}

// eventTime is when a revocation took effect: event_timestamp, else the SET's
// iat -- NumericDates, which RFC 7519 allows fractional. A SET with neither
// is refused: RFC 8417 requires iat, and a zero time would be pruned the
// moment it was kept, revoking nothing (found by the security review).
func eventTime(iat, event json.Number) (time.Time, error) {
	for _, n := range []json.Number{event, iat} {
		if n == "" {
			continue
		}
		f, err := n.Float64()
		if err != nil || f <= 0 {
			return time.Time{}, fmt.Errorf("a SET with an unusable time %q", n)
		}
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(frac*1e9)), nil
	}
	return time.Time{}, fmt.Errorf("a SET with no iat and no event_timestamp")
}

var errIssSubOnly = errors.New("the event names the person by iss_sub only: certificates, which carry only the name, cannot be matched to it")

func audienceHas(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	return json.Unmarshal(raw, &many) == nil && slices.Contains(many, want)
}
