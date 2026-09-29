package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/zeebo/blake3"
)

// KeyRing holds one data encryption key per data subject and can destroy them.
//
// The interface is deliberately small and deliberately one-way. There is no
// export, no escrow, and no undo: a key ring that can hand back a destroyed key
// is not a crypto-shredding mechanism, it is a filing cabinet. A KMS-backed
// implementation replaces this one without the callers changing.
type KeyRing interface {
	// EnsureKey returns the subject's key, creating it on first use. The caller
	// owns the returned slice and should zero it when done.
	EnsureKey(subject string) ([]byte, error)
	// Key returns an existing key. It returns ErrKeyDestroyed if the subject has
	// been shredded and ErrNoKey if the subject was never seen.
	Key(subject string) ([]byte, error)
	// Shred destroys a subject's key permanently and returns a receipt.
	Shred(subject, reason, approvedBy string, at time.Time) (ShredReceipt, error)
	// State reports whether a subject's key is live, shredded, or unknown.
	State(subject string) KeyState
	// Subjects lists every subject the ring knows about, live or shredded.
	Subjects() []string
}

// KeyState is the lifecycle of a subject's key.
type KeyState string

const (
	// KeyUnknown means the subject has never had a key.
	KeyUnknown KeyState = "unknown"
	// KeyLive means the key exists and content is readable.
	KeyLive KeyState = "live"
	// KeyShredded means the key was destroyed. This is terminal.
	KeyShredded KeyState = "shredded"
)

// ShredReceipt records an erasure. It is what goes into the SHRED event, and it
// names an accountable person because erasure is an irreversible act performed
// under someone's authority.
type ShredReceipt struct {
	Subject string `json:"subject"`
	// KeyFingerprint identifies the destroyed key without revealing it, so the
	// record can show that *this* key was destroyed and not some other.
	KeyFingerprint string    `json:"key_fingerprint"`
	Reason         string    `json:"reason"`
	ApprovedBy     string    `json:"approved_by"`
	ShreddedAt     time.Time `json:"shredded_at"`
	// CreatedAt is when the key first existed, which bounds what was encrypted
	// under it.
	CreatedAt time.Time `json:"created_at"`
}

// Payload renders the receipt for the evidence log.
func (r ShredReceipt) Payload() ([]byte, error) { return json.Marshal(r) }

// Errors returned by key rings.
var (
	// ErrAlreadyShredded means erasure was requested for a subject already
	// erased. It is an error rather than a no-op so that a duplicate request
	// does not silently produce a second, misleading SHRED event.
	ErrAlreadyShredded = errors.New("crypto: subject already shredded")
)

// FileKeyRing keeps subject keys on disk, each wrapped under a master key.
//
// The master key is the single thing that must be protected properly; in a
// deployment it lives in a KMS or an HSM and this file-backed ring is replaced.
// It is a complete implementation rather than a stub so that an air-gapped
// single-node install has something real to run.
type FileKeyRing struct {
	mu     sync.RWMutex
	dir    string
	master []byte
	// index caches state so a shredded subject can be reported without
	// touching the filesystem.
	index map[string]KeyState
}

// keyRecord is the on-disk form of one subject's key.
type keyRecord struct {
	Subject     string    `json:"subject"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	// Wrapped is the DEK encrypted under the master key.
	Wrapped string `json:"wrapped"`
}

// tombstone marks a shredded subject. It exists so the ring can tell "erased"
// apart from "never existed" — a distinction an auditor needs, because the first
// has a SHRED event explaining it and the second does not.
type tombstone struct {
	Subject     string    `json:"subject"`
	Fingerprint string    `json:"fingerprint"`
	ShreddedAt  time.Time `json:"shredded_at"`
	Reason      string    `json:"reason"`
	ApprovedBy  string    `json:"approved_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// NewFileKeyRing opens or creates a key ring rooted at dir.
func NewFileKeyRing(dir string, master []byte) (*FileKeyRing, error) {
	if dir == "" {
		return nil, errors.New("crypto: key ring needs a directory")
	}
	if len(master) != KeySize {
		return nil, fmt.Errorf("crypto: master key is %d bytes, want %d", len(master), KeySize)
	}
	for _, sub := range []string{"keys", "tombstones"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	r := &FileKeyRing{dir: dir, master: append([]byte(nil), master...), index: map[string]KeyState{}}
	if err := r.loadIndex(); err != nil {
		return nil, err
	}
	return r, nil
}

// GenerateMasterKey returns a fresh master key.
func GenerateMasterKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, err
	}
	return k, nil
}

// LoadOrCreateMasterKey reads a master key from path, creating one if absent.
func LoadOrCreateMasterKey(path string) ([]byte, error) {
	blob, err := os.ReadFile(path)
	if err == nil {
		k, derr := hex.DecodeString(string(trimSpace(blob)))
		if derr != nil {
			return nil, fmt.Errorf("crypto: parse master key %s: %w", path, derr)
		}
		if len(k) != KeySize {
			return nil, fmt.Errorf("crypto: master key in %s is %d bytes, want %d", path, len(k), KeySize)
		}
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	k, err := GenerateMasterKey()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(k)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

// subjectFile maps a subject to a file name without putting the subject itself
// in a path. A directory listing of a key store should not be a list of the
// people a bank holds data about.
func (r *FileKeyRing) subjectFile(subject string) string {
	sum := blake3.Sum256(append([]byte("JANUS/subject/1\x00"), subject...))
	return hex.EncodeToString(sum[:16]) + ".json"
}

func (r *FileKeyRing) keyPath(subject string) string {
	return filepath.Join(r.dir, "keys", r.subjectFile(subject))
}

func (r *FileKeyRing) tombPath(subject string) string {
	return filepath.Join(r.dir, "tombstones", r.subjectFile(subject))
}

func (r *FileKeyRing) loadIndex() error {
	for _, sub := range []struct {
		dir   string
		state KeyState
	}{{"keys", KeyLive}, {"tombstones", KeyShredded}} {
		entries, err := os.ReadDir(filepath.Join(r.dir, sub.dir))
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			blob, err := os.ReadFile(filepath.Join(r.dir, sub.dir, e.Name()))
			if err != nil {
				return err
			}
			var probe struct {
				Subject string `json:"subject"`
			}
			if err := json.Unmarshal(blob, &probe); err != nil {
				return fmt.Errorf("crypto: parse %s/%s: %w", sub.dir, e.Name(), err)
			}
			// A tombstone always wins: shredded is terminal, so if both files
			// somehow exist the subject is shredded.
			if sub.state == KeyShredded || r.index[probe.Subject] == "" {
				r.index[probe.Subject] = sub.state
			}
		}
	}
	return nil
}

// State implements KeyRing.
func (r *FileKeyRing) State(subject string) KeyState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.index[subject]; ok {
		return s
	}
	return KeyUnknown
}

// Subjects implements KeyRing.
func (r *FileKeyRing) Subjects() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.index))
	for s := range r.index {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// EnsureKey implements KeyRing.
func (r *FileKeyRing) EnsureKey(subject string) ([]byte, error) {
	if key, err := r.Key(subject); err == nil {
		return key, nil
	} else if !errors.Is(err, ErrNoKey) {
		// A shredded subject must not quietly get a fresh key: that would let
		// new records be written for someone whose data was erased, under a key
		// the erasure receipt does not cover.
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Re-check under the write lock in case another goroutine created it.
	if state := r.index[subject]; state == KeyShredded {
		return nil, fmt.Errorf("%w: %s", ErrKeyDestroyed, subject)
	}
	if _, err := os.Stat(r.keyPath(subject)); err == nil {
		return r.readKeyLocked(subject)
	}

	dek := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	wrapped, err := r.wrap(subject, dek)
	if err != nil {
		return nil, err
	}
	rec := keyRecord{
		Subject:     subject,
		Fingerprint: fingerprint(dek),
		CreatedAt:   time.Now().UTC(),
		Wrapped:     hex.EncodeToString(wrapped),
	}
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writeFileSync(r.keyPath(subject), append(blob, '\n')); err != nil {
		return nil, err
	}
	r.index[subject] = KeyLive
	return dek, nil
}

// Key implements KeyRing.
//
// The state check and the file read happen under one lock. Splitting them let a
// concurrent Shred land in between, after which the read found no file and the
// caller was told the subject was never seen — or, worse, caught the file
// mid-overwrite and was told the record was corrupt. Both answers contradict
// the distinction this package exists to preserve: a fulfilled erasure must
// never look like damage or like absence.
func (r *FileKeyRing) Key(subject string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	switch r.index[subject] {
	case KeyShredded:
		return nil, fmt.Errorf("%w: %s", ErrKeyDestroyed, subject)
	case "":
		return nil, fmt.Errorf("%w: %s", ErrNoKey, subject)
	}
	return r.readKeyLocked(subject)
}

func (r *FileKeyRing) readKeyLocked(subject string) ([]byte, error) {
	blob, err := os.ReadFile(r.keyPath(subject))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNoKey, subject)
		}
		return nil, err
	}
	var rec keyRecord
	if err := json.Unmarshal(blob, &rec); err != nil {
		return nil, fmt.Errorf("crypto: parse key record: %w", err)
	}
	wrapped, err := hex.DecodeString(rec.Wrapped)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse wrapped key: %w", err)
	}
	return r.unwrap(subject, wrapped)
}

// Shred implements KeyRing. It is irreversible by construction: the wrapped key
// is overwritten and unlinked, and a tombstone takes its place.
func (r *FileKeyRing) Shred(subject, reason, approvedBy string, at time.Time) (ShredReceipt, error) {
	if reason == "" || approvedBy == "" {
		return ShredReceipt{}, errors.New("crypto: erasure needs a reason and an accountable approver")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.index[subject] {
	case KeyShredded:
		return ShredReceipt{}, fmt.Errorf("%w: %s", ErrAlreadyShredded, subject)
	case "":
		return ShredReceipt{}, fmt.Errorf("%w: %s", ErrNoKey, subject)
	}

	blob, err := os.ReadFile(r.keyPath(subject))
	if err != nil {
		return ShredReceipt{}, err
	}
	var rec keyRecord
	if err := json.Unmarshal(blob, &rec); err != nil {
		return ShredReceipt{}, fmt.Errorf("crypto: parse key record: %w", err)
	}

	tomb := tombstone{
		Subject:     subject,
		Fingerprint: rec.Fingerprint,
		ShreddedAt:  at.UTC(),
		Reason:      reason,
		ApprovedBy:  approvedBy,
		CreatedAt:   rec.CreatedAt,
	}
	tombBlob, err := json.MarshalIndent(tomb, "", "  ")
	if err != nil {
		return ShredReceipt{}, err
	}
	// The tombstone lands before the key is destroyed. If the process dies
	// between the two, the subject reads as shredded and the key is unreachable
	// through this ring — erring towards erasure rather than towards a key that
	// outlives its own erasure record.
	if err := writeFileSync(r.tombPath(subject), append(tombBlob, '\n')); err != nil {
		return ShredReceipt{}, err
	}
	r.index[subject] = KeyShredded

	if err := destroyFile(r.keyPath(subject)); err != nil {
		return ShredReceipt{}, fmt.Errorf("crypto: destroy key for %s: %w", subject, err)
	}

	return ShredReceipt{
		Subject:        subject,
		KeyFingerprint: rec.Fingerprint,
		Reason:         reason,
		ApprovedBy:     approvedBy,
		ShreddedAt:     at.UTC(),
		CreatedAt:      rec.CreatedAt,
	}, nil
}

// wrap encrypts a DEK under the master key, binding it to its subject so a
// wrapped key cannot be relabelled onto a different person.
func (r *FileKeyRing) wrap(subject string, dek []byte) ([]byte, error) {
	aead, err := newAEAD(r.master)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aad := append([]byte("JANUS/kek/1\x00"), subject...)
	return aead.Seal(nonce, nonce, dek, aad), nil
}

func (r *FileKeyRing) unwrap(subject string, wrapped []byte) ([]byte, error) {
	if len(wrapped) < nonceSize+gcmTagSize {
		return nil, fmt.Errorf("%w: wrapped key too short", ErrCiphertextMalformed)
	}
	aead, err := newAEAD(r.master)
	if err != nil {
		return nil, err
	}
	aad := append([]byte("JANUS/kek/1\x00"), subject...)
	dek, err := aead.Open(nil, wrapped[:nonceSize], wrapped[nonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap key for %s: wrong master key or damaged record", subject)
	}
	return dek, nil
}

// fingerprint identifies a key without revealing it.
func fingerprint(key []byte) string {
	sum := blake3.Sum256(append([]byte("JANUS/keyfp/1\x00"), key...))
	return "blake3:" + hex.EncodeToString(sum[:8])
}

// writeFileSync writes a file and flushes it, so a crash cannot leave a key
// record or a tombstone half-written.
func writeFileSync(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// destroyFile overwrites a file before unlinking it.
//
// On a copy-on-write or log-structured filesystem, and on any SSD with wear
// levelling, overwriting in place does not reliably erase the old blocks — the
// real guarantee comes from the master key being held in a KMS or HSM that can
// destroy it, and from full-disk encryption underneath. This is defence in
// depth against the easy case of someone reading the raw device, not the
// mechanism the erasure claim rests on.
func destroyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	junk := make([]byte, info.Size())
	if _, err := io.ReadFull(rand.Reader, junk); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(junk); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}
