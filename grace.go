package mcpoauth

import "time"

// The refresh-rotation grace cache.
//
// A client that never received a rotation's response — a dropped connection, a
// retry, two parallel requests — presents the token it still holds. On the wire
// that is byte-identical to a thief replaying a spent token, so without a grace
// window the client's own retry destroys its session. The window answers the
// duplicate with the very same successor the rotation issued.
//
// That needs one piece of state: predecessor -> successor. v1 kept it in the
// database, AES-GCM sealed onto the consumed predecessor row so a dump of the
// table stayed worthless. v2 keeps it in process memory instead, and the reason
// is a difference in what losing it costs:
//
//   - The REUSE ledger (RefreshToken.ConsumedAt) must be durable. Losing it is
//     a security bypass — that was a round-2 HIGH, when detection lived in a
//     4096-entry in-process map a thief could flush by rotating in a loop. It
//     stays in the Store, retained until the family expires, and nothing here
//     touches it.
//   - The GRACE cache does not. Losing an entry fails SAFE: the duplicate is no
//     longer answerable, so it is either reported as a concurrent rotation (and
//     retried) or, once the window closes, classified as reuse and the family is
//     revoked. The operator signs in once. An attacker gains nothing by evicting
//     an entry, and flooding the cache only degrades honest retries.
//
// The residual risk, stated plainly: on a process restart, or in a
// multi-instance deployment where the duplicate lands on another node, a
// duplicate refresh submitted inside RefreshGracePeriod is not answerable and
// costs one re-login. No data is exposed and no token is issued to anyone. In
// exchange the library sheds ~90 lines of AES-GCM, a column, and the single
// most error-prone method of the Store contract (an INSERT path in
// LinkRefreshSuccessor materialised a refresh-token row that was never issued,
// with a caller-influenced family_id).

// maxGraceEntries caps the cache. At the default 30s window this is far more
// concurrent rotations than any real deployment sees; the cap exists so an
// attacker holding many refresh tokens cannot grow the map without bound.
const maxGraceEntries = 1024

// graceEntry is one rotation, remembered for the length of the grace window.
// The successor is held in the clear because it never leaves the process: it is
// only ever handed back over the same TLS connection that would have received
// it from the rotation itself.
type graceEntry struct {
	successorRaw string
	expiresAt    time.Time
}

// rememberSuccessor records that predecessorHash was rotated into successorRaw.
// It is called only after the successor has been persisted AND the predecessor
// re-read confirmed the family was not revoked mid-flight, so a remembered
// successor is always one that was really issued.
func (p *Provider) rememberSuccessor(predecessorHash, successorRaw string, now time.Time) {
	if p.cfg.RefreshGracePeriod <= 0 || predecessorHash == "" {
		return
	}
	p.graceMu.Lock()
	defer p.graceMu.Unlock()
	if p.grace == nil {
		p.grace = make(map[string]graceEntry, 16)
	}
	if len(p.grace) >= maxGraceEntries {
		p.sweepGraceLocked(now)
	}
	for len(p.grace) >= maxGraceEntries {
		// Still full of live entries. Dropping one costs at most a re-login for
		// whoever owned it, so any victim will do.
		for h := range p.grace {
			delete(p.grace, h)
			break
		}
	}
	p.grace[predecessorHash] = graceEntry{
		successorRaw: successorRaw,
		expiresAt:    now.Add(p.cfg.RefreshGracePeriod),
	}
}

// recallSuccessor returns the successor predecessorHash was rotated into.
//
// ok=false means "this process cannot answer the duplicate" — either the
// rotation is still in flight, or the entry was never here (restart, another
// instance) or has been swept. The caller must treat all of those the same way,
// and must never read ok=false as evidence of anything: it is an absence, not a
// signal.
func (p *Provider) recallSuccessor(predecessorHash string, now time.Time) (string, bool) {
	p.graceMu.Lock()
	defer p.graceMu.Unlock()
	e, ok := p.grace[predecessorHash]
	if !ok {
		return "", false
	}
	if now.After(e.expiresAt) {
		delete(p.grace, predecessorHash)
		return "", false
	}
	return e.successorRaw, true
}

// sweepGraceLocked drops expired entries. Callers hold graceMu.
func (p *Provider) sweepGraceLocked(now time.Time) {
	for h, e := range p.grace {
		if now.After(e.expiresAt) {
			delete(p.grace, h)
		}
	}
}
