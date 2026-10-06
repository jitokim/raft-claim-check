package app

import (
	"github.com/jitokim/raft-claim-check/cli/internal/spool"
)

type flushStats struct {
	stored, rejected, expired, pending int
	stopped                            bool
}

func (a *app) cmdFlush(args []string) int {
	fset, svc := a.newFlags("flush")
	pos, code, ok := a.parse(fset, args, false)
	if !ok {
		return code
	}
	if len(pos) > 0 {
		return a.usageErr("usage: claim-check flush")
	}
	p, code := a.openProfile(*svc)
	if p == nil {
		return code
	}
	st, err := a.flush(p)
	if err != nil {
		a.logf("flush: %v", err)
		return ExitFailure
	}
	a.logf("flush: %d stored, %d rejected, %d expired, %d still pending", st.stored, st.rejected, st.expired, st.pending)
	if st.pending > 0 {
		return ExitTempFail
	}
	return ExitOK
}

// flush deletes rejected files older than 30 days, moves pending receipts
// signed more than 7 days ago (and unreadable files) to rejected/, then
// submits the rest oldest first, stopping at the first 401 or 429 (or when
// the Raft CLI is missing or not logged in).
func (a *app) flush(p *profile) (flushStats, error) {
	var st flushStats
	now := a.Now()
	if _, err := spool.PurgeRejected(p.paths, now); err != nil {
		return st, err
	}
	entries, bad, err := spool.List(p.paths)
	if err != nil {
		return st, err
	}
	for _, path := range bad {
		if err := spool.Quarantine(p.paths, path, now); err != nil {
			return st, err
		}
		a.logf("%s is not a readable receipt; moved to spool/rejected/", path)
		st.rejected++
	}
	var live []spool.Entry
	for _, e := range entries {
		if now.Sub(e.SignedAt) <= spool.MaxPendingAge {
			live = append(live, e)
			continue
		}
		rej := spool.Rejection{Error: "receipt_too_old", Hint: "Signed more than 7 days ago, so the app would refuse it."}
		if err := spool.Reject(p.paths, e, rej, now); err != nil {
			return st, err
		}
		a.logf("%s expired: signed more than 7 days ago; moved to spool/rejected/", e.ID)
		st.expired++
	}
	for i, e := range live {
		res := a.submit(p, e)
		a.logf("%s %s", e.ID, res.summary)
		switch res.outcome {
		case outStored:
			st.stored++
		case outRejected:
			st.rejected++
		default:
			st.pending++
		}
		if res.stop {
			st.stopped = true
			st.pending += len(live) - i - 1
			break
		}
	}
	return st, nil
}
