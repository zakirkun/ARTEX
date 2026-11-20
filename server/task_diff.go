package server

import (
	"log"
	"net/http"
	"strconv"
)

// taskDiff reports what changed between two runs of the same target.
//
//	GET /api/tasks/{id}/diff?base={id}
//
// The task in the path is the head ("now"); the base query parameter is the
// earlier run. The direction is explicit in the response, so a caller can never
// mistake which side is which.
//
// The response carries the four buckets plus the coverage-completeness verdict of
// each run. When the head run did not cover its scope, ResolvedTrustworthy is
// false and ResolvedNote explains why: a scan that stopped early looks identical
// to one that retested everything and found nothing, and only the caller can
// decide how to present that difference.
func (s *Server) taskDiff(w http.ResponseWriter, r *http.Request) {
	head, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}

	baseParam := r.URL.Query().Get("base")
	if baseParam == "" {
		writeErr(w, 400, "base task id required")
		return
	}
	base, ok := s.m.Task(baseParam)
	if !ok {
		writeErr(w, 404, "base task not found")
		return
	}

	// No exploration-equality requirement: a "run" is a task, and repeated runs of
	// one target are separate tasks with separate explorations. Findings are
	// matched by fingerprint, and assets are globally unique, so two tasks are
	// directly comparable. Comparing genuinely unrelated targets is the caller's
	// decision to make; the diff reports what it sees rather than refusing.

	headID, err := strconv.ParseInt(head.ID, 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid task id")
		return
	}
	baseID, err := strconv.ParseInt(base.ID, 10, 64)
	if err != nil {
		writeErr(w, 400, "invalid base task id")
		return
	}
	if headID == baseID {
		writeErr(w, 400, "base and head are the same task")
		return
	}

	pg := s.m.PG()
	if pg == nil {
		writeErr(w, 503, "database not available")
		return
	}

	diff, err := pg.DiffFindings(baseID, headID)
	if err != nil {
		log.Printf("[diff] task %d vs %d: %v", headID, baseID, err)
		writeErr(w, 500, "diff query failed")
		return
	}
	writeJSON(w, 200, diff)
}
