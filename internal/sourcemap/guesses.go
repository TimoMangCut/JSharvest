package sourcemap

import (
	"net/url"
	"strings"
	"sync"
)

// GuessMisses is how many <script>.map guesses an origin may miss, with
// none found, before no more are made there: a build that ships no maps
// answers each one with a 404 or its SPA's shell, one request a script for
// nothing (a real Vite app: 431 guesses, 0 maps).
const GuessMisses = 10

// Guesses keeps, per origin, the guessed maps that were found and missed,
// and says whether one more guess is worth a request. Safe for concurrent
// use; a guess in flight is not counted until Done, so a few more than
// GuessMisses may go out at once.
type Guesses struct {
	mu sync.Mutex
	by map[string]*tally
}

type tally struct{ hit, miss int }

func origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// Allow reports whether a guess at mapURL may be made.
func (g *Guesses) Allow(mapURL string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.by[origin(mapURL)]
	if t != nil && t.hit == 0 && t.miss >= GuessMisses {
		return false
	}
	return true
}

// Done records a guess's outcome: found (a source map v3) or not.
func (g *Guesses) Done(mapURL string, found bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.by == nil {
		g.by = map[string]*tally{}
	}
	o := origin(mapURL)
	t := g.by[o]
	if t == nil {
		t = &tally{}
		g.by[o] = t
	}
	if found {
		t.hit++
	} else {
		t.miss++
	}
}
