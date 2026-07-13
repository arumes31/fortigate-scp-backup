package web

import (
	"sync"
	"time"
)

// loginLimiter is a simple in-memory brute-force guard keyed by client/username.
// After max consecutive failures a key is blocked for the lockout window.
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
	max      int
	lockout  time.Duration
}

type loginAttempt struct {
	count    int
	blocked  time.Time
	lastSeen time.Time
}

func newLoginLimiter(max int, lockout time.Duration) *loginLimiter {
	if max < 1 {
		max = 5
	}
	if lockout <= 0 {
		lockout = 15 * time.Minute
	}
	l := &loginLimiter{attempts: make(map[string]*loginAttempt), max: max, lockout: lockout}
	go l.gc()
	return l
}

// allowed reports whether the key may attempt a login now.
func (l *loginLimiter) allowed(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[key]
	if a == nil {
		return true
	}
	return a.blocked.IsZero() || time.Now().After(a.blocked)
}

// fail records a failed attempt, blocking the key once max is reached.
func (l *loginLimiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[key]
	if a == nil {
		a = &loginAttempt{}
		l.attempts[key] = a
	}
	if !a.blocked.IsZero() && time.Now().After(a.blocked) {
		a.count = 0
		a.blocked = time.Time{}
	}
	a.count++
	a.lastSeen = time.Now()
	if a.count >= l.max {
		a.blocked = time.Now().Add(l.lockout)
	}
}

// reset clears a key after a successful login.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

func (l *loginLimiter) gc() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		l.mu.Lock()
		for k, a := range l.attempts {
			if time.Since(a.lastSeen) > l.lockout+time.Hour {
				delete(l.attempts, k)
			}
		}
		l.mu.Unlock()
	}
}
