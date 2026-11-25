package web

import (
	"sync"
	"time"
)

// loginLimiter is a simple in-memory brute-force guard keyed by client/username.
// After max consecutive failures a key is blocked for the lockout window.
type loginLimiter struct {
	mu        sync.Mutex
	attempts  map[string]*loginAttempt
	max       int
	lockout   time.Duration
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
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
	l := &loginLimiter{
		attempts: make(map[string]*loginAttempt), max: max, lockout: lockout,
		done: make(chan struct{}),
	}
	l.wg.Add(1)
	go l.gc()
	return l
}

// acquire atomically checks the key and counts one attempt against it before
// the credentials are verified, blocking the key once max is reached. A
// successful attempt hands its count back with release or reset.
func (l *loginLimiter) acquire(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	a := l.attempts[key]
	if a == nil {
		a = &loginAttempt{}
		l.attempts[key] = a
	}
	if !a.blocked.IsZero() {
		if now.Before(a.blocked) {
			return false
		}
		a.count = 0
		a.blocked = time.Time{}
	}
	// Failures older than the lockout window decay, so buckets that are never
	// reset on success (the per-IP aggregate) do not accumulate forever.
	if !a.lastSeen.IsZero() && now.Sub(a.lastSeen) > l.lockout {
		a.count = 0
	}
	a.count++
	a.lastSeen = now
	if a.count >= l.max {
		a.blocked = now.Add(l.lockout)
	}
	return true
}

// release returns one attempt counted by acquire that turned out to succeed.
func (l *loginLimiter) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.attempts[key]
	if a == nil {
		return
	}
	if a.count > 0 {
		a.count--
	}
	if a.count == 0 {
		delete(l.attempts, key)
		return
	}
	if a.count < l.max {
		a.blocked = time.Time{}
	}
}

// reset clears a key after a successful login.
func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	delete(l.attempts, key)
	l.mu.Unlock()
}

func (l *loginLimiter) gc() {
	defer l.wg.Done()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-l.done:
			return
		case <-t.C:
			l.mu.Lock()
			for k, a := range l.attempts {
				if time.Since(a.lastSeen) > l.lockout+time.Hour {
					delete(l.attempts, k)
				}
			}
			l.mu.Unlock()
		}
	}
}

// Close stops the background garbage collector. It is safe to call repeatedly.
func (l *loginLimiter) Close() {
	l.closeOnce.Do(func() { close(l.done) })
	l.wg.Wait()
}
