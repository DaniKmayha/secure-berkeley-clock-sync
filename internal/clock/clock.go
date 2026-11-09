// Package clock implements the simulated, drifting hardware clock that every
// node owns. The Berkeley algorithm is evaluated on these clocks (synthetic
// data, as stated in the thesis proposal).
//
// Model
//
//	local(t) = anchorLocal + (t - anchorReal) * rate
//
// where t is the real (host) time and rate = 1 + drift + slew.
//   - drift  : a constant skew in parts-per-million (every quartz clock has one)
//   - slew   : a temporary extra rate used to apply an adjustment gradually.
//
// Berkeley tells each node to "speed up or slow down" rather than jump,
// because jumping backwards breaks monotonicity (timestamps would repeat).
// Slewing keeps the clock monotonic as long as |slew| < 1 + drift.
package clock

import (
	"fmt"
	"sync"
	"time"
)

// Clock is safe for concurrent use.
type Clock struct {
	mu sync.Mutex

	// Piecewise-linear anchor.
	anchorReal  time.Time
	anchorLocal float64 // microseconds

	baseRate float64 // 1 + drift
	slewRate float64 // extra rate while slewing (0 when idle)
	slewEnd  time.Time

	now func() time.Time // injectable real-time source (tests)
}

// New creates a clock that starts offsetUs microseconds away from real time
// and drifts by driftPPM parts per million.
func New(offsetUs int64, driftPPM float64) *Clock {
	return NewWithSource(offsetUs, driftPPM, time.Now)
}

// NewWithSource is New with an injectable real-time source.
func NewWithSource(offsetUs int64, driftPPM float64, now func() time.Time) *Clock {
	t := now()
	return &Clock{
		anchorReal:  t,
		anchorLocal: float64(t.UnixMicro() + offsetUs),
		baseRate:    1 + driftPPM/1e6,
		now:         now,
	}
}

// reanchor moves the anchor to real time t (caller holds mu).
func (c *Clock) reanchor(t time.Time) {
	c.anchorLocal = c.localAt(t)
	c.anchorReal = t
}

// localAt evaluates the clock at real time t (caller holds mu). It handles
// the end of an active slew period so the result is exact even if nobody
// called Now() exactly at slewEnd.
func (c *Clock) localAt(t time.Time) float64 {
	rate := c.baseRate + c.slewRate
	if c.slewRate != 0 && t.After(c.slewEnd) {
		// Part of the interval at the slewed rate, the rest at the base rate.
		slewed := float64(c.slewEnd.Sub(c.anchorReal).Microseconds())
		rest := float64(t.Sub(c.slewEnd).Microseconds())
		return c.anchorLocal + slewed*rate + rest*c.baseRate
	}
	return c.anchorLocal + float64(t.Sub(c.anchorReal).Microseconds())*rate
}

// settle finishes an expired slew (caller holds mu).
func (c *Clock) settle(t time.Time) {
	if c.slewRate != 0 && !t.Before(c.slewEnd) {
		c.reanchor(t)
		c.slewRate = 0
	}
}

// Now returns the local clock value in microseconds since the Unix epoch.
func (c *Clock) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	c.settle(t)
	return int64(c.localAt(t))
}

// OffsetFromReal returns local - real in microseconds. This is the "ground
// truth" error, which only the simulator can know; nodes never use it.
func (c *Clock) OffsetFromReal() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	c.settle(t)
	return int64(c.localAt(t)) - t.UnixMicro()
}

// Direction describes an adjustment in Berkeley terms.
func Direction(deltaUs int64) string {
	switch {
	case deltaUs > 0:
		return "speed up"
	case deltaUs < 0:
		return "slow down"
	}
	return "keep"
}

// Slew applies deltaUs gradually over period: the clock runs faster
// (delta > 0) or slower (delta < 0) until the full delta has been absorbed.
// A new call cancels the remainder of a previous slew: the new delta was
// measured against the *current* clock value, so finishing the old slew too
// would double-count.
func (c *Clock) Slew(deltaUs int64, period time.Duration) error {
	if period <= 0 {
		return fmt.Errorf("clock: slew period must be positive")
	}
	rate := float64(deltaUs) / float64(period.Microseconds())
	// Keep the clock strictly monotonic: total rate must stay > 0.
	if c.baseRate+rate <= 0.05 {
		return fmt.Errorf("clock: slew of %dus over %v would stop/reverse the clock", deltaUs, period)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	c.settle(t)
	c.reanchor(t)
	c.slewRate = rate
	c.slewEnd = t.Add(period)
	return nil
}

// Step jumps the clock by deltaUs immediately (used only for comparison
// experiments; not monotonic for negative deltas).
func (c *Clock) Step(deltaUs int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := c.now()
	c.settle(t)
	c.reanchor(t)
	c.anchorLocal += float64(deltaUs)
}
