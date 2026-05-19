package reputation

import (
	"context"
	"errors"
	"sort"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   []Enricher
)

// Register adds e to the package-level registry. Re-registering an
// enricher with the same Name() replaces the existing entry so callers may
// safely call Register from init() in tests without leaking instances
// across runs. A nil enricher is ignored.
func Register(e Enricher) {
	if e == nil {
		return
	}
	registryMu.Lock()
	defer registryMu.Unlock()
	name := e.Name()
	for i, existing := range registry {
		if existing.Name() == name {
			registry[i] = e
			return
		}
	}
	registry = append(registry, e)
}

// Reset clears the registry. Exported for tests.
func Reset() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = nil
}

// Registered returns a copy of the currently registered enrichers in
// registration order. The returned slice is owned by the caller.
func Registered() []Enricher {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Enricher, len(registry))
	copy(out, registry)
	return out
}

// EnrichAll fans out the lookup for ip to every registered enricher
// concurrently and returns the non-nil results.
//
// Behaviour:
//   - Each enricher is invoked with the supplied ctx. Slow or hung
//     enrichers do not block others — EnrichAll only waits for the
//     enrichers that respond (or for ctx cancellation).
//   - Results are sorted by enricher name for deterministic output.
//   - If one or more enrichers return an error, the errors are joined
//     and returned alongside any successful results. Callers should not
//     treat a partial error as fatal.
func EnrichAll(ctx context.Context, ip string) ([]*Result, error) {
	enrichers := Registered()
	if len(enrichers) == 0 {
		return nil, nil
	}

	type outcome struct {
		res *Result
		err error
	}
	resCh := make(chan outcome, len(enrichers))

	var wg sync.WaitGroup
	for _, e := range enrichers {
		wg.Add(1)
		go func(e Enricher) {
			defer wg.Done()
			defer func() {
				// An enricher panic must not bring the report run down.
				if r := recover(); r != nil {
					resCh <- outcome{err: errors.New("reputation: enricher " + e.Name() + " panicked")}
				}
			}()
			res, err := e.Enrich(ctx, ip)
			resCh <- outcome{res: res, err: err}
		}(e)
	}

	go func() {
		wg.Wait()
		close(resCh)
	}()

	var results []*Result
	var errs []error
	for {
		select {
		case <-ctx.Done():
			// Drain whatever already arrived before the deadline; do not
			// wait on the still-running enrichers. Their goroutines exit
			// when they observe ctx (or, worst case, run to completion in
			// the background and their sends are dropped because nobody is
			// reading).
			for {
				select {
				case o, ok := <-resCh:
					if !ok {
						return finalize(results, errs, ctx.Err())
					}
					if o.res != nil {
						results = append(results, o.res)
					}
					if o.err != nil {
						errs = append(errs, o.err)
					}
				default:
					return finalize(results, errs, ctx.Err())
				}
			}
		case o, ok := <-resCh:
			if !ok {
				return finalize(results, errs, nil)
			}
			if o.res != nil {
				results = append(results, o.res)
			}
			if o.err != nil {
				errs = append(errs, o.err)
			}
		}
	}
}

func finalize(results []*Result, errs []error, ctxErr error) ([]*Result, error) {
	sort.SliceStable(results, func(i, j int) bool {
		return results[i].Enricher < results[j].Enricher
	})
	if ctxErr != nil {
		errs = append(errs, ctxErr)
	}
	if len(errs) == 0 {
		return results, nil
	}
	return results, errors.Join(errs...)
}
