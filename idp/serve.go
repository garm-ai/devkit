package idp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// shutdownTimeout is how long an in-flight request gets once the context
// ends. A request here is a signature and a map lookup, so this is generous
// rather than tight.
const shutdownTimeout = 5 * time.Second

// Serve runs the dev identity provider until ctx is cancelled, then drains
// and returns nil. It returns an error only when the server could not be
// started — a non-loopback address, an unreadable personas file, a busy
// port — or when the listener failed on its own.
//
// Cancelling ctx is the only shutdown path: cmd/garmdev turns SIGINT and
// SIGTERM into a cancelled context, and garmstack cancels the context it
// gave every component.
func Serve(ctx context.Context, cfg Config) error {
	// Before anything is bound or read: a token minter on a shared
	// interface is a way for anyone who can reach it to mint any identity.
	if err := checkLoopback(cfg.Addr); err != nil {
		return err
	}
	if cfg.PersonasPath != "" {
		p, err := loadPersonas(cfg.PersonasPath)
		if err != nil {
			return err
		}
		cfg.Personas = p
	}
	h, err := New(cfg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Addr, err)
	}
	if cfg.OnListen != nil {
		cfg.OnListen(ln.Addr().String())
	}

	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
	}
	// Closed once Shutdown has returned, so Serve does not come back while a
	// handler is still writing a token. The goroutine outlives a failed
	// Serve below — it is waiting on ctx, which the caller ends.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		sc, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serving the dev IdP: %w", err)
	}
	// ErrServerClosed says Shutdown was CALLED, not that it returned.
	<-drained
	return nil
}
