// queue.go
//
// Redis-backed async mail queue. QueuedMailer implements Mailer and enqueues
// jobs instead of sending synchronously; StartWorker drains the queue in a
// background goroutine and hands each job to the inner Mailer (SMTPMailer).
package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// QueueKey is the Redis list used as the outbound mail queue.
const QueueKey = "charon:mail:queue"

// DefaultMaxQueueSize is the cap applied when creating a QueuedMailer via NewQueuedMailer.
// Prevents unbounded growth when the SMTP server is down. 0 = unlimited.
const DefaultMaxQueueSize int64 = 1000

// ErrQueueFull is returned by enqueue when the queue has reached its size cap.
var ErrQueueFull = errors.New("mail queue full")

// job type constants identify which send method to invoke on dispatch.
const (
	jobPasswordReset     = "password_reset"
	jobEmailVerification = "email_verification"
)

// EmailJob is the serialized payload pushed onto the queue.
type EmailJob struct {
	Type      string            `json:"type"`
	ToEmail   string            `json:"to_email"`
	Token     string            `json:"token"`
	ExpiresIn int64             `json:"expires_in"` // nanoseconds; cast to time.Duration on dispatch
	Vars      map[string]string `json:"vars"`
}

// QueuedMailer enqueues email jobs to Redis so the HTTP handler returns
// immediately without waiting for SMTP. StartWorker drains the queue
// asynchronously. Implements Mailer -- callers are unaware of async dispatch.
type QueuedMailer struct {
	inner        Mailer
	rdb          *redis.Client
	maxQueueSize int64 // 0 = unlimited
}

// NewQueuedMailer wraps inner with a Redis-backed async queue.
// inner handles actual SMTP sending; rdb is the shared Redis client.
// maxSize caps the queue length (0 = unlimited); use DefaultMaxQueueSize for production.
func NewQueuedMailer(inner Mailer, rdb *redis.Client, maxSize int64) *QueuedMailer {
	return &QueuedMailer{inner: inner, rdb: rdb, maxQueueSize: maxSize}
}

// enqueueScript atomically checks the queue length and pushes the job only if
// under the cap. Returns 1 if enqueued, 0 if rejected (queue full).
// KEYS[1] = queue key, ARGV[1] = max size (0 = skip check), ARGV[2] = payload.
var enqueueScript = redis.NewScript(`
local max = tonumber(ARGV[1])
if max > 0 and redis.call('LLEN', KEYS[1]) >= max then
    return 0
end
redis.call('RPUSH', KEYS[1], ARGV[2])
return 1
`)

// SendPasswordReset enqueues a password reset email job.
func (q *QueuedMailer) SendPasswordReset(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error {
	return q.enqueue(ctx, EmailJob{
		Type:      jobPasswordReset,
		ToEmail:   toEmail,
		Token:     token,
		ExpiresIn: int64(expiresIn),
		Vars:      vars,
	})
}

// SendEmailVerification enqueues an email verification job.
func (q *QueuedMailer) SendEmailVerification(ctx context.Context, toEmail, token string, expiresIn time.Duration, vars map[string]string) error {
	return q.enqueue(ctx, EmailJob{
		Type:      jobEmailVerification,
		ToEmail:   toEmail,
		Token:     token,
		ExpiresIn: int64(expiresIn),
		Vars:      vars,
	})
}

// enqueue serializes job to JSON and appends it to the Redis queue.
// Returns ErrQueueFull if the queue has reached maxQueueSize.
func (q *QueuedMailer) enqueue(ctx context.Context, job EmailJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshaling email job: %w", err)
	}
	ok, err := enqueueScript.Run(ctx, q.rdb, []string{QueueKey}, q.maxQueueSize, data).Int64()
	if err != nil {
		return fmt.Errorf("enqueuing email job: %w", err)
	}
	if ok == 0 {
		return ErrQueueFull
	}
	return nil
}

// StartWorker drains the mail queue in a loop, dispatching each job to inner.
// Blocks until ctx is cancelled (server shutdown). Call in a goroutine.
func (q *QueuedMailer) StartWorker(ctx context.Context) {
	for {
		// BLPop blocks up to 2s then returns redis.Nil -- keeps the loop
		// responsive to ctx cancellation without busy-spinning.
		res, err := q.rdb.BLPop(ctx, 2*time.Second, QueueKey).Result()
		if err != nil {
			if ctx.Err() != nil {
				return // server shutting down
			}
			if errors.Is(err, redis.Nil) {
				continue // timeout; check ctx and try again
			}
			slog.Error("mail worker: queue pop failed", "err", err)
			continue
		}
		// res[0] = key name, res[1] = payload
		var job EmailJob
		if err := json.Unmarshal([]byte(res[1]), &job); err != nil {
			slog.Error("mail worker: bad job payload", "err", err)
			continue
		}
		q.dispatch(ctx, job)
	}
}

// dispatch calls the appropriate inner Mailer method based on job.Type.
// Errors are logged and dropped -- no retry in v1.
func (q *QueuedMailer) dispatch(ctx context.Context, job EmailJob) {
	expiresIn := time.Duration(job.ExpiresIn)
	var err error
	switch job.Type {
	case jobPasswordReset:
		err = q.inner.SendPasswordReset(ctx, job.ToEmail, job.Token, expiresIn, job.Vars)
	case jobEmailVerification:
		err = q.inner.SendEmailVerification(ctx, job.ToEmail, job.Token, expiresIn, job.Vars)
	default:
		slog.Error("mail worker: unknown job type", "type", job.Type)
		return
	}
	if err != nil {
		slog.Error("mail worker: send failed", "type", job.Type, "to", job.ToEmail, "err", err)
	}
}
