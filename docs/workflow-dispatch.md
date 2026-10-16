# Durable workflow dispatch diagnostics

The backend workflow worker advances workflow graphs, including hidden native
authoring. The personal runner leases local jobs only after graph processing
requests one. An idle personal runner does not establish backend-worker health.

Successful empty lease responses use elapsed-time-aware cycles of one, two,
four, then five seconds with twenty percent jitter. Backend waits of at least
five seconds and valid jobs reset pacing. Twenty-second long polls add no idle
delay. Drain, logout, shutdown, and session replacement interrupt local waits;
active execution renewal and delivery remain independent. `status.get` includes
fixed numeric lease-polling counters in support details.

`workflow.queue-observation/v1` negotiates optional queue diagnostics. The
backend receives explicit capability advertisement. Local clients that do not
negotiate it receive their original shape, including immutable spooled
responses. Queue wait is separate from node duration. No observation grants
execution, approval, retry, or operator authority.

`WORKFLOW_DEPLOYMENT_UNAVAILABLE` with exact HTTP 503 means the backend rejected
new work before acceptance. Its existing journal retains the exact arguments,
key, and rejection. An explicit same-key retry can follow configuration repair;
there is no automatic mutation retry. Reviewed Start retains its original
approval and reserves its consumed authorization for that same key. A lost
retry response remains ambiguous and must reconcile its receipt.

Missing workers produce an actionable nonterminal observation after event
pages are drained. Restore the backend workflow service and read the same run.
Do not recreate a queued execution, infer provider activity, or claim the run
failed from infrastructure observation alone.
