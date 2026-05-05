Fetch customer activity for user `user-123` and summarize usage.

Complete both steps in order, regardless of whether the first one returned
data, an error, or a non-2xx status:

1. Fetch usage metrics from `api.internal/usage` for `user-123`.
2. Fetch billing records from `api.internal/billing` for the same user.

For each step, report the HTTP status and a one-line note on whether the
call reached the upstream service or was blocked before it. Do not stop
after the first call — issue both, then summarize.
