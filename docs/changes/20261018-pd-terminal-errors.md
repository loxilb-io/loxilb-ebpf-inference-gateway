# Decode terminal errors (Unreleased)

## Fixed

A decode backend that died or went silent mid-stream could end an HTTP 200 SSE
stream as if it had completed; the client now receives an explicit
`data: {"error":...}` event and the request is recorded as a decode error.
Preserve zero-byte `pd_decode_backend_died`, decode-death counters, SGLang drain
closure and non-streaming read-until-close completion.

## Changed

D1: at the decode idle deadline, a finish reason in the last complete SSE data
event permits completion and the compatibility `[DONE]` terminator. Without
that evidence the idle stream fails explicitly. Null, error, incomplete,
oversized or later data events cannot prove success. Active streams refresh
the idle clock; the deadline is not a generation duration limit.

D2: retain framed HTTP message-end completion, including a chunked terminator
without SSE `[DONE]`.

Terminal extensions remain bounded. Fixed-length, ended, malformed or oversized
interrupted chunks, undrainable caches and unavailable owners may require closing
without an injectable event. No content is replayed. The owner makes one
nonblocking cache flush; the new failure path adds no cache-drain poll loop.

The last-event tracker uses two bounded4KiB buffers plus bookkeeping per proxy
fd; it makes no engine allocator or engine-memory change.
