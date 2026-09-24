# Python SDK (`sentinelai`)

**Status: implemented** (`packages/sdk/python`; 39 tests against a real threaded HTTP server + cross-language e2e against the real gateway and engine). Not yet published to PyPI. Python 3.9+, standard library only (zero dependencies), synchronous.

```python
import os
from sentinelai import Sentinel, SentinelBlockedError

client = Sentinel(api_key=os.getenv("SENTINEL_API_KEY"), base_url="https://gateway.example.com")

try:
    response = client.secure(provider="gemini", prompt=prompt)
    print(response.content)                       # scanned on the way in AND out
except SentinelBlockedError as e:
    print(e.stage, e.decision, e.event_id)        # never contains content
```

`secure()` / `chat()` / `scan()` / `check()` / `scan_file()` mirror the [JavaScript SDK](javascript.md) with snake_case names and frozen dataclass results
(`SecureResponse`, `ScanResult`, `CheckResult`, `FileScanResult`). `scan_file(data: bytes, filename=None)` sends only the extension; a blocked file is returned with
`blocked=True` and `sanitized_text=None`, so check `blocked` before using the text. Configuration also comes from `SENTINEL_API_KEY` and `SENTINEL_BASE_URL`.

Exceptions: `SentinelBlockedError`, `SentinelAuthenticationError`, `SentinelPermissionError`, `SentinelValidationError`, `SentinelRateLimitError`,
`SentinelProviderError`, `SentinelUnavailableError`, `SentinelConfigError` (all subclass `SentinelError`; none contain the key, prompt or response).

## Guarantees
Same as the JavaScript SDK: fail-closed (content only from a well-formed 200; contradictory replies rejected), https required except localhost,
key redacted from `repr()` and unpicklable, no retries. **Redirects are refused**: `urllib` follows 301/302/303 as a GET *and re-sends custom headers*, which
would hand the API key to another host. This was confirmed by a mutation test (with default `urllib` handling the key does reach the redirect target) and is
covered for 301/302/303/307/308.

## Not implemented
Async client, streaming, retries, management APIs.
