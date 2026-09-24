# sentinelai (Python SDK)

Route AI requests through the SentinelAI security gateway. Standard library only; Python 3.9+.

```python
import os
from sentinelai import Sentinel, SentinelBlockedError

client = Sentinel(api_key=os.getenv("SENTINEL_API_KEY"), base_url="https://gateway.example.com")

try:
    response = client.secure(provider="gemini", prompt=prompt)
    print(response.content)              # already scanned (input AND output)
except SentinelBlockedError as e:        # policy block, injection, secret, or fail-closed
    print(e.stage, e.decision, e.event_id)   # never contains content
```

- `secure()` / `chat()` - full pipeline; raises on any block, network failure, timeout or malformed reply (fail closed).
- `scan()` - decision + evidence + sanitized text, without calling a model. A blocked result is returned (`result.blocked`).
- `check()` - cheap allow/deny.

Security defaults: `https://` required except for localhost; redirects are never followed (the key is never re-sent elsewhere); the key
never appears in `repr()`, exceptions or logs; responses that contradict themselves (e.g. blocked *with* text) are rejected.
