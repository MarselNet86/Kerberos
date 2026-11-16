"""Panel errors (tech.md §7.5)."""

from __future__ import annotations

from typing import Optional

# code -> meaning
#   unauthorized  401: wrong login and password, or a token that does not fit
#   forbidden     403: the token lacks rights for `operation`
#   server_error  5xx after the retries
#   timeout       no answer after the retries
#   no_response   POST without an answer: not retried, the object may exist
#   unreachable   connection refused after the retries
#   bad_request   other 4xx: KERBEROS sent something the panel did not accept
#   bad_response  the answer does not match the schema; the run stops before changes


class PanelError(Exception):
    def __init__(
        self,
        code: str,
        status: Optional[int] = None,
        operation: str = "",
        detail: str = "",
    ) -> None:
        super().__init__(f"{code} {status or ''} {operation} {detail}".strip())
        self.code = code
        self.status = status
        self.operation = operation
        self.detail = detail
