"""
Custom exceptions for SIEM connectors.

Hierarchy:
  ConnectorError                 (base — catch this to catch any connector error)
    ├── ConnectionError         (network/host unreachable)
    ├── AuthenticationError     (wrong credentials)
    ├── QueryError              (malformed query, indexer rejected it)
    └── ResponseError           (got a response, but couldn't parse it)
"""


class ConnectorError(Exception):
    """Base class for all SIEM connector errors."""


class ConnectionError(ConnectorError):
    """Could not reach the SIEM host (network, DNS, port closed, TLS failure)."""


class AuthenticationError(ConnectorError):
    """SIEM rejected our credentials."""


class QueryError(ConnectorError):
    """The SIEM understood the request but rejected the query (e.g. bad DSL)."""


class ResponseError(ConnectorError):
    """The SIEM returned data we couldn't parse or didn't expect."""
