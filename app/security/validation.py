"""URI and scope validation helpers."""

import logging
import urllib.parse

logger = logging.getLogger(__name__)


def _flatten_string_values(values: object) -> list[str]:
    """Flatten nested list/tuple values into a plain list of strings."""
    if values is None:
        return []

    if isinstance(values, (list, tuple)):
        result: list[str] = []
        for item in values:
            result.extend(_flatten_string_values(item))
        return result

    if isinstance(values, str):
        return [values]

    return [str(values)]


def validate_redirect_uri(redirect_uri: str, allowed_uris: list[str] | object) -> bool:
    """Check if redirect_uri is in the client's allowed list.

    Exact string match is required. Wildcard patterns are not supported.

    Args:
        redirect_uri: The URI to validate.
        allowed_uris: List of allowed redirect URIs from client config.

    Returns:
        True if redirect_uri is in allowed_uris, False otherwise.
    """
    normalized_allowed_uris = _flatten_string_values(allowed_uris)
    is_allowed = redirect_uri in normalized_allowed_uris
    logger.info(
        "[oauth.validate_redirect_uri] "
        f"redirect_uri={redirect_uri!r} "
        f"allowed_uris_raw={allowed_uris!r} "
        f"allowed_uris_normalized={normalized_allowed_uris!r} "
        f"allowed={is_allowed!r}"
    )
    return is_allowed


def is_valid_redirect_uri(uri: str) -> bool:
    """Basic validation that redirect_uri is a valid absolute URL.

    Checks:
    - Must be a valid URL (not relative)
    - Must have a scheme (http/https)
    - Must have a netloc (domain)

    Args:
        uri: The URI to validate.

    Returns:
        True if URI appears to be valid, False otherwise.
    """
    try:
        parsed = urllib.parse.urlparse(uri)
        # Must have scheme and netloc to be absolute
        return bool(parsed.scheme and parsed.netloc)
    except Exception:
        return False


def validate_scope(requested_scope: str, allowed_scopes: list[str]) -> tuple[bool, list[str]]:
    """Check if requested scopes are a subset of allowed scopes.

    Args:
        requested_scope: Space-separated scope string from request.
        allowed_scopes: List of scopes the client is allowed to request.

    Returns:
        Tuple of (is_valid, granted_scopes).
        If valid, granted_scopes is the list of scopes that were requested.
        If not valid, granted_scopes is an empty list.
    """
    if not requested_scope:
        return True, []

    requested = set(requested_scope.split())
    allowed = set(allowed_scopes)

    # Check if all requested scopes are in the allowed set
    if requested.issubset(allowed):
        return True, list(requested)
    else:
        return False, []


def scope_to_string(scopes: list[str]) -> str:
    """Convert list of scopes to space-separated string.

    Args:
        scopes: List of scope strings.

    Returns:
        Space-separated scope string.
    """
    return " ".join(scopes) if scopes else ""
