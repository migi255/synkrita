"""Reject recognizable credentials at retention boundaries; not general secret detection."""
from urllib.parse import urlsplit

CREDENTIAL_KEYS = {'authorization', 'proxy_authorization', 'password', 'access_token',
                   'refresh_token', 'api_key', 'apikey', 'client_secret', 'cookie', 'set_cookie'}


def retention_safe(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if str(key).lower().replace('-', '_') in CREDENTIAL_KEYS:
                raise ValueError('Credential-bearing content cannot be retained')
            retention_safe(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            retention_safe(item)
    elif isinstance(value, str) and '://' in value:
        try:
            parsed = urlsplit(value)
            if parsed.username or parsed.password:
                raise ValueError('Credential-bearing URL cannot be retained')
        except ValueError:
            raise ValueError('Unsafe retained URL') from None
