import urllib.parse
from channels.db import database_sync_to_async
from channels.auth import AuthMiddlewareStack
from django.contrib.auth.models import AnonymousUser
from rest_framework.authtoken.models import Token

def get_user_from_token_sync(token_key):
    try:
        token = Token.objects.get(key=token_key)
        # Force evaluation of the user (e.g. access primary key)
        _ = token.user.pk
        return token.user
    except Token.DoesNotExist:
        return AnonymousUser()

class TokenAuthMiddleware:
    """
    Custom middleware that extracts a token from the query string and authenticates the user.
    Expects the token parameter as ?token=YOUR_TOKEN.
    """
    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        query_string = scope.get("query_string", b"").decode()
        query_params = urllib.parse.parse_qs(query_string)
        token_key = query_params.get("token", [None])[0]
        if token_key:
            scope["user"] = await database_sync_to_async(get_user_from_token_sync)(token_key)
        else:
            scope["user"] = AnonymousUser()
        return await self.inner(scope, receive, send)

def TokenAuthMiddlewareStack(inner):
    # Wrap the inner app with AuthMiddlewareStack, then add TokenAuthMiddleware.
    return TokenAuthMiddleware(AuthMiddlewareStack(inner))