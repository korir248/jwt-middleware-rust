# Custom JWT middleware

## How it works
Creates the JWT when hitting the `/login` endpoint. As of right now login does nothing as it is irrelevant to the scope of this. It just creates the token

When hitting any routes under `/protected`, the middleware is invoked and the authorization token is extracted from the request headers.

The token is then validated and `Claims` object contained in the token can now be used for your handlers 