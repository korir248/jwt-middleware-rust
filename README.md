# JWT middleware

## How it works
One can create the JWT when calling `/login`. As of right now login does nothing as it is irrelevant to what I'm doing. It just creates the JWT

I can tell that it gets processed and validated when calling the  `/protected` route but I ran into some error. Spent most of my night trying to fix it but to no avail.

## Issue

The JWT gets validated correctly but as of right now, the claims cannot be accessed in the handlers using the `.extensions()` method on `HttpRequest`.

The problem is that I am adding the `Claims` object after the request has been passed to the handlers hence can't be found when trying to access them. 

I've tried to switch the order but it gives an error I could not fix. So I left it as is for now. Will continue working on it later. 