Refresh Tokens
==============

Persistent Refresh Tokens

These are tokens that are stored in some persistent object (e.g. database) that can be looked up and the user's authentication session can be refreshed against this token.

The refresh token exists as part of (???) the JWT payload and assuming the payload is valid, even if it is expired, the user can be authenticated and have their credentials refreshed.

this requires the use of the RefreshToken model/document/entity  