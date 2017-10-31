<?php
/* Copyright (c) Rhapsody Project
 *
 * Licensed under the MIT License (http://opensource.org/licenses/MIT)
 *
 * Permission is hereby granted, free of charge, to any
 * person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the
 * Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished
 * to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice
 * shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
 * WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
 * OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT
 * OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
namespace Rhapsody\SecurityBundle;

/**
 * Events.
 *
 */
final class RhapsodySecurityEvents
{
    /**
     * Dispatched after the token generation to allow sending more data
     * on the authentication success response.
     *
     * @var string
     */
    const JWT_AUTHENTICATION_SUCCESS = 'rhapsody_security.jwt.on_authentication_success';

    /**
     * Dispatched after an authentication failure.
     *
     * Hook into this event to add a custom error message in the response body.
     *
     * @var string
     */
    const JWT_AUTHENTICATION_FAILURE = 'rhapsody_security.jwt.on_authentication_failure';

    /**
     * Dispatched before the token payload is encoded by the configured encoder
     * (JWTEncoder by default).
     *
     * Hook into this event to add extra fields to the payload.
     *
     * @var string
     */
    const JWT_CREATED = 'rhapsody_security.jwt.on_jwt_created';

    /**
     * Dispatched right after token string is created.
     *
     * Hook into this event to get token representation itself.
     *
     * @var string
     */
    const JWT_ENCODED = 'rhapsody_security.jwt.on_jwt_encoded';

    /**
     * Dispatched after the token payload has been decoded by the configured
     * encoder (JWTEncoder by default).
     *
     * Hook into this event to perform additional validation on the received
     * payload.
     *
     * @var string
     */
    const JWT_DECODED = 'rhapsody_security.jwt.on_jwt_decoded';

    /**
     * Dispatched after the token payload has been authenticated by the
     * provider.
     *
     * Hook into this event to perform additional modification to the
     * authenticated token using the payload.
     *
     * @var string
     */
    const JWT_AUTHENTICATED = 'rhapsody_security.jwt.on_jwt_authenticated';

    /**
     * Dispatched after the token has been invalidated by the provider.
     *
     * Hook into this event to add a custom error message in the response body.
     *
     * @var string
     */
    const JWT_INVALID = 'rhapsody_security.jwt.on_jwt_invalid';

    /**
     * Dispatched when no token can be found in a request.
     * Hook into this event to set a custom response.
     */
    const JWT_NOT_FOUND = 'rhapsody_security.jwt.on_jwt_not_found';

    /**
     * Dispatched when a token is refreshed.
     *
     * Hook into this event to perform additional modifications to the refreshed
     * token using the payload.
     *
     * @var string
     */
    const JWT_REFRESHED = 'rhapsody_security.jwt.on_jwt_refreshed';

    /**
     * Dispatched when a token fails to be refreshed.
     *
     * Hook into this event to add a custom error message in the response body.
     * token using the payload.
     *
     * @var string
     */
    const JWT_REFRESH_FAILED = 'rhapsody_security.jwt.on_jwt_refresh_failed';

    /**
     * Dispatched when the token is expired.
     *
     * The expired token's payload can be retrieved by hooking into this event,
     * so you can set a different response.
     *
     * @var string
     */
    const JWT_EXPIRED = 'rhapsody_security.jwt.on_jwt_expired';
}
