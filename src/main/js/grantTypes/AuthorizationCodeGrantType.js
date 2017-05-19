'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import util from '../utils';
import AbstractGrantType from './AbstractGrantType';

import {InvalidArgumentError, InvalidGrantError, InvalidRequestError, ServerError} from '../models/OAuthError';

export default class AuthorizationCodeGrantType extends AbstractGrantType {

    constructor(options) {
        super(options);
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        if (!options.service.getAuthorizationCode) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `getAuthorizationCode()`');
        }

        if (!options.service.revokeAuthorizationCode) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `revokeAuthorizationCode()`');
        }

        if (!options.service.saveToken) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
        }
    }

    /**
     * Handle authorization code grant.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
     */

    handle = async (request, client) => {
        if (!request) {
            throw new InvalidArgumentError('Missing parameter: `request`');
        }

        if (!client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }
        const code = await this.getAuthorizationCode(request, client);
        this.validateRedirectUri(request, code);
        await this.revokeAuthorizationCode(code);
        return this.saveToken(code.user, client, code.authorizationCode, code.scope);
    };

    /**
     * Get the authorization code.
     */

    getAuthorizationCode = async (request, client) => {
        if (!request.body.code) {
            throw new InvalidRequestError('Missing parameter: `code`');
        }

        if (!util.vschar(request.body.code)) {
            throw new InvalidRequestError('Invalid parameter: `code`');
        }
        const code = await this.service.getAuthorizationCode(request.body.code);
        if (!code) {
            throw new InvalidGrantError('Invalid grant: authorization code is invalid');
        }

        if (!code.client) {
            throw new ServerError('Server error: `getAuthorizationCode()` did not return a `client` object');
        }

        if (!code.user) {
            throw new ServerError('Server error: `getAuthorizationCode()` did not return a `user` object');
        }

        if (code.client.id !== client.id) {
            throw new InvalidGrantError('Invalid grant: authorization code is invalid');
        }

        if (!(code.expiresAt instanceof Date)) {
            throw new ServerError('Server error: `expiresAt` must be a Date instance');
        }

        if (code.expiresAt < new Date()) {
            throw new InvalidGrantError('Invalid grant: authorization code has expired');
        }

        if (code.redirectUri && !is.uri(code.redirectUri)) {
            throw new InvalidGrantError('Invalid grant: `redirect_uri` is not a valid URI');
        }

        return code;
    };

    /**
     * Validate the redirect URI.
     *
     * "The authorization server MUST ensure that the redirect_uri parameter is
     * present if the redirect_uri parameter was included in the initial
     * authorization request as described in Section 4.1.1, and if included
     * ensure that their values are identical."
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
     */

    validateRedirectUri = (request, code) => {
        if (!code.redirectUri) {
            return;
        }

        const redirectUri = request.body.redirect_uri || request.query.redirect_uri;

        if (!util.uri(redirectUri)) {
            throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
        }

        if (redirectUri !== code.redirectUri) {
            throw new InvalidRequestError('Invalid request: `redirect_uri` is invalid');
        }
    };

    /**
     * Revoke the authorization code.
     *
     * "The authorization code MUST expire shortly after it is issued to mitigate
     * the risk of leaks. [...] If an authorization code is used more than once,
     * the authorization server MUST deny the request."
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
     */

    revokeAuthorizationCode = async (code) => {
        const status = await this.service.revokeAuthorizationCode(code);
        if (!status) {
            throw new InvalidGrantError('Invalid grant: authorization code is invalid');
        }
        return code;
    };

    /**
     * Save token.
     */

    saveToken = async (user, client, authorizationCode, scope) => {

        const scopes = await this.validateScope(user, client, scope);
        const accessToken = await this.generateAccessToken(client, user, scope);
        const refreshToken = await this.generateRefreshToken(client, user, scope);
        const accessTokenExpiresAt = this.getAccessTokenExpiresAt();
        const refreshTokenExpiresAt = this.getRefreshTokenExpiresAt();
        const token = {
            accessToken: accessToken,
            authorizationCode: authorizationCode,
            accessTokenExpiresAt: accessTokenExpiresAt,
            refreshToken: refreshToken,
            refreshTokenExpiresAt: refreshTokenExpiresAt,
            scope: scopes
        };

        return await this.service.saveToken(token, client, user);
    };

}
