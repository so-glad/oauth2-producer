'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import util from '../utils';
import AbstractGrantType from './AbstractGrantType';

import {InvalidArgumentError, InvalidGrantError, InvalidRequestError, ServerError} from '../models/OAuthError';

export default class RefreshTokenGrantType extends AbstractGrantType {

    constructor(options) {
        super(options);

        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `service`');
        }

        if (!options.service.getRefreshToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `getRefreshToken()`');
        }

        if (!options.service.revokeToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `revokeToken()`');
        }

        if (!options.service.saveToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `saveToken()`');
        }

    }

    /**
     * Handle refresh token grant.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-6
     */

    handle = async (params, client) => {
        if (!params) {
            throw new InvalidArgumentError('Missing parameter: `params`');
        }

        if (!client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }
        const token = await this.getRefreshToken(params, client);
        await this.revokeToken(token);
        return await this.saveToken(token.user, client, token.scope);
    };

    /**
     * Get refresh token.
     */

    getRefreshToken = async (params, client) => {
        if (!params.refresh_token) {
            throw new InvalidRequestError('Missing parameter: `refresh_token`');
        }

        if (!util.vschar(params.refresh_token)) {
            throw new InvalidRequestError('Invalid parameter: `refresh_token`');
        }

        const token = await this.service.getRefreshToken(params.refresh_token);

        if (!token) {
            throw new InvalidGrantError('Invalid grant: refresh token is invalid');
        }

        if (!token.client) {
            throw new ServerError('Server error: `getRefreshToken()` did not return a `client` object');
        }

        if (!token.user) {
            throw new ServerError('Server error: `getRefreshToken()` did not return a `user` object');
        }

        if (token.client.id !== client.id) {
            throw new InvalidGrantError('Invalid grant: refresh token is invalid');
        }

        if (token.refreshTokenExpiresAt && !(token.refreshTokenExpiresAt instanceof Date)) {
            throw new ServerError('Server error: `refreshTokenExpiresAt` must be a Date instance');
        }

        if (token.refreshTokenExpiresAt && token.refreshTokenExpiresAt < new Date()) {
            throw new InvalidGrantError('Invalid grant: refresh token has expired');
        }

        return token;
    };

    /**
     * Revoke the refresh token.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-6
     */

    revokeToken = async (token) => {
        if (this.alwaysIssueNewRefreshToken === false) {
            return token;
        }
        const status = this.service.revokeToken(token);
        if (!status) {
            throw new InvalidGrantError('Invalid grant: refresh token is invalid');
        }

        return token;
    };

    /**
     * Save token.
     */

    saveToken = async (user, client, scope) => {
        const accessToken = await this.generateAccessToken(client, user, scope);
        const accessTokenExpiresAt = this.getAccessTokenExpiresAt();
        const token = {
            accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt,
            scope: scope
        };
        if (this.alwaysIssueNewRefreshToken) {
            const refreshToken = await this.generateRefreshToken(client, user, scope);
            const refreshTokenExpiresAt = this.getRefreshTokenExpiresAt();
            token.refreshToken = refreshToken;
            token.refreshTokenExpiresAt = refreshTokenExpiresAt;
        }
        return await this.service.saveToken(token, client, user);
    };
}
