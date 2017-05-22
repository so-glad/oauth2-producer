'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import util from '../utils';
import {InvalidArgumentError, InvalidScopeError} from '../models/OAuthError';

export default class AbstractGrantType {

    accessTokenLifetime = null;

    service = null;

    refreshTokenLifetime = null;

    alwaysIssueNewRefreshToken = null;

    constructor(options) {
        options = options || {};

        if (!options.accessTokenLifetime) {
            throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
        }

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `service`');
        }

        this.accessTokenLifetime = options.accessTokenLifetime;
        this.service = options.service;
        this.refreshTokenLifetime = options.refreshTokenLifetime;
        this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken;
    }

    /**
     * Generate access token.
     */

    generateAccessToken = async (client, user, scope) => {
        if (this.service.generateAccessToken) {
            const accessToken = await this.service.generateAccessToken(client, user, scope);
            return accessToken || util.generateRandomToken(256);
        }

        return await util.generateRandomToken(256);
    };

    /**
     * Generate refresh token.
     */

    generateRefreshToken = async (client, user, scope) => {
        if (this.service.generateRefreshToken) {
            const refreshToken = this.service.generateRefreshToken(client, user, scope);
            return refreshToken || util.generateRandomToken(256);
        }

        return await util.generateRandomToken(256);
    };

    /**
     * Get access token expiration date.
     */

    getAccessTokenExpiresAt = () => {
        const expires = new Date();
        expires.setSeconds(expires.getSeconds() + this.accessTokenLifetime);
        return expires;
    };

    /**
     * Get refresh token expiration date.
     */

    getRefreshTokenExpiresAt = () => {
        const expires = new Date();
        expires.setSeconds(expires.getSeconds() + this.refreshTokenLifetime);
        return expires;
    };

    /**
     * Get scope from the request body.
     */

    getScope = (params) => {
        const scope = params.get('scope');
        if (!util.nqschar(scope)) {
            throw new InvalidArgumentError('Invalid parameter: `scope`');
        }
        return scope;
    };

    /**
     * Validate requested scope.
     */
    validateScope = async (user, client, scope) => {
        if (this.service.validateScope) {
            const scope = await this.service.validateScope(user, client, scope);
            if (!scope) {
                throw new InvalidScopeError('Invalid scope: Requested scope is invalid');
            }
            return scope;
        } else {
            return scope;
        }
    };
}