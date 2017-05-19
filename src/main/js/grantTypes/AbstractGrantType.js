'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import util from '../utils';
import {InvalidArgumentError, InvalidScopeError} from "../models/OAuthError";

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

        if (!options.model) {
            throw new InvalidArgumentError('Missing parameter: `model`');
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
        if (this.model.generateAccessToken) {
            const accessToken = await this.service.generateAccessToken(client, user, scope);
            return accessToken || util.generateRandomToken();
        }

        return util.generateRandomToken();
    };

    /**
     * Generate refresh token.
     */

    generateRefreshToken = async (client, user, scope) => {
        if (this.service.generateRefreshToken) {
            const refreshToken = this.service.generateRefreshToken(client, user, scope);
            return refreshToken || util.generateRandomToken();
        }

        return util.generateRandomToken();
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

    getScope = (request) => {
        if (!util.nqschar(request.body.scope)) {
            throw new InvalidArgumentError('Invalid parameter: `scope`');
        }
        return request.body.scope;
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