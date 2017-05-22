'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import Parameter from '../models/Parameter';
import Result from '../models/Result';

import {
    InsufficientScopeError,
    InvalidArgumentError,
    InvalidTokenError,
    OAuthError,
    ServerError,
    UnauthorizedRequestError
} from '../models/OAuthError';

/**
 * Constructor.
 */

export default class AuthenticateHandler {

    addAcceptedScopesHeader = null;

    addAuthorizedScopesHeader = null;

    service = null;

    scope = null;

    constructor(options) {
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `service`');
        }

        if (!options.service.getAccessToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `getAccessToken()`');
        }

        if (options.scope && undefined === options.addAcceptedScopesHeader) {
            throw new InvalidArgumentError('Missing parameter: `addAcceptedScopesHeader`');
        }

        if (options.scope && undefined === options.addAuthorizedScopesHeader) {
            throw new InvalidArgumentError('Missing parameter: `addAuthorizedScopesHeader`');
        }

        if (options.scope && !options.service.verifyScope) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `verifyScope()`');
        }

        this.addAcceptedScopesHeader = options.addAcceptedScopesHeader;
        this.addAuthorizedScopesHeader = options.addAuthorizedScopesHeader;
        this.allowBearerTokensInQueryString = options.allowBearerTokensInQueryString;
        this.service = options.service;
        this.scope = options.scope;
    }

    handle = async (params) => {
        if (!(params instanceof Parameter) || !(params instanceof Object)) {
            throw new InvalidArgumentError('Invalid argument: `params` must be an instance of Parameter');
        }

        try {
            let accessToken = params.get('Authorization') || params.get('access_token');
            const matches = accessToken.match(/Bearer\s(\S+)/);
            if(matches) {
                accessToken = matches[1];
            }
            const token = await this.getToken(accessToken);
            this.validateToken(token);
            await this.verifyScope(token);
            return this.toResult(accessToken);
        } catch (e) {
            // Include the "WWW-Authenticate" response header field if the client
            // lacks any authentication information.
            //
            // @see https://tools.ietf.org/html/rfc6750#section-3.1
            const result = new Result();
            if (e instanceof UnauthorizedRequestError) {
                result.header('WWW-Authenticate', 'Bearer realm="Service"');
                return result;
            }

            if (!(e instanceof OAuthError)) {
                throw new ServerError(e);
            }

            throw e;
        }
    };

    getToken = async (token) => {
        const accessToken = await this.service.getAccessToken(token);
        if (!accessToken) {
            throw new InvalidTokenError('Invalid token: access token is invalid');
        }

        if (!accessToken.user) {
            throw new ServerError('Server error: `getAccessToken()` did not return a `user` object');
        }

        return accessToken;
    };

    validateToken = (token) => {
        if (!(token.accessTokenExpiresAt instanceof Date)) {
            throw new ServerError('Server error: `accessTokenExpiresAt` must be a Date instance');
        }

        if (token.accessTokenExpiresAt < new Date()) {
            throw new InvalidTokenError('Invalid token: access token has expired');
        }

        return token;
    };

    verifyScope = async (token) => {
        const scope = await this.service.verifyScope(token, this.scope);
        if (!scope) {
            throw new InsufficientScopeError('Insufficient scope: authorized scope is insufficient');
        }
        return scope;
    };

    toResult = (accessToken) => {
        const result = new Result();
        if (this.scope && this.addAcceptedScopesHeader) {
            result.header('X-Accepted-OAuth-Scopes', this.scope);
        }

        if (this.scope && this.addAuthorizedScopesHeader) {
            result.header('X-OAuth-Scopes', accessToken.scope);
        }
        for (const key in accessToken) {
            result.set(key, accessToken[key]);
        }
        return result;
    };
}