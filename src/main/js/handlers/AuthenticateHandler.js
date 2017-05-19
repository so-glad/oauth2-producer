'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import Parameter from "../models/Parameter";
import Result from "../models/Result";

import {
    InsufficientScopeError,
    InvalidArgumentError,
    InvalidRequestError,
    InvalidTokenError,
    OAuthError,
    ServerError,
    UnauthorizedRequestError
} from "../models/OAuthError";

/**
 * Constructor.
 */

export default class AuthenticateHandler {

    addAcceptedScopesHeader = null;

    addAuthorizedScopesHeader = null;

    allowBearerTokensInQueryString = null;

    service = null;

    scope = null;

    constructor(options) {
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        if (!options.service.getAccessToken) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `getAccessToken()`');
        }

        if (options.scope && undefined === options.addAcceptedScopesHeader) {
            throw new InvalidArgumentError('Missing parameter: `addAcceptedScopesHeader`');
        }

        if (options.scope && undefined === options.addAuthorizedScopesHeader) {
            throw new InvalidArgumentError('Missing parameter: `addAuthorizedScopesHeader`');
        }

        if (options.scope && !options.model.verifyScope) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `verifyScope()`');
        }

        this.addAcceptedScopesHeader = options.addAcceptedScopesHeader;
        this.addAuthorizedScopesHeader = options.addAuthorizedScopesHeader;
        this.allowBearerTokensInQueryString = options.allowBearerTokensInQueryString;
        this.service = options.service;
        this.scope = options.scope;
    }

    handle = async (request, response) => {
        if (!(request instanceof Request)) {
            throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
        }

        if (!(response instanceof Response)) {
            throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
        }

        try {
            const token = this.getTokenFromRequest(request);
            const accessToken = await this.getAccessToken(token);
            this.validateAccessToken(accessToken);
            await this.verifyScope(accessToken);
            this.updateResponse(response, token);
        } catch (e) {
            // Include the "WWW-Authenticate" response header field if the client
            // lacks any authentication information.
            //
            // @see https://tools.ietf.org/html/rfc6750#section-3.1
            if (e instanceof UnauthorizedRequestError) {
                response.set('WWW-Authenticate', 'Bearer realm="Service"');
            }

            if (!(e instanceof OAuthError)) {
                throw new ServerError(e);
            }

            throw e;
        }
    };

    getTokenFromRequest = (request) => {
        const headerToken = request.get('Authorization');
        const queryToken = request.query.access_token;
        const bodyToken = request.body.access_token;

        if (!!headerToken + !!queryToken + !!bodyToken > 1) {
            throw new InvalidRequestError('Invalid request: only one authentication method is allowed');
        }

        if (headerToken) {
            return this.getTokenFromRequestHeader(request);
        }

        if (queryToken) {
            return this.getTokenFromRequestQuery(request);
        }

        if (bodyToken) {
            return this.getTokenFromRequestBody(request);
        }

        throw new UnauthorizedRequestError('Unauthorized request: no authentication given');
    };

    getTokenFromRequestHeader = (request) => {
        const token = request.get('Authorization');
        const matches = token.match(/Bearer\s(\S+)/);

        if (!matches) {
            throw new InvalidRequestError('Invalid request: malformed authorization header');
        }

        return matches[1];
    };

    getTokenFromRequestQuery = (request) => {
        if (!this.allowBearerTokensInQueryString) {
            throw new InvalidRequestError('Invalid request: do not send bearer tokens in query URLs');
        }

        return request.query.access_token;
    };

    getTokenFromRequestBody = (request) => {
        if (request.method === 'GET') {
            throw new InvalidRequestError('Invalid request: token may not be passed in the body when using the GET verb');
        }

        if (!request.is('application/x-www-form-urlencoded')) {
            throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded');
        }

        return request.body.access_token;
    };

    getAccessToken = async (token) => {
        const accessToken = await this.service.getAccessToken(token);
        if (!accessToken) {
            throw new InvalidTokenError('Invalid token: access token is invalid');
        }

        if (!accessToken.user) {
            throw new ServerError('Server error: `getAccessToken()` did not return a `user` object');
        }

        return accessToken;
    };

    validateAccessToken = (accessToken) => {
        if (!(accessToken.accessTokenExpiresAt instanceof Date)) {
            throw new ServerError('Server error: `accessTokenExpiresAt` must be a Date instance');
        }

        if (accessToken.accessTokenExpiresAt < new Date()) {
            throw new InvalidTokenError('Invalid token: access token has expired');
        }

        return accessToken;
    };

    verifyScope = async (accessToken) => {
        const scope = await this.service.verifyScope(accessToken, this.scope);
        if (!scope) {
            throw new InsufficientScopeError('Insufficient scope: authorized scope is insufficient');
        }
        return scope;
    };

    updateResponse = function (response, accessToken) {
        if (this.scope && this.addAcceptedScopesHeader) {
            response.set('X-Accepted-OAuth-Scopes', this.scope);
        }

        if (this.scope && this.addAuthorizedScopesHeader) {
            response.set('X-OAuth-Scopes', accessToken.scope);
        }
    };
}