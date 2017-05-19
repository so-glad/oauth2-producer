'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import _ from 'lodash';
import url from 'url';

import util from '../utils';

import Parameter from "../models/Parameter";
import Result from "../models/Result";

import AuthenticateHandler from '../handlers/AuthenticateHandler';
import CodeResponseType from '../CodeResponseType';
import {
    AccessDeniedError,
    InvalidArgumentError,
    InvalidClientError,
    InvalidRequestError,
    InvalidScopeError,
    UnsupportedResponseTypeError,
    OAuthError,
    ServerError,
    UnauthorizedClientError
} from '../models/OAuthError';

/**
 * Response types.
 */

const responseTypes = {
    code: CodeResponseType,
    //token:
};

/**
 * Constructor.
 */
export default class AuthorizeHandler {

    allowEmptyState = null;

    authenticateHandler = null;

    authorizationCodeLifetime = null;

    service = null;

    constructor(options) {
        options = options || {};

        if (options.authenticateHandler && !options.authenticateHandler.handle) {
            throw new InvalidArgumentError('Invalid argument: authenticateHandler does not implement `handle()`');
        }

        if (!options.authorizationCodeLifetime) {
            throw new InvalidArgumentError('Missing parameter: `authorizationCodeLifetime`');
        }

        if (!options.model) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        if (!options.model.getClient) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
        }

        if (!options.model.saveAuthorizationCode) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `saveAuthorizationCode()`');
        }

        this.allowEmptyState = options.allowEmptyState;
        this.authenticateHandler = options.authenticateHandler || new AuthenticateHandler(options);
        this.authorizationCodeLifetime = options.authorizationCodeLifetime;
        this.service = options.service;
    }

    /**
     * Authorize Handler.
     */

    handle = async (request, response) => {
        if (!(request instanceof Parameter)) {
            throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
        }

        if (!(response instanceof Result)) {
            throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
        }

        if ('false' === request.allowed) {
            throw new AccessDeniedError('Access denied: user denied access to application');
        }
        try {
            const authorizationCode = await this.generateAuthorizationCode();
            const expiresAt = this.getAuthorizationCodeLifetime();
            const client = await this.getClient(request);
            const user = await this.getUser(request, response);
            const uri = this.getRedirectUri(request, client);
            const scope = this.getScope(request);
            const state = this.getState(request);
            const ResponseType = this.getResponseType(request);
            const code = await this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);
            const responseType = new ResponseType(code.authorizationCode);
            const redirectUri = this.buildSuccessRedirectUri(uri, responseType);
            this.updateResponse(response, redirectUri, state);
            return code;
        } catch(e){
            if (!(e instanceof OAuthError)) {
                e = new ServerError(e);
            }
            const redirectUri = this.buildErrorRedirectUri(uri, e);
            this.updateResponse(response, redirectUri, state);
            throw e;
        }
    };

    /**
     * Generate authorization code.
     */

    generateAuthorizationCode = async () => {
        if (this.service.generateAuthorizationCode) {
            return await this.service.generateAuthorizationCode();
        }
        return util.generateRandomToken();
    };

    /**
     * Get authorization code lifetime.
     */

    getAuthorizationCodeLifetime = () => {
        const expires = new Date();

        expires.setSeconds(expires.getSeconds() + this.authorizationCodeLifetime);
        return expires;
    };

    /**
     * Get the client from the model.
     */

    getClient = async (params) => {
        const clientId = params.client_id;

        if (!clientId) {
            throw new InvalidRequestError('Missing parameter: `client_id`');
        }

        if (!util.vschar(clientId)) {
            throw new InvalidRequestError('Invalid parameter: `client_id`');
        }

        const redirectUri = params.redirect_uri;

        if (redirectUri && !util.uri(redirectUri)) {
            throw new InvalidRequestError('Invalid request: `redirect_uri` is not a valid URI');
        }

        const client = await this.service.getClient(clientId, null);

        if (!client) {
            throw new InvalidClientError('Invalid client: client credentials are invalid');
        }

        if (!client.grants) {
            throw new InvalidClientError('Invalid client: missing client `grants`');
        }

        if (!_.includes(client.grants, 'authorization_code')) {
            throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
        }

        if (!client.redirectUris || 0 === client.redirectUris.length) {
            throw new InvalidClientError('Invalid client: missing client `redirectUri`');
        }

        if (redirectUri && !_.includes(client.redirectUris, redirectUri)) {
            throw new InvalidClientError('Invalid client: `redirect_uri` does not match client value');
        }
        return client;
    };

    /**
     * Get scope from the request.
     */

    getScope = (params) => {
        const scope = params.scope;

        if (!util.nqschar(scope)) {
            throw new InvalidScopeError('Invalid parameter: `scope`');
        }

        return scope;
    };

    /**
     * Get state from the request.
     */

    getState = (params) => {
        const state = params.state;

        if (!this.allowEmptyState && !state) {
            throw new InvalidRequestError('Missing parameter: `state`');
        }

        if (!util.vschar(state)) {
            throw new InvalidRequestError('Invalid parameter: `state`');
        }

        return state;
    };

    /**
     * Get user by calling the authenticate middleware.
     */

    getUser = async (request, response) => {
        if (this.authenticateHandler instanceof AuthenticateHandler) {
            const result =  await this.authenticateHandler.handle(request, response);
            return result.get('user');
        }
        return promisify(this.authenticateHandler.handle, 2)(request, response).then(function (user) {
            if (!user) {
                throw new ServerError('Server error: `handle()` did not return a `user` object');
            }

            return user;
        });
    };

    /**
     * Get redirect URI.
     */

    getRedirectUri = (params, client) => (params.redirect_uri || client.redirectUris[0]);

    /**
     * Save authorization code.
     */

    saveAuthorizationCode = async (authorizationCode, expiresAt, scope, client, redirectUri, user) => {
        const code = {
            authorizationCode: authorizationCode,
            expiresAt: expiresAt,
            redirectUri: redirectUri,
            scope: scope
        };
        return await this.service.saveAuthorizationCode(code, client, user);
    };

    /**
     * Get response type.
     */

    getResponseType = (params) => {
        const responseType = params.response_type;

        if (!responseType) {
            throw new InvalidRequestError('Missing parameter: `response_type`');
        }

        if (!_.has(responseTypes, responseType)) {
            throw new UnsupportedResponseTypeError('Unsupported response type: `response_type` is not supported');
        }

        return responseTypes[responseType];
    };

    /**
     * Build a successful response that redirects the user-agent to the client-provided url.
     */

    buildSuccessRedirectUri = (redirectUri, responseType) => responseType.buildRedirectUri(redirectUri);

    /**
     * Build an error response that redirects the user-agent to the client-provided url.
     */

    buildErrorRedirectUri = (redirectUri, error) => {
        const uri = url.parse(redirectUri);

        uri.query = {
            error: error.name
        };

        if (error.message) {
            uri.query.error_description = error.message;
        }

        return uri;
    };

    /**
     * Update response with the redirect uri and the state parameter, if available.
     */

    updateResponse = (response, redirectUri, state) => {
        redirectUri.query = redirectUri.query || {};

        if (state) {
            redirectUri.query.state = state;
        }

        response.redirect(url.format(redirectUri));
    };

}
