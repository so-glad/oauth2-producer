'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import url from 'url';

import util from '../utils';

import Parameter from "../models/Parameter";
import Result from "../models/Result";

import AuthenticateHandler from '../handlers/AuthenticateHandler';
import CodeResponseType from '../responseTypes/CodeResponseType';
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

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        if (!options.service.getClientById) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
        }

        if (!options.service.saveAuthorizationCode) {
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

    handle = async (params) => {
        if (!(params instanceof Parameter) || !(params instanceof Object)) {
            throw new InvalidArgumentError('Invalid argument: `params` must be an instance of Parameter');
        }

        if ('false' === params.allowed) {
            throw new AccessDeniedError('Access denied: user denied access to application');
        }
        const scope = this.getScope(params);
        const state = this.getState(params);
        const client = await this.getClient(params);
        const uri = this.getRedirectUri(params, client);
        try {
            const user = await this.getUser(params);
            const authorizationCode = await this.generateAuthorizationCode();
            const expiresAt = this.getAuthorizationCodeLifetime();
            const ResponseType = this.getResponseType(params);
            const code = await this.saveAuthorizationCode(authorizationCode, expiresAt, scope, client, uri, user);
            const responseType = new ResponseType(code.authorizationCode);
            const redirectUri = this.buildSuccessRedirectUri(uri, responseType);
            return this.toResult(redirectUri, state, code);
        } catch(e){
            if (!(e instanceof OAuthError)) {
                e = new ServerError(e);
            }
            const redirectUri = this.buildErrorRedirectUri(uri, e);
            return this.toResult(redirectUri, state);
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

        const client = await this.service.getClientById(clientId);

        if (!client) {
            throw new InvalidClientError('Invalid client: client credentials are invalid');
        }

        if (!client.grants) {
            throw new InvalidClientError('Invalid client: missing client `grants`');
        }

        if (!client.grants.includes('authorization_code')) {
            throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
        }

        if (!client.redirectUris || 0 === client.redirectUris.length) {
            throw new InvalidClientError('Invalid client: missing client `redirectUri`');
        }

        if (redirectUri && !client.redirectUris.includes(redirectUri)) {
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

    getUser = async (params) => {
        if (this.authenticateHandler instanceof AuthenticateHandler) {
            const result = await this.authenticateHandler.handle(params);
            return result.get('user');
        }
        const user = await this.authenticateHandler.handle(params);
        if (!user) {
            throw new ServerError('Server error: `handle()` did not return a `user` object');
        }
        return user;
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

        if (!(responseType in responseTypes)) {
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

    toResult = (redirectUri, state, code) => {
        redirectUri.query = redirectUri.query || {};
        if (code) {
            redirectUri.query.code = code;
        }
        if (state) {
            redirectUri.query.state = state;
        }
        const result = new Result();
        result.redirect(url.format(redirectUri));
        return result;
    };

}
