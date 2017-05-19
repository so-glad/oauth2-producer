'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import _ from "lodash";

import auth from "basic-auth";
import util from "../utils";

import Parameter from "../models/Parameter";
import Result from "../models/Result";

import BearerTokenType from "../BearerTokenType";
import TokenModel from "../models/TokenModel";

import AuthorizationCodeGrantType from "../grantTypes/AuthorizationCodeGrantType";
import PasswordGrantType from "../grantTypes/PasswordGrantType";
import ClientCredentialsGrantType from "../grantTypes/ClientCredentialsGrantType";
import ProxyGrantType from "../grantTypes/ProxyGrantType";
import RefreshTokenGrantType from "../grantTypes/RefreshTokenGrantType";

import {
    InvalidArgumentError,
    InvalidClientError,
    InvalidRequestError,
    OAuthError,
    ServerError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError
} from "../models/OAuthError";

/**
 * Grant types.
 */

const grantTypes = {
    authorization_code: AuthorizationCodeGrantType,
    client_credentials: ClientCredentialsGrantType,
    password: PasswordGrantType,
    refresh_token: RefreshTokenGrantType,
    proxy: ProxyGrantType
};

/**
 * Constructor.
 */
export default class TokenHandler {

    accessTokenLifetime = null;
    grantTypes = null;
    service = null;
    refreshTokenLifetime = null;
    allowExtendedTokenAttributes = null;
    requireClientAuthentication = null;
    alwaysIssueNewRefreshToken = null;

    constructor(options) {
        options = options || {};

        if (!options.accessTokenLifetime) {
            throw new InvalidArgumentError('Missing parameter: `accessTokenLifetime`');
        }

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        if (!options.refreshTokenLifetime) {
            throw new InvalidArgumentError('Missing parameter: `refreshTokenLifetime`');
        }

        if (!options.service.getClient) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
        }

        this.accessTokenLifetime = options.accessTokenLifetime;
        this.grantTypes = _.assign({}, grantTypes, options.extendedGrantTypes);
        this.service = options.service;
        this.refreshTokenLifetime = options.refreshTokenLifetime;
        this.allowExtendedTokenAttributes = options.allowExtendedTokenAttributes;
        this.requireClientAuthentication = options.requireClientAuthentication || {};
        this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken !== false;
    }

    /**
     * Token Handler.
     */

    handle = async (request, response) => {
        if (!(request instanceof Parameter)) {
            throw new InvalidArgumentError('Invalid argument: `request` must be an instance of Request');
        }

        if (!(response instanceof Result)) {
            throw new InvalidArgumentError('Invalid argument: `response` must be an instance of Response');
        }

        if (request.method !== 'POST') {
            throw new InvalidRequestError('Invalid request: method must be POST');
        }

        if (!request.is('application/x-www-form-urlencoded')) {
            throw new InvalidRequestError('Invalid request: content must be application/x-www-form-urlencoded');
        }
        try {
            const client = await this.getClient(request, response);
            const data = await this.handleGrantType(request, client);
            const model = new TokenModel(data, {allowExtendedTokenAttributes: this.allowExtendedTokenAttributes});
            const tokenType = this.getTokenType(model);
            this.updateSuccessResponse(response, tokenType);
        } catch (e) {
            const error = (e instanceof OAuthError) ? e : new ServerError(e);
            this.updateErrorResponse(response, error);
            throw error;
        }
    };

    /**
     * Get the client from the model.
     */

    getClient = async (request, response) => {
        const credentials = this.getClientCredentials(request);
        const grantType = request.body.grant_type;

        if (!credentials.clientId) {
            throw new InvalidRequestError('Missing parameter: `client_id`');
        }

        if (this.isClientAuthenticationRequired(grantType) && !credentials.clientSecret) {
            throw new InvalidRequestError('Missing parameter: `client_secret`');
        }

        if (!util.vschar(credentials.clientId)) {
            throw new InvalidRequestError('Invalid parameter: `client_id`');
        }

        if (!util.vschar(credentials.clientSecret)) {
            throw new InvalidRequestError('Invalid parameter: `client_secret`');
        }
        const client = await this.service.getClient(credentials.clientId, credentials.clientSecret);
        if (!client) {
            const properties = {};
            if (request.get('authorization')) {
                response.set('WWW-Authenticate', 'Basic realm="Service"');
                properties.code = 401;
            }
            throw new InvalidClientError('Invalid client: client is invalid', properties);
        }

        if (!client.grants) {
            throw new ServerError('Server error: missing client `grants`');
        }

        if (!(client.grants instanceof Array)) {
            throw new ServerError('Server error: `grants` must be an array');
        }
        return client;
    };


    /**
     * Get client credentials.
     *
     * The client credentials may be sent using the HTTP Basic authentication scheme or, alternatively,
     * the `client_id` and `client_secret` can be embedded in the body.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
     */

    getClientCredentials = (request) => {
        const credentials = auth(request);
        const grantType = request.body.grant_type;

        if (credentials) {
            return {clientId: credentials.name, clientSecret: credentials.pass};
        }

        if (request.body.client_id && request.body.client_secret) {
            return {clientId: request.body.client_id, clientSecret: request.body.client_secret};
        }

        if (!this.isClientAuthenticationRequired(grantType)) {
            if (request.body.client_id) {
                return {clientId: request.body.client_id};
            }
        }

        throw new InvalidClientError('Invalid client: cannot retrieve client credentials');
    };

    /**
     * Handle grant type.
     */

    handleGrantType = async (request, client) => {
        const grantType = request.body.grant_type;

        if (!grantType) {
            throw new InvalidRequestError('Missing parameter: `grant_type`');
        }

        if (!util.nchar(grantType) && !is.uri(grantType)) {
            throw new InvalidRequestError('Invalid parameter: `grant_type`');
        }

        if (!_.has(this.grantTypes, grantType)) {
            throw new UnsupportedGrantTypeError('Unsupported grant type: `grant_type` is invalid');
        }

        if (!_.includes(client.grants, grantType)) {
            throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
        }

        const accessTokenLifetime = this.getAccessTokenLifetime(client);
        const refreshTokenLifetime = this.getRefreshTokenLifetime(client);
        const GrantType = this.grantTypes[grantType];

        const options = {
            accessTokenLifetime: accessTokenLifetime,
            model: this.service,
            refreshTokenLifetime: refreshTokenLifetime,
            alwaysIssueNewRefreshToken: this.alwaysIssueNewRefreshToken
        };

        return await new GrantType(options).handle(request, client);
    };

    /**
     * Get access token lifetime.
     */

    getAccessTokenLifetime = (client) => {
        return client.accessTokenLifetime || this.accessTokenLifetime;
    };

    /**
     * Get refresh token lifetime.
     */

    getRefreshTokenLifetime = (client) => {
        return client.refreshTokenLifetime || this.refreshTokenLifetime;
    };

    /**
     * Get token type.
     */

    getTokenType = (model) => new BearerTokenType(model.accessToken, model.accessTokenLifetime, model.refreshToken, model.scope, model.customAttributes);

    /**
     * Update response when a token is generated.
     */

    updateSuccessResponse = (response, tokenType) => {
        response.body = tokenType.valueOf();

        response.set('Cache-Control', 'no-store');
        response.set('Pragma', 'no-cache');
    };

    /**
     * Update response when an error is thrown.
     */

    updateErrorResponse = (response, error) => {
        response.body = {
            error: error.name,
            error_description: error.message
        };

        response.status = error.code;
    };

    /**
     * Given a grant type, check if client authentication is required
     */
    isClientAuthenticationRequired = (grantType) => {
        if (Object.keys(this.requireClientAuthentication).length > 0) {
            return (typeof this.requireClientAuthentication[grantType] !== 'undefined') ?
                this.requireClientAuthentication[grantType] : true;
        } else {
            return true;
        }
    };

}
