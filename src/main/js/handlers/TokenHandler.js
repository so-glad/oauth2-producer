'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import util from '../utils';

import Parameter from '../models/Parameter';
import Result from '../models/Result';

import AccessToken from '../models/AccessToken';

import AuthorizationCodeGrantType from '../grantTypes/AuthorizationCodeGrantType';
import PasswordGrantType from '../grantTypes/PasswordGrantType';
import ClientCredentialsGrantType from '../grantTypes/ClientCredentialsGrantType';
import ProxyGrantType from '../grantTypes/ProxyGrantType';
import RefreshTokenGrantType from '../grantTypes/RefreshTokenGrantType';

import {
    InvalidArgumentError,
    InvalidClientError,
    InvalidRequestError,
    OAuthError,
    ServerError,
    UnauthorizedClientError,
    UnsupportedGrantTypeError
} from '../models/OAuthError';

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
            throw new InvalidArgumentError('Missing parameter: `service`');
        }

        if (!options.refreshTokenLifetime) {
            throw new InvalidArgumentError('Missing parameter: `refreshTokenLifetime`');
        }

        if (!options.service.getClient) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `getClient()`');
        }

        this.accessTokenLifetime = options.accessTokenLifetime;
        this.grantTypes = Object.assign({}, grantTypes, options.extendedGrantTypes);
        this.service = options.service;
        this.refreshTokenLifetime = options.refreshTokenLifetime;
        this.allowExtendedTokenAttributes = options.allowExtendedTokenAttributes;
        this.requireClientAuthentication = options.requireClientAuthentication || {};
        this.alwaysIssueNewRefreshToken = options.alwaysIssueNewRefreshToken !== false;
    }

    /**
     * Token Handler.
     */

    handle = async (params) => {
        if (!(params instanceof Parameter) || !(params instanceof Object)) {
            throw new InvalidArgumentError('Invalid argument: `params` must be an instance of Parameter');
        }

        try {
            const client = await this.getClient(params);
            const data = await this.handleGrantType(params, client);
            const model = new AccessToken(data, {allowExtendedTokenAttributes: this.allowExtendedTokenAttributes});
            const bearerToken = model.asBearerType();
            return this.toResult(bearerToken);
        } catch (e) {
            const error = (e instanceof OAuthError) ? e : new ServerError(e);
            const result = this.toError(error);
            if(error instanceof InvalidClientError && params.get('authorization')) {
                result.header('WWW-Authenticate', 'Basic realm="Service"');
                result.status = 401;
            }
            return result;
        }
    };

    /**
     * Get the client from the model.
     */

    getClient = async (params) => {
        const credentials = this.getClientCredentials(params);
        const grantType = params.get('grant_type');

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
            throw new InvalidClientError('Invalid client: client is invalid');
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

    getClientCredentials = (params) => {
        const grantType = params.get('grant_type');

        if (params.get('client_id') && params.get('client_secret')) {
            return {clientId: params.get('client_id'), clientSecret: params.get('client_secret')};
        }

        if (!this.isClientAuthenticationRequired(grantType)) {
            if (params.get('client_id')) {
                return {clientId: params.get('client_id')};
            }
        }

        throw new InvalidClientError('Invalid client: cannot retrieve client credentials');
    };

    /**
     * Handle grant type.
     */

    handleGrantType = async (params, client) => {
        const grantType = params.get('grant_type');

        if (!grantType) {
            throw new InvalidRequestError('Missing parameter: `grant_type`');
        }

        if (!util.nchar(grantType) && !util.uri(grantType)) {
            throw new InvalidRequestError('Invalid parameter: `grant_type`');
        }

        if (!(grantType in this.grantTypes)) {
            throw new UnsupportedGrantTypeError('Unsupported grant type: `grant_type` is invalid');
        }

        if (!client.grants.includes(grantType)) {
            throw new UnauthorizedClientError('Unauthorized client: `grant_type` is invalid');
        }

        const accessTokenLifetime = this.getAccessTokenLifetime(client);
        const refreshTokenLifetime = this.getRefreshTokenLifetime(client);
        const GrantType = this.grantTypes[grantType];

        const options = {
            accessTokenLifetime: accessTokenLifetime,
            service: this.service,
            refreshTokenLifetime: refreshTokenLifetime,
            alwaysIssueNewRefreshToken: this.alwaysIssueNewRefreshToken
        };
        const grantHandler = new GrantType(options);
        return await grantHandler.handle(params, client);
    };

    /**
     * Get access token lifetime.
     */

    getAccessTokenLifetime = (client) => client.accessTokenLifetime || this.accessTokenLifetime;

    /**
     * Get refresh token lifetime.
     */

    getRefreshTokenLifetime = (client) => client.refreshTokenLifetime || this.refreshTokenLifetime;

    /**
     * Update response when a token is generated.
     */

    toResult = (tokenType) => {
        const result = new Result();
        for (const key in tokenType) {
            result.set(key, tokenType[key]);
        }
        result.header('Cache-Control', 'no-store');
        result.header('Pragma', 'no-cache');
        return result;
    };

    /**
     * Update response when an error is thrown.
     */

    toError = (error) => {
        const result = new Result();
        result.set('error', error.name);
        result.set('message', error.message);
        result.status = error.code;
        return result;
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
