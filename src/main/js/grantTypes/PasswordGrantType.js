'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import util from '../utils';
import AbstractGrantType from './AbstractGrantType';
import {InvalidArgumentError, InvalidGrantError, InvalidRequestError} from '../models/OAuthError';

/**
 * Constructor.
 */
export default class PasswordGrantType extends AbstractGrantType {

    constructor(options) {
        super(options);
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `service`');
        }

        if (!options.service.getUser) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `getUser()`');
        }

        if (!options.service.saveToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `saveToken()`');
        }
    }

    /**
     * Retrieve the user from the model using a username/password combination.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
     */

    handle = async (params, client) => {
        if (!params) {
            throw new InvalidArgumentError('Missing parameter: `params`');
        }

        if (!client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }

        const scope = this.getScope(params);
        const user = await this.getUser(params);
        return await this.saveToken(user, client, scope);
    };

    /**
     * Get user using a username/password combination.
     */

    getUser = async (params) => {
        const username = params.get('username');
        const password = params.get('password');
        if (!username) {
            throw new InvalidRequestError('Missing parameter: `username`');
        }

        if (!password) {
            throw new InvalidRequestError('Missing parameter: `password`');
        }

        if (!util.uchar(username)) {
            throw new InvalidRequestError('Invalid parameter: `username`');
        }

        if (!util.uchar(password)) {
            throw new InvalidRequestError('Invalid parameter: `password`');
        }
        const user = await this.service.getUser(username, password);
        if (!user) {
            throw new InvalidGrantError('Invalid grant: user credentials are invalid');
        }
        return user;
    };

    /**
     * Save token.
     */

    saveToken = async (user, client, scope) => {
        const validatedScope = await this.validateScope(user, client, scope);
        const accessToken = await this.generateAccessToken(client, user, scope);
        const refreshToken = await this.generateRefreshToken(client, user, scope);
        const accessTokenExpiresAt = this.getAccessTokenExpiresAt();
        const refreshTokenExpiresAt = this.getRefreshTokenExpiresAt();
        const token = {
            accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt,
            refreshToken: refreshToken,
            refreshTokenExpiresAt: refreshTokenExpiresAt,
            scope: validatedScope
        };

        return await this.service.saveToken(token, client, user);
    };
}
