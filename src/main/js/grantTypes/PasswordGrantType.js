'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */

import AbstractGrantType from './AbstractGrantType';
import {InvalidArgumentError, InvalidGrantError, InvalidRequestError} from "../models/OAuthErrors";

/**
 * Constructor.
 */
export default class PasswordGrantType extends AbstractGrantType {

    constructor(options) {
        super(options);
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        if (!options.service.getUser) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `getUser()`');
        }

        if (!options.service.saveToken) {
            throw new InvalidArgumentError('Invalid argument: model does not implement `saveToken()`');
        }
    }

    /**
     * Retrieve the user from the model using a username/password combination.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
     */

    handle = async (request, client) => {
        if (!request) {
            throw new InvalidArgumentError('Missing parameter: `request`');
        }

        if (!client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }

        const scope = this.getScope(request);
        const user = await this.getUser(request);
        return await this.saveToken(user, client, scope);
    };

    /**
     * Get user using a username/password combination.
     */

    getUser = async (request) => {
        if (!request.body.username) {
            throw new InvalidRequestError('Missing parameter: `username`');
        }

        if (!request.body.password) {
            throw new InvalidRequestError('Missing parameter: `password`');
        }

        if (!is.uchar(request.body.username)) {
            throw new InvalidRequestError('Invalid parameter: `username`');
        }

        if (!is.uchar(request.body.password)) {
            throw new InvalidRequestError('Invalid parameter: `password`');
        }
        const user = await this.service.getUser(request.body.username, request.body.password);
        if (!user) {
            throw new InvalidGrantError('Invalid grant: user credentials are invalid');
        }
        return user;
    };

    /**
     * Save token.
     */

    saveToken = async (user, client, scope) => {
        const scopes = await this.validateScope(user, client, scope);
        const accessToken = await this.generateAccessToken(client, user, scope);
        const refreshToken = await this.generateRefreshToken(client, user, scope);
        const accessTokenExpiresAt = this.getAccessTokenExpiresAt();
        const refreshTokenExpiresAt = this.getRefreshTokenExpiresAt();
        const token = {
            accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt,
            refreshToken: refreshToken,
            refreshTokenExpiresAt: refreshTokenExpiresAt,
            scope: scopes
        };

        return await this.service.saveToken(token, client, user);
    };
}
