'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */

import AbstractGrantType from './AbstractGrantType';
import {InvalidArgumentError, InvalidGrantError} from '../models/OAuthError';

export default class ClientCredentialsGrantType extends AbstractGrantType {


    constructor(options) {
        super(options);
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `service`');
        }

        if (!options.service.getUserFromClient) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `getUserFromClient()`');
        }

        if (!options.service.saveToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `saveToken()`');
        }

    }

    /**
     * Handle client credentials grant.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.4.2
     */

    handle = async (params, client) => {
        if (!params) {
            throw new InvalidArgumentError('Missing parameter: `params`');
        }

        if (!client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }

        const scope = this.getScope(params);
        const user = await this.getUserFromClient(client);
        const token = await this.saveToken(user, client, scope);
        if(!token.user) {
            token.user = user;
        }
        if(!token.client) {
            token.client = client;
        }
        return token;
    };

    /**
     * Retrieve the user using client credentials.
     */

    getUserFromClient = async (client) => {
        const user = await this.service.getUserFromClient(client);
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
        const accessTokenExpiresAt = this.getAccessTokenExpiresAt(client, user, scope);
        const token = {
            accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt,
            scope: scopes
        };
        return await this.service.saveToken(token, client, user);
    };

}
