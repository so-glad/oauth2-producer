'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import AbstractGrantType from './AbstractGrantType';
import {InvalidArgumentError, InvalidGrantError, InvalidRequestError} from '../models/OAuthError';

export default class ProxyGrantType extends AbstractGrantType {

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
        if(!options.service.exchangeAccessTokenByCode) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `exchangeAccessTokenByCode()`');
        }
        if(!options.service.getUserByAccessToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `getUserByAccessToken()`');
        }
    }

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

    getUser = async (params) => {
        const type = params.get('provider');
        if (params.get('error')) {
            return;
        }
        const code = params.get('code');
        const state = params.get('state');
        try {
            const access = await this.service.exchangeAccessTokenByCode(type, code, state);
            if (access.error) {
                throw access.error;
            } else {
                const user = await this.service.getUserByAccessToken(type, access.params());
                if(!user || !user.id){
                    throw new Error('Cannot get user via accessToken')
                }else {
                    return user;
                }
            }
        } catch (e) {
            throw e;
        }
    };

    saveToken = async (user, client, scope) => {
        const validatedScope = await this.validateScope(user, client, scope);
        const accessToken = await this.generateAccessToken(client, user, validatedScope);
        const refreshToken = await this.generateRefreshToken(client, user, validatedScope);
        const accessTokenExpiresAt = this.getAccessTokenExpiresAt();
        const refreshTokenExpiresAt = this.getRefreshTokenExpiresAt();

        const token = {
            accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt,
            refreshToken: refreshToken,
            refreshTokenExpiresAt: refreshTokenExpiresAt,
            scope: validatedScope
        };

        await this.service.saveToken(token, client, user);
    }

}