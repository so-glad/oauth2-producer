'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import AbstracatGrantType from './AbstractGrantType';


export default class ImplicitGrantType extends AbstracatGrantType {
    constructor(options) {
        super(options);
        if (!request) {
            throw new InvalidArgumentError('Missing parameter: `request`');
        }

        if (!client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }
    }

    handle = async (request, client) => {
        if (!request) {
            throw new InvalidArgumentError('Missing parameter: `request`');
        }

        if (!client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }

        var scope = this.getScope(request);
        const user = await this.getUser(request);
        this.saveToken(user, client, scope);
    };

    getUser = async (request) => {
        const type = request.params.provider;
        if (request.query.error) {
            this.logger.error(request.query);
            return;
        }
        const code = request.query.code;
        const state = request.query.state;
        let result = null;
        try {
            const access = await this.service.exchangeAccessTokenByCode(type, code, state);
            if (access.error) {
                this.logger.error(access.error);
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
            this.logger.error(e);
            throw e;
        }
    }

    saveToken = async (user, client, scope) => {
        const scope = await this.validateScope(user, client, scope);
        const accessToken = await this.generateAccessToken(client, user, scope);
        const refreshToken = await this.generateRefreshToken(client, user, scope);
        const accessTokenExpiresAt = await this.getAccessTokenExpiresAt();
        const refreshTokenExpiresAt = await this.getRefreshTokenExpiresAt();

        const token = {
            accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt,
            refreshToken: refreshToken,
            refreshTokenExpiresAt: refreshTokenExpiresAt,
            scope: scope
        };

        await this.service.saveToken(token, client, user);
    }

}