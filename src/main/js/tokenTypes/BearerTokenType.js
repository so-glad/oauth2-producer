'use strict';


import AccessToken from '../models/AccessToken';
import {InvalidArgumentError} from '../models/OAuthError';

export default class BearerTokenType {

    constructor(token) {
        if(!(token instanceof AccessToken)) {
            throw new InvalidArgumentError('Invalid argument token, should be type of \'AccessToken\'');
        }

        if (!token.accessToken) {
            throw new InvalidArgumentError('Missing parameter: `accessToken`');
        }

        this.accessToken = token.accessToken;
        this.accessTokenLifetime = token.accessTokenLifetime;
        this.refreshToken = token.refreshToken;
        this.scope = token.scope;
        this.user = token.user;
        this.client = token.client;
        if (token.customAttributes) {
            this.customAttributes = token.customAttributes;
        }
    }

    valueOf = () => {
        const object = {
            access_token: this.accessToken,
            token_type: 'Bearer'
        };

        if (this.accessTokenLifetime) {
            object.expires_in = this.accessTokenLifetime;
        }

        if (this.refreshToken) {
            object.refresh_token = this.refreshToken;
        }

        if (this.refreshTokenLifetime) {
            object.remind_in = this.refreshTokenLifetime;
        }

        if (this.scope) {
            object.scope = this.scope;
        }

        for (const key in this.customAttributes) {
            if (this.customAttributes.hasOwnProperty(key)) {
                object[key] = this.customAttributes[key];
            }
        }
        return object;
    };
}

