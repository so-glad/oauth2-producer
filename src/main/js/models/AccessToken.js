'use strict';

/**
 * Module dependencies.
 */

import BearerTokenType from '../tokenTypes/BearerTokenType';
import {InvalidArgumentError} from './OAuthError';


const modelAttributes = [
    'accessToken',
    'accessTokenExpiresAt',
    'refreshToken',
    'refreshTokenExpiresAt',
    'scope',
    'client',
    'user'
];

const tokenType = {
    Bearer: BearerTokenType
};

export default class TokenModel {

    accessToken = null;

    accessTokenExpiresAt = null;

    accessTokenLifetime = null;

    refreshToken = null;

    refreshTokenExpiresAt = null;

    refreshTokenLifetime = null;

    scope = null;

    client = null;

    user = null;

    customAttributes = {};

    constructor(data, options) {
        data = data || {};

        if (!data || !data.accessToken) {
            throw new InvalidArgumentError('Missing parameter: `accessToken`');
        }

        if (!data.client) {
            throw new InvalidArgumentError('Missing parameter: `client`');
        }

        if (!data.user) {
            throw new InvalidArgumentError('Missing parameter: `user`');
        }

        if (data.accessTokenExpiresAt && !(data.accessTokenExpiresAt instanceof Date)) {
            throw new InvalidArgumentError('Invalid parameter: `accessTokenExpiresAt`');
        }

        if (data.refreshTokenExpiresAt && !(data.refreshTokenExpiresAt instanceof Date)) {
            throw new InvalidArgumentError('Invalid parameter: `refreshTokenExpiresAt`');
        }

        this.accessToken = data.accessToken;
        this.accessTokenExpiresAt = data.accessTokenExpiresAt;
        this.refreshToken = data.refreshToken;
        this.refreshTokenExpiresAt = data.refreshTokenExpiresAt;
        this.scope = data.scope;
        this.client = data.client;
        this.user = data.user;

        if (options && options.allowExtendedTokenAttributes) {
            this.customAttributes = {};

            for (const key in data) {
                if (data.hasOwnProperty(key) && (modelAttributes.indexOf(key) < 0)) {
                    this.customAttributes[key] = data[key];
                }
            }
        }

        if (this.accessTokenExpiresAt) {
            this.accessTokenLifetime = Math.floor((this.accessTokenExpiresAt - new Date()) / 1000);
        }
        if (this.refreshTokenExpiresAt) {
            this.refreshTokenLifetime = Math.floor((this.refreshTokenExpiresAt - new Date()) / 1000);
        }
    }

    asType = (type) =>
        new (tokenType[type])(this);

    asBearerType = () => this.asType('Bearer');
}