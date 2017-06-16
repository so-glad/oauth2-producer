'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import AuthorizeHandler from './handlers/AuthorizeHandler';
import AuthenticateHandler from './handlers/AuthenticateHandler';
import TokenHandler from './handlers/TokenHandler';

import {InvalidArgumentError} from './models/OAuthError';
import Parameter from './models/Parameter';
import Result from './models/Result';

export default class OAuth2Server {

    options = null;

    constructor(options) {
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `service`');
        }

        this.options = options;
    }

    authenticate = async (params, options) => {
        if (typeof options === 'string') {
            options = {scope: options};
        }

        options = Object.assign({
            addAcceptedScopesHeader: true,
            addAuthorizedScopesHeader: true
        }, this.options, options);
        const handler = new AuthenticateHandler(options);
        return await handler.handle(params instanceof Parameter ? params : new Parameter(params));
    };

    token = async (params, options) => {
        options = Object.assign({
            accessTokenLifetime: 60 * 60,             // 1 hour.
            refreshTokenLifetime: 60 * 60 * 24 * 14,  // 2 weeks.
            allowExtendedTokenAttributes: false,
            requireClientAuthentication: {}           // defaults to true for all grant types
        }, this.options, options);

        const handler = new TokenHandler(options);
        return await handler.handle(params instanceof Parameter ? params : new Parameter(params));
    };

    revoke = async (params, options) => {
        const opts = Object.assign({}, this.options, options);
        if (!opts.service.revokeToken) {
            throw new InvalidArgumentError('Invalid argument: service does not implement `revokeToken()`');
        }
        const token = params.accessToken ? params : params.params;
        const result = new Result();
        result.header('Cache-Control', 'no-store');
        result.header('Pragma', 'no-cache');
        try {
            const status = await opts.service.revokeToken(token);
            for(const i in status) {
                result.set(i, status[i]);
            }
            return result;
        } catch(e) {
            result.status = e.code;
            return result;
        }
    };

    authorize = async (params, options) => {
        options = Object.assign({
            allowEmptyState: false,
            authorizationCodeLifetime: 5 * 60   // 5 minutes.
        }, this.options, options);

        const handler = new AuthorizeHandler(options);
        return await handler.handle(params instanceof Parameter ? params : new Parameter(params));
    };
}