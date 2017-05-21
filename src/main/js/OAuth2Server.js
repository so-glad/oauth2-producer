'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import AuthorizeHandler from './handlers/AuthorizeHandler';
import AuthenticateHandler from './handlers/AuthenticateHandler';
import TokenHandler from './handlers/TokenHandler';

import {InvalidArgumentError} from './models/OAuthError';

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
        return await handler.handle(params);
    };

    token = async (params, options) => {
        options = Object.assign({
            accessTokenLifetime: 60 * 60,             // 1 hour.
            refreshTokenLifetime: 60 * 60 * 24 * 14,  // 2 weeks.
            allowExtendedTokenAttributes: false,
            requireClientAuthentication: {}           // defaults to true for all grant types
        }, this.options, options);

        const handler = new TokenHandler(options);
        return await handler.handle(params);
    };

    authorize = async (params, options) => {
        options = Object.assign({
            allowEmptyState: false,
            authorizationCodeLifetime: 5 * 60   // 5 minutes.
        }, this.options, options);

        const handler = new AuthorizeHandler(options);
        return await handler.handle(params);
    };
}