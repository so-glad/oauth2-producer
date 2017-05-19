'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


export default class OAuth2Server {

    options = null;

    constructor(options) {
        options = options || {};

        if (!options.service) {
            throw new InvalidArgumentError('Missing parameter: `model`');
        }

        this.options = options;
    }

    authenticate = async (request, response, options) => {
        if (typeof options === 'string') {
            options = {scope: options};
        }

        options = Object.assign({
            addAcceptedScopesHeader: true,
            addAuthorizedScopesHeader: true,
            allowBearerTokensInQueryString: false
        }, this.options, options);

        return await new AuthenticateHandler(options)
            .handle(request, response);
    };

    token = async (request, response, options) => {
        options = Object.assign({
            accessTokenLifetime: 60 * 60,             // 1 hour.
            refreshTokenLifetime: 60 * 60 * 24 * 14,  // 2 weeks.
            allowExtendedTokenAttributes: false,
            requireClientAuthentication: {}           // defaults to true for all grant types
        }, this.options, options);

        return await new TokenHandler(options)
            .handle(request, response);
    };

    authorize = async (request, response, options) => {
        options = Object.assign({
            allowEmptyState: false,
            authorizationCodeLifetime: 5 * 60   // 5 minutes.
        }, this.options, options);

        return await new AuthorizeHandler(options)
            .handle(request, response);
    };
}