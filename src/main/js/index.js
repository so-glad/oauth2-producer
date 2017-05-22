'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


import OAuth2Server from './OAuth2Server';
import OAuthError from './models/OAuthError';
import Parameter from './models/Parameter';

exports = module.exports = {
    OAuth2Server: OAuth2Server,
    OAuth2Errors: OAuthError,
    Parameter: Parameter
};

export default module.exports;