'use strict';

/**
 * Module dependencies.
 */

import url from 'url';
import {InvalidArgumentError} from './models/OAuthError';

/**
 * Constructor.
 */
export default class CodeResponseType {

    code = null;

    constructor(code) {
        if (!code) {
            throw new InvalidArgumentError('Missing parameter: `code`');
        }

        this.code = code;
    }

    /**
     * Build redirect uri.
     */

    buildRedirectUri = (redirectUri) => {
        if (!redirectUri) {
            throw new InvalidArgumentError('Missing parameter: `redirectUri`');
        }

        const uri = url.parse(redirectUri, true);

        uri.query.code = this.code;
        uri.search = null;

        return uri;
    };

}
