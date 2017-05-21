'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


export default class Parameter {

    _method = 'GET';

    _params = null;

    get method() {
        return this._method;
    }

    constructor(options) {
        options = options || {};

        this._params = Object.assign({}, options.headers, options.header,
            options.query, options.params, options. options.body);

        // Store additional properties of the request object passed in
        for (const property in options) {
            if (options.hasOwnProperty(property) && !this[property]) {
                this[property] = options[property];
            }
        }
    }

    get = (field) => {
        return this._params[field.toLowerCase()];
    };
}