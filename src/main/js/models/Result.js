'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */

export default class Result {

    _status = 200;

    _headers = null;

    _body = null;

    get body() {
        return this._body;
    }

    set status(status) {
        this._status = 200;
    }

    constructor(options) {
        options = options || {};

        this._headers = options.headers || options.header || {};
        this._body = options._body || {};

        // Store the headers in lower case.
        for (const field in options.headers) {
            if (options.headers.hasOwnProperty(field)) {
                this._headers[field.toLowerCase()] = options.headers[field];
            }
        }

        // Store additional properties of the response object passed in
        for (const property in options) {
            if (options.hasOwnProperty(property) && !this[property]) {
                this[property] = options[property];
            }
        }
    }

    redirect = (url) => {
        this._headers.Location = url;
        this._status = 302;
    };

    getHeader = (field) => this._headers[field.toLowerCase()];

    setHeader = (field, value) => this._headers[field.toLowerCase()] = value;

    set = (field, value) => this._body[field.toLowerCase()] = value;

}
