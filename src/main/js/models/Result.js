'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */

export default class Result {

    _status = 200;

    _headers = {};

    _body = {};

    set status(status) {
        this._status = status;
    }

    get status() {
        return this._status;
    }

    get headers() {
        return this._headers;
    }

    get body() {
        return this._body;
    }

    set = (key, value) => this._body[key] = value;

    header = (key, value) => value ?
        (this._headers[key.toLowerCase()] = value) : this._headers[key.toLowerCase()];

    redirect = (url) => {
        this._headers.location = url;
        this._status = 302;
    };
}
