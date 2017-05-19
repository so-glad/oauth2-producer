'use strict';

/**
 * @author palmtale
 * @since 2017/5/19.
 */


class OAuthError extends Error {

    message = null;
    code = null;

    constructor(messageOrError, properties) {
        super();
        const message = messageOrError instanceof Error ? messageOrError.message : messageOrError;
        const error = messageOrError instanceof Error ? messageOrError : null;
        properties = properties || {};
        properties.code = properties.code || 500;
        if (error) {
            properties.inner = error;
        }
        // if (_.isEmpty(message)) {
        //     message = statuses[properties.code];
        // }
        this.message = message;
        this.code = this.status = this.statusCode = properties.code;
        for (const key in properties) {
            if (key !== 'code') {
                this[key] = properties[key];
            }
        }
        // Error.captureStackTrace(this, OAuthError);
    }
}

class ServerError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 503,
            name: 'server_error'
        }, properties));
    }

}

class AccessDeniedError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'access_denied'
        }, properties));
    }

}

class InsufficientScopeError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 403,
            name: 'insufficient_scope'
        }, properties));
    }

}

class InvalidArgumentError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 500,
            name: 'invalid_argument'
        }, properties));
    }

}

class InvalidClientError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'invalid_client'
        }, properties));
    }

}

class InvalidGrantError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'invalid_grant'
        }, properties));
    }

}

class InvalidRequestError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'invalid_request'
        }, properties));
    }

}

class InvalidScopeError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'invalid_scope'
        }, properties));
    }

}

class InvalidTokenError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 401,
            name: 'invalid_token'
        }, properties));
    }

}

class UnauthorizedClientError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'unauthorized_client'
        }, properties));
    }

}
class UnauthorizedRequestError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 401,
            name: 'unauthorized_request'
        }, properties));
    }

}
class UnsupportedGrantTypeError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'unsupported_grant_type'
        }, properties));
    }

}
class UnsupportedResponseTypeError extends OAuthError {

    constructor(message, properties) {
        super(message, Object.assign({
            code: 400,
            name: 'unsupported_response_type'
        }, properties));
    }

}

module.exports = {
    OAuthError: OAuthError,
    ServerError: ServerError,
    AccessDeniedError: AccessDeniedError,
    InsufficientScopeError: InsufficientScopeError,
    InvalidArgumentError: InvalidArgumentError,
    InvalidClientError: InvalidClientError,
    InvalidGrantError: InvalidGrantError,
    InvalidRequestError: InvalidRequestError,
    InvalidScopeError: InvalidScopeError,
    InvalidTokenError: InvalidTokenError,
    UnauthorizedClientError: UnauthorizedClientError,
    UnauthorizedRequestError: UnauthorizedRequestError,
    UnsupportedGrantTypeError: UnsupportedGrantTypeError,
    UnsupportedResponseTypeError: UnsupportedResponseTypeError
};

export default module.exports;