"use strict";

function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

/**
 * Module dependencies.
 */
// eslint-disable-next-line node/no-deprecated-api
var _require = require('url'),
    parse = _require.parse,
    format = _require.format,
    resolve = _require.resolve;

var Stream = require('stream');

var https = require('https');

var http = require('http');

var fs = require('fs');

var zlib = require('zlib');

var util = require('util');

var qs = require('qs');

var mime = require('mime');

var methods = require('methods');

var FormData = require('form-data-mixed-dropbox');

var formidable = require('formidable');

var debug = require('debug')('superagent');

var CookieJar = require('cookiejar');

var semver = require('semver');

var safeStringify = require('fast-safe-stringify');

var utils = require('../utils');

var RequestBase = require('../request-base');

var _require2 = require('./unzip'),
    unzip = _require2.unzip;

var Response = require('./response');

var http2;
if (semver.gte(process.version, 'v10.10.0')) http2 = require('./http2wrapper');

function request(method, url) {
  // callback
  if (typeof url === 'function') {
    return new exports.Request('GET', method).end(url);
  } // url first


  if (arguments.length === 1) {
    return new exports.Request('GET', method);
  }

  return new exports.Request(method, url);
}

module.exports = request;
exports = module.exports;
/**
 * Expose `Request`.
 */

exports.Request = Request;
/**
 * Expose the agent function
 */

exports.agent = require('./agent');
/**
 * Noop.
 */

function noop() {}
/**
 * Expose `Response`.
 */


exports.Response = Response;
/**
 * Define "form" mime type.
 */

mime.define({
  'application/x-www-form-urlencoded': ['form', 'urlencoded', 'form-data']
}, true);
/**
 * Protocol map.
 */

exports.protocols = {
  'http:': http,
  'https:': https,
  'http2:': http2
};
/**
 * Default serialization map.
 *
 *     superagent.serialize['application/xml'] = function(obj){
 *       return 'generated xml here';
 *     };
 *
 */

exports.serialize = {
  'application/x-www-form-urlencoded': qs.stringify,
  'application/json': safeStringify
};
/**
 * Default parsers.
 *
 *     superagent.parse['application/xml'] = function(res, fn){
 *       fn(null, res);
 *     };
 *
 */

exports.parse = require('./parsers');
/**
 * Default buffering map. Can be used to set certain
 * response types to buffer/not buffer.
 *
 *     superagent.buffer['application/xml'] = true;
 */

exports.buffer = {};
/**
 * Initialize internal header tracking properties on a request instance.
 *
 * @param {Object} req the instance
 * @api private
 */

function _initHeaders(req) {
  req._header = {// coerces header names to lowercase
  };
  req.header = {// preserves header name case
  };
}
/**
 * Initialize a new `Request` with the given `method` and `url`.
 *
 * @param {String} method
 * @param {String|Object} url
 * @api public
 */


function Request(method, url) {
  Stream.call(this);
  if (typeof url !== 'string') url = format(url);
  this._enableHttp2 = Boolean(process.env.HTTP2_TEST); // internal only

  this._agent = false;
  this._formData = null;
  this.method = method;
  this.url = url;

  _initHeaders(this);

  this.writable = true;
  this._redirects = 0;
  this.redirects(method === 'HEAD' ? 0 : 5);
  this.cookies = '';
  this.qs = {};
  this._query = [];
  this.qsRaw = this._query; // Unused, for backwards compatibility only

  this._redirectList = [];
  this._streamRequest = false;
  this.once('end', this.clearTimeout.bind(this));
}
/**
 * Inherit from `Stream` (which inherits from `EventEmitter`).
 * Mixin `RequestBase`.
 */


util.inherits(Request, Stream); // eslint-disable-next-line new-cap

RequestBase(Request.prototype);
/**
 * Enable or Disable http2.
 *
 * Enable http2.
 *
 * ``` js
 * request.get('http://localhost/')
 *   .http2()
 *   .end(callback);
 *
 * request.get('http://localhost/')
 *   .http2(true)
 *   .end(callback);
 * ```
 *
 * Disable http2.
 *
 * ``` js
 * request = request.http2();
 * request.get('http://localhost/')
 *   .http2(false)
 *   .end(callback);
 * ```
 *
 * @param {Boolean} enable
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.http2 = function (bool) {
  if (exports.protocols['http2:'] === undefined) {
    throw new Error('superagent: this version of Node.js does not support http2');
  }

  this._enableHttp2 = bool === undefined ? true : bool;
  return this;
};
/**
 * Queue the given `file` as an attachment to the specified `field`,
 * with optional `options` (or filename).
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('field', Buffer.from('<b>Hello world</b>'), 'hello.html')
 *   .end(callback);
 * ```
 *
 * A filename may also be used:
 *
 * ``` js
 * request.post('http://localhost/upload')
 *   .attach('files', 'image.jpg')
 *   .end(callback);
 * ```
 *
 * @param {String} field
 * @param {String|fs.ReadStream|Buffer} file
 * @param {String|Object} options
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.attachWithDescription = function (field, file, options, textVal) {
  if (file) {
    if (this._data) {
      throw Error("superagent can't mix .send() and .attach()");
    }

    var o = options || {};

    if (typeof options === 'string') {
      o = {
        filename: options
      };
    }

    if (typeof file === 'string') {
      if (!o.filename) o.filename = file;
      debug('creating `fs.ReadStream` instance for file: %s', file);
      file = fs.createReadStream(file);
    } else if (!o.filename && file.path) {
      o.filename = file.path;
    }

    this._getFormData().appendWithJson(field, file, o, textVal);
  }

  return this;
};

Request.prototype.attach = function (field, file, options) {
  if (file) {
    if (this._data) {
      throw new Error("superagent can't mix .send() and .attach()");
    }

    var o = options || {};

    if (typeof options === 'string') {
      o = {
        filename: options
      };
    }

    if (typeof file === 'string') {
      if (!o.filename) o.filename = file;
      debug('creating `fs.ReadStream` instance for file: %s', file);
      file = fs.createReadStream(file);
    } else if (!o.filename && file.path) {
      o.filename = file.path;
    }

    this._getFormData().appendWithJson(field, file, o, textVal);
  }

  return this;
};

Request.prototype._getFormData = function () {
  var _this = this;

  if (!this._formData) {
    this._formData = new FormData();

    this._formData.on('error', function (err) {
      debug('FormData error', err);

      if (_this.called) {
        // The request has already finished and the callback was called.
        // Silently ignore the error.
        return;
      }

      _this.callback(err);

      _this.abort();
    });
  }

  return this._formData;
};
/**
 * Gets/sets the `Agent` to use for this HTTP request. The default (if this
 * function is not called) is to opt out of connection pooling (`agent: false`).
 *
 * @param {http.Agent} agent
 * @return {http.Agent}
 * @api public
 */


Request.prototype.agent = function (agent) {
  if (arguments.length === 0) return this._agent;
  this._agent = agent;
  return this;
};
/**
 * Set _Content-Type_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      request.post('/')
 *        .type('xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('application/json')
 *        .send(jsonstring)
 *        .end(callback);
 *
 * @param {String} type
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.type = function (type) {
  return this.set('Content-Type', type.includes('/') ? type : mime.getType(type));
};
/**
 * Set _Accept_ response header passed through `mime.getType()`.
 *
 * Examples:
 *
 *      superagent.types.json = 'application/json';
 *
 *      request.get('/agent')
 *        .accept('json')
 *        .end(callback);
 *
 *      request.get('/agent')
 *        .accept('application/json')
 *        .end(callback);
 *
 * @param {String} accept
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.accept = function (type) {
  return this.set('Accept', type.includes('/') ? type : mime.getType(type));
};
/**
 * Add query-string `val`.
 *
 * Examples:
 *
 *   request.get('/shoes')
 *     .query('size=10')
 *     .query({ color: 'blue' })
 *
 * @param {Object|String} val
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.query = function (val) {
  if (typeof val === 'string') {
    this._query.push(val);
  } else {
    Object.assign(this.qs, val);
  }

  return this;
};
/**
 * Write raw `data` / `encoding` to the socket.
 *
 * @param {Buffer|String} data
 * @param {String} encoding
 * @return {Boolean}
 * @api public
 */


Request.prototype.write = function (data, encoding) {
  var req = this.request();

  if (!this._streamRequest) {
    this._streamRequest = true;
  }

  return req.write(data, encoding);
};
/**
 * Pipe the request body to `stream`.
 *
 * @param {Stream} stream
 * @param {Object} options
 * @return {Stream}
 * @api public
 */


Request.prototype.pipe = function (stream, options) {
  this.piped = true; // HACK...

  this.buffer(false);
  this.end();
  return this._pipeContinue(stream, options);
};

Request.prototype._pipeContinue = function (stream, options) {
  var _this2 = this;

  this.req.once('response', function (res) {
    // redirect
    if (isRedirect(res.statusCode) && _this2._redirects++ !== _this2._maxRedirects) {
      return _this2._redirect(res) === _this2 ? _this2._pipeContinue(stream, options) : undefined;
    }

    _this2.res = res;

    _this2._emitResponse();

    if (_this2._aborted) return;

    if (_this2._shouldUnzip(res)) {
      var unzipObj = zlib.createUnzip();
      unzipObj.on('error', function (err) {
        if (err && err.code === 'Z_BUF_ERROR') {
          // unexpected end of file is ignored by browsers and curl
          stream.emit('end');
          return;
        }

        stream.emit('error', err);
      });
      res.pipe(unzipObj).pipe(stream, options);
    } else {
      res.pipe(stream, options);
    }

    res.once('end', function () {
      _this2.emit('end');
    });
  });
  return stream;
};
/**
 * Enable / disable buffering.
 *
 * @return {Boolean} [val]
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.buffer = function (val) {
  this._buffer = val !== false;
  return this;
};
/**
 * Redirect to `url
 *
 * @param {IncomingMessage} res
 * @return {Request} for chaining
 * @api private
 */


Request.prototype._redirect = function (res) {
  var url = res.headers.location;

  if (!url) {
    return this.callback(new Error('No location header for redirect'), res);
  }

  debug('redirect %s -> %s', this.url, url); // location

  url = resolve(this.url, url); // ensure the response is being consumed
  // this is required for Node v0.10+

  res.resume();
  var headers = this.req.getHeaders ? this.req.getHeaders() : this.req._headers;
  var changesOrigin = parse(url).host !== parse(this.url).host; // implementation of 302 following defacto standard

  if (res.statusCode === 301 || res.statusCode === 302) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin); // force GET

    this.method = this.method === 'HEAD' ? 'HEAD' : 'GET'; // clear data

    this._data = null;
  } // 303 is always GET


  if (res.statusCode === 303) {
    // strip Content-* related fields
    // in case of POST etc
    headers = utils.cleanHeader(headers, changesOrigin); // force method

    this.method = 'GET'; // clear data

    this._data = null;
  } // 307 preserves method
  // 308 preserves method


  delete headers.host;
  delete this.req;
  delete this._formData; // remove all add header except User-Agent

  _initHeaders(this); // redirect


  this._endCalled = false;
  this.url = url;
  this.qs = {};
  this._query.length = 0;
  this.set(headers);
  this.emit('redirect', res);

  this._redirectList.push(this.url);

  this.end(this._callback);
  return this;
};
/**
 * Set Authorization field value with `user` and `pass`.
 *
 * Examples:
 *
 *   .auth('tobi', 'learnboost')
 *   .auth('tobi:learnboost')
 *   .auth('tobi')
 *   .auth(accessToken, { type: 'bearer' })
 *
 * @param {String} user
 * @param {String} [pass]
 * @param {Object} [options] options with authorization type 'basic' or 'bearer' ('basic' is default)
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.auth = function (user, pass, options) {
  if (arguments.length === 1) pass = '';

  if (_typeof(pass) === 'object' && pass !== null) {
    // pass is optional and can be replaced with options
    options = pass;
    pass = '';
  }

  if (!options) {
    options = {
      type: 'basic'
    };
  }

  var encoder = function encoder(string) {
    return Buffer.from(string).toString('base64');
  };

  return this._auth(user, pass, options, encoder);
};
/**
 * Set the certificate authority option for https request.
 *
 * @param {Buffer | Array} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.ca = function (cert) {
  this._ca = cert;
  return this;
};
/**
 * Set the client certificate key option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.key = function (cert) {
  this._key = cert;
  return this;
};
/**
 * Set the key, certificate, and CA certs of the client in PFX or PKCS12 format.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.pfx = function (cert) {
  if (_typeof(cert) === 'object' && !Buffer.isBuffer(cert)) {
    this._pfx = cert.pfx;
    this._passphrase = cert.passphrase;
  } else {
    this._pfx = cert;
  }

  return this;
};
/**
 * Set the client certificate option for https request.
 *
 * @param {Buffer | String} cert
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.cert = function (cert) {
  this._cert = cert;
  return this;
};
/**
 * Do not reject expired or invalid TLS certs.
 * sets `rejectUnauthorized=true`. Be warned that this allows MITM attacks.
 *
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.disableTLSCerts = function () {
  this._disableTLSCerts = true;
  return this;
};
/**
 * Return an http[s] request.
 *
 * @return {OutgoingMessage}
 * @api private
 */
// eslint-disable-next-line complexity


Request.prototype.request = function () {
  var _this3 = this;

  if (this.req) return this.req;
  var options = {};

  try {
    var query = qs.stringify(this.qs, {
      indices: false,
      strictNullHandling: true
    });

    if (query) {
      this.qs = {};

      this._query.push(query);
    }

    this._finalizeQueryString();
  } catch (err) {
    return this.emit('error', err);
  }

  var url = this.url;
  var retries = this._retries; // Capture backticks as-is from the final query string built above.
  // Note: this'll only find backticks entered in req.query(String)
  // calls, because qs.stringify unconditionally encodes backticks.

  var queryStringBackticks;

  if (url.includes('`')) {
    var queryStartIndex = url.indexOf('?');

    if (queryStartIndex !== -1) {
      var queryString = url.slice(queryStartIndex + 1);
      queryStringBackticks = queryString.match(/`|%60/g);
    }
  } // default to http://


  if (url.indexOf('http') !== 0) url = "http://".concat(url);
  url = parse(url); // See https://github.com/visionmedia/superagent/issues/1367

  if (queryStringBackticks) {
    var i = 0;
    url.query = url.query.replace(/%60/g, function () {
      return queryStringBackticks[i++];
    });
    url.search = "?".concat(url.query);
    url.path = url.pathname + url.search;
  } // support unix sockets


  if (/^https?\+unix:/.test(url.protocol) === true) {
    // get the protocol
    url.protocol = "".concat(url.protocol.split('+')[0], ":"); // get the socket, path

    var unixParts = url.path.match(/^([^/]+)(.+)$/);
    options.socketPath = unixParts[1].replace(/%2F/g, '/');
    url.path = unixParts[2];
  } // Override IP address of a hostname


  if (this._connectOverride) {
    var _url = url,
        hostname = _url.hostname;
    var match = hostname in this._connectOverride ? this._connectOverride[hostname] : this._connectOverride['*'];

    if (match) {
      // backup the real host
      if (!this._header.host) {
        this.set('host', url.host);
      }

      var newHost;
      var newPort;

      if (_typeof(match) === 'object') {
        newHost = match.host;
        newPort = match.port;
      } else {
        newHost = match;
        newPort = url.port;
      } // wrap [ipv6]


      url.host = /:/.test(newHost) ? "[".concat(newHost, "]") : newHost;

      if (newPort) {
        url.host += ":".concat(newPort);
        url.port = newPort;
      }

      url.hostname = newHost;
    }
  } // options


  options.method = this.method;
  options.port = url.port;
  options.path = url.path;
  options.host = url.hostname;
  options.ca = this._ca;
  options.key = this._key;
  options.pfx = this._pfx;
  options.cert = this._cert;
  options.passphrase = this._passphrase;
  options.agent = this._agent;
  options.rejectUnauthorized = typeof this._disableTLSCerts === 'boolean' ? !this._disableTLSCerts : process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0'; // Allows request.get('https://1.2.3.4/').set('Host', 'example.com')

  if (this._header.host) {
    options.servername = this._header.host.replace(/:\d+$/, '');
  }

  if (this._trustLocalhost && /^(?:localhost|127\.0\.0\.\d+|(0*:)+:0*1)$/.test(url.hostname)) {
    options.rejectUnauthorized = false;
  } // initiate request


  var mod = this._enableHttp2 ? exports.protocols['http2:'].setProtocol(url.protocol) : exports.protocols[url.protocol]; // request

  this.req = mod.request(options);
  var req = this.req; // set tcp no delay

  req.setNoDelay(true);

  if (options.method !== 'HEAD') {
    req.setHeader('Accept-Encoding', 'gzip, deflate');
  }

  this.protocol = url.protocol;
  this.host = url.host; // expose events

  req.once('drain', function () {
    _this3.emit('drain');
  });
  req.on('error', function (err) {
    // flag abortion here for out timeouts
    // because node will emit a faux-error "socket hang up"
    // when request is aborted before a connection is made
    if (_this3._aborted) return; // if not the same, we are in the **old** (cancelled) request,
    // so need to continue (same as for above)

    if (_this3._retries !== retries) return; // if we've received a response then we don't want to let
    // an error in the request blow up the response

    if (_this3.response) return;

    _this3.callback(err);
  }); // auth

  if (url.auth) {
    var auth = url.auth.split(':');
    this.auth(auth[0], auth[1]);
  }

  if (this.username && this.password) {
    this.auth(this.username, this.password);
  }

  for (var key in this.header) {
    if (Object.prototype.hasOwnProperty.call(this.header, key)) req.setHeader(key, this.header[key]);
  } // add cookies


  if (this.cookies) {
    if (Object.prototype.hasOwnProperty.call(this._header, 'cookie')) {
      // merge
      var tmpJar = new CookieJar.CookieJar();
      tmpJar.setCookies(this._header.cookie.split(';'));
      tmpJar.setCookies(this.cookies.split(';'));
      req.setHeader('Cookie', tmpJar.getCookies(CookieJar.CookieAccessInfo.All).toValueString());
    } else {
      req.setHeader('Cookie', this.cookies);
    }
  }

  return req;
};
/**
 * Invoke the callback with `err` and `res`
 * and handle arity check.
 *
 * @param {Error} err
 * @param {Response} res
 * @api private
 */


Request.prototype.callback = function (err, res) {
  if (this._shouldRetry(err, res)) {
    return this._retry();
  } // Avoid the error which is emitted from 'socket hang up' to cause the fn undefined error on JS runtime.


  var fn = this._callback || noop;
  this.clearTimeout();
  if (this.called) return console.warn('superagent: double callback bug');
  this.called = true;

  if (!err) {
    try {
      if (!this._isResponseOK(res)) {
        var msg = 'Unsuccessful HTTP response';

        if (res) {
          msg = http.STATUS_CODES[res.status] || msg;
        }

        err = new Error(msg);
        err.status = res ? res.status : undefined;
      }
    } catch (err_) {
      err = err_;
    }
  } // It's important that the callback is called outside try/catch
  // to avoid double callback


  if (!err) {
    return fn(null, res);
  }

  err.response = res;
  if (this._maxRetries) err.retries = this._retries - 1; // only emit error event if there is a listener
  // otherwise we assume the callback to `.end()` will get the error

  if (err && this.listeners('error').length > 0) {
    this.emit('error', err);
  }

  fn(err, res);
};
/**
 * Check if `obj` is a host object,
 *
 * @param {Object} obj host object
 * @return {Boolean} is a host object
 * @api private
 */


Request.prototype._isHost = function (obj) {
  return Buffer.isBuffer(obj) || obj instanceof Stream || obj instanceof FormData;
};
/**
 * Initiate request, invoking callback `fn(err, res)`
 * with an instanceof `Response`.
 *
 * @param {Function} fn
 * @return {Request} for chaining
 * @api public
 */


Request.prototype._emitResponse = function (body, files) {
  var response = new Response(this);
  this.response = response;
  response.redirects = this._redirectList;

  if (undefined !== body) {
    response.body = body;
  }

  response.files = files;

  if (this._endCalled) {
    response.pipe = function () {
      throw new Error("end() has already been called, so it's too late to start piping");
    };
  }

  this.emit('response', response);
  return response;
};

Request.prototype.end = function (fn) {
  this.request();
  debug('%s %s', this.method, this.url);

  if (this._endCalled) {
    throw new Error('.end() was called twice. This is not supported in superagent');
  }

  this._endCalled = true; // store callback

  this._callback = fn || noop;

  this._end();
};

Request.prototype._end = function () {
  var _this4 = this;

  if (this._aborted) return this.callback(new Error('The request has been aborted even before .end() was called'));
  var data = this._data;
  var req = this.req;
  var method = this.method;

  this._setTimeouts(); // body


  if (method !== 'HEAD' && !req._headerSent) {
    // serialize stuff
    if (typeof data !== 'string') {
      var contentType = req.getHeader('Content-Type'); // Parse out just the content type from the header (ignore the charset)

      if (contentType) contentType = contentType.split(';')[0];
      var serialize = this._serializer || exports.serialize[contentType];

      if (!serialize && isJSON(contentType)) {
        serialize = exports.serialize['application/json'];
      }

      if (serialize) data = serialize(data);
    } // content-length


    if (data && !req.getHeader('Content-Length')) {
      req.setHeader('Content-Length', Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data));
    }
  } // response
  // eslint-disable-next-line complexity


  req.once('response', function (res) {
    debug('%s %s -> %s', _this4.method, _this4.url, res.statusCode);

    if (_this4._responseTimeoutTimer) {
      clearTimeout(_this4._responseTimeoutTimer);
    }

    if (_this4.piped) {
      return;
    }

    var max = _this4._maxRedirects;
    var mime = utils.type(res.headers['content-type'] || '') || 'text/plain';
    var type = mime.split('/')[0];
    if (type) type = type.toLowerCase().trim();
    var multipart = type === 'multipart';
    var redirect = isRedirect(res.statusCode);
    var responseType = _this4._responseType;
    _this4.res = res; // redirect

    if (redirect && _this4._redirects++ !== max) {
      return _this4._redirect(res);
    }

    if (_this4.method === 'HEAD') {
      _this4.emit('end');

      _this4.callback(null, _this4._emitResponse());

      return;
    } // zlib support


    if (_this4._shouldUnzip(res)) {
      unzip(req, res);
    }

    var buffer = _this4._buffer;

    if (buffer === undefined && mime in exports.buffer) {
      buffer = Boolean(exports.buffer[mime]);
    }

    var parser = _this4._parser;

    if (undefined === buffer) {
      if (parser) {
        console.warn("A custom superagent parser has been set, but buffering strategy for the parser hasn't been configured. Call `req.buffer(true or false)` or set `superagent.buffer[mime] = true or false`");
        buffer = true;
      }
    }

    if (!parser) {
      if (responseType) {
        parser = exports.parse.image; // It's actually a generic Buffer

        buffer = true;
      } else if (multipart) {
        var form = new formidable.IncomingForm();
        parser = form.parse.bind(form);
        buffer = true;
      } else if (isImageOrVideo(mime)) {
        parser = exports.parse.image;
        buffer = true; // For backwards-compatibility buffering default is ad-hoc MIME-dependent
      } else if (exports.parse[mime]) {
        parser = exports.parse[mime];
      } else if (type === 'text') {
        parser = exports.parse.text;
        buffer = buffer !== false; // everyone wants their own white-labeled json
      } else if (isJSON(mime)) {
        parser = exports.parse['application/json'];
        buffer = buffer !== false;
      } else if (buffer) {
        parser = exports.parse.text;
      } else if (undefined === buffer) {
        parser = exports.parse.image; // It's actually a generic Buffer

        buffer = true;
      }
    } // by default only buffer text/*, json and messed up thing from hell


    if (undefined === buffer && isText(mime) || isJSON(mime)) {
      buffer = true;
    }

    _this4._resBuffered = buffer;
    var parserHandlesEnd = false;

    if (buffer) {
      // Protectiona against zip bombs and other nuisance
      var responseBytesLeft = _this4._maxResponseSize || 200000000;
      res.on('data', function (buf) {
        responseBytesLeft -= buf.byteLength || buf.length;

        if (responseBytesLeft < 0) {
          // This will propagate through error event
          var err = new Error('Maximum response size reached');
          err.code = 'ETOOLARGE'; // Parsers aren't required to observe error event,
          // so would incorrectly report success

          parserHandlesEnd = false; // Will emit error event

          res.destroy(err);
        }
      });
    }

    if (parser) {
      try {
        // Unbuffered parsers are supposed to emit response early,
        // which is weird BTW, because response.body won't be there.
        parserHandlesEnd = buffer;
        parser(res, function (err, obj, files) {
          if (_this4.timedout) {
            // Timeout has already handled all callbacks
            return;
          } // Intentional (non-timeout) abort is supposed to preserve partial response,
          // even if it doesn't parse.


          if (err && !_this4._aborted) {
            return _this4.callback(err);
          }

          if (parserHandlesEnd) {
            _this4.emit('end');

            _this4.callback(null, _this4._emitResponse(obj, files));
          }
        });
      } catch (err) {
        _this4.callback(err);

        return;
      }
    }

    _this4.res = res; // unbuffered

    if (!buffer) {
      debug('unbuffered %s %s', _this4.method, _this4.url);

      _this4.callback(null, _this4._emitResponse());

      if (multipart) return; // allow multipart to handle end event

      res.once('end', function () {
        debug('end %s %s', _this4.method, _this4.url);

        _this4.emit('end');
      });
      return;
    } // terminating events


    res.once('error', function (err) {
      parserHandlesEnd = false;

      _this4.callback(err, null);
    });
    if (!parserHandlesEnd) res.once('end', function () {
      debug('end %s %s', _this4.method, _this4.url); // TODO: unless buffering emit earlier to stream

      _this4.emit('end');

      _this4.callback(null, _this4._emitResponse());
    });
  });
  this.emit('request', this);

  var getProgressMonitor = function getProgressMonitor() {
    var lengthComputable = true;
    var total = req.getHeader('Content-Length');
    var loaded = 0;
    var progress = new Stream.Transform();

    progress._transform = function (chunk, encoding, cb) {
      loaded += chunk.length;

      _this4.emit('progress', {
        direction: 'upload',
        lengthComputable: lengthComputable,
        loaded: loaded,
        total: total
      });

      cb(null, chunk);
    };

    return progress;
  };

  var bufferToChunks = function bufferToChunks(buffer) {
    var chunkSize = 16 * 1024; // default highWaterMark value

    var chunking = new Stream.Readable();
    var totalLength = buffer.length;
    var remainder = totalLength % chunkSize;
    var cutoff = totalLength - remainder;

    for (var i = 0; i < cutoff; i += chunkSize) {
      var chunk = buffer.slice(i, i + chunkSize);
      chunking.push(chunk);
    }

    if (remainder > 0) {
      var remainderBuffer = buffer.slice(-remainder);
      chunking.push(remainderBuffer);
    }

    chunking.push(null); // no more data

    return chunking;
  }; // if a FormData instance got created, then we send that as the request body


  var formData = this._formData;

  if (formData) {
    // set headers
    var headers = formData.getHeaders();

    for (var i in headers) {
      if (Object.prototype.hasOwnProperty.call(headers, i)) {
        debug('setting FormData header: "%s: %s"', i, headers[i]);
        req.setHeader(i, headers[i]);
      }
    } // attempt to get "Content-Length" header


    formData.getLength(function (err, length) {
      // TODO: Add chunked encoding when no length (if err)
      if (err) debug('formData.getLength had error', err, length);
      debug('got FormData Content-Length: %s', length);

      if (typeof length === 'number') {
        req.setHeader('Content-Length', length);
      }

      formData.pipe(getProgressMonitor()).pipe(req);
    });
  } else if (Buffer.isBuffer(data)) {
    bufferToChunks(data).pipe(getProgressMonitor()).pipe(req);
  } else {
    req.end(data);
  }
}; // Check whether response has a non-0-sized gzip-encoded body


Request.prototype._shouldUnzip = function (res) {
  if (res.statusCode === 204 || res.statusCode === 304) {
    // These aren't supposed to have any body
    return false;
  } // header content is a string, and distinction between 0 and no information is crucial


  if (res.headers['content-length'] === '0') {
    // We know that the body is empty (unfortunately, this check does not cover chunked encoding)
    return false;
  } // console.log(res);


  return /^\s*(?:deflate|gzip)\s*$/.test(res.headers['content-encoding']);
};
/**
 * Overrides DNS for selected hostnames. Takes object mapping hostnames to IP addresses.
 *
 * When making a request to a URL with a hostname exactly matching a key in the object,
 * use the given IP address to connect, instead of using DNS to resolve the hostname.
 *
 * A special host `*` matches every hostname (keep redirects in mind!)
 *
 *      request.connect({
 *        'test.example.com': '127.0.0.1',
 *        'ipv6.example.com': '::1',
 *      })
 */


Request.prototype.connect = function (connectOverride) {
  if (typeof connectOverride === 'string') {
    this._connectOverride = {
      '*': connectOverride
    };
  } else if (_typeof(connectOverride) === 'object') {
    this._connectOverride = connectOverride;
  } else {
    this._connectOverride = undefined;
  }

  return this;
};

Request.prototype.trustLocalhost = function (toggle) {
  this._trustLocalhost = toggle === undefined ? true : toggle;
  return this;
}; // generate HTTP verb methods


if (!methods.includes('del')) {
  // create a copy so we don't cause conflicts with
  // other packages using the methods package and
  // npm 3.x
  methods = methods.slice(0);
  methods.push('del');
}

methods.forEach(function (method) {
  var name = method;
  method = method === 'del' ? 'delete' : method;
  method = method.toUpperCase();

  request[name] = function (url, data, fn) {
    var req = request(method, url);

    if (typeof data === 'function') {
      fn = data;
      data = null;
    }

    if (data) {
      if (method === 'GET' || method === 'HEAD') {
        req.query(data);
      } else {
        req.send(data);
      }
    }

    if (fn) req.end(fn);
    return req;
  };
});
/**
 * Check if `mime` is text and should be buffered.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api public
 */

function isText(mime) {
  var parts = mime.split('/');
  var type = parts[0];
  if (type) type = type.toLowerCase().trim();
  var subtype = parts[1];
  if (subtype) subtype = subtype.toLowerCase().trim();
  return type === 'text' || subtype === 'x-www-form-urlencoded';
}

function isImageOrVideo(mime) {
  var type = mime.split('/')[0];
  if (type) type = type.toLowerCase().trim();
  return type === 'image' || type === 'video';
}
/**
 * Check if `mime` is json or has +json structured syntax suffix.
 *
 * @param {String} mime
 * @return {Boolean}
 * @api private
 */


function isJSON(mime) {
  // should match /json or +json
  // but not /json-seq
  return /[/+]json($|[^-\w])/i.test(mime);
}
/**
 * Check if we should follow the redirect `code`.
 *
 * @param {Number} code
 * @return {Boolean}
 * @api private
 */


function isRedirect(code) {
  return [301, 302, 303, 305, 307, 308].includes(code);
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL2luZGV4LmpzIl0sIm5hbWVzIjpbInJlcXVpcmUiLCJwYXJzZSIsImZvcm1hdCIsInJlc29sdmUiLCJTdHJlYW0iLCJodHRwcyIsImh0dHAiLCJmcyIsInpsaWIiLCJ1dGlsIiwicXMiLCJtaW1lIiwibWV0aG9kcyIsIkZvcm1EYXRhIiwiZm9ybWlkYWJsZSIsImRlYnVnIiwiQ29va2llSmFyIiwic2VtdmVyIiwic2FmZVN0cmluZ2lmeSIsInV0aWxzIiwiUmVxdWVzdEJhc2UiLCJ1bnppcCIsIlJlc3BvbnNlIiwiaHR0cDIiLCJndGUiLCJwcm9jZXNzIiwidmVyc2lvbiIsInJlcXVlc3QiLCJtZXRob2QiLCJ1cmwiLCJleHBvcnRzIiwiUmVxdWVzdCIsImVuZCIsImFyZ3VtZW50cyIsImxlbmd0aCIsIm1vZHVsZSIsImFnZW50Iiwibm9vcCIsImRlZmluZSIsInByb3RvY29scyIsInNlcmlhbGl6ZSIsInN0cmluZ2lmeSIsImJ1ZmZlciIsIl9pbml0SGVhZGVycyIsInJlcSIsIl9oZWFkZXIiLCJoZWFkZXIiLCJjYWxsIiwiX2VuYWJsZUh0dHAyIiwiQm9vbGVhbiIsImVudiIsIkhUVFAyX1RFU1QiLCJfYWdlbnQiLCJfZm9ybURhdGEiLCJ3cml0YWJsZSIsIl9yZWRpcmVjdHMiLCJyZWRpcmVjdHMiLCJjb29raWVzIiwiX3F1ZXJ5IiwicXNSYXciLCJfcmVkaXJlY3RMaXN0IiwiX3N0cmVhbVJlcXVlc3QiLCJvbmNlIiwiY2xlYXJUaW1lb3V0IiwiYmluZCIsImluaGVyaXRzIiwicHJvdG90eXBlIiwiYm9vbCIsInVuZGVmaW5lZCIsIkVycm9yIiwiYXR0YWNoV2l0aERlc2NyaXB0aW9uIiwiZmllbGQiLCJmaWxlIiwib3B0aW9ucyIsInRleHRWYWwiLCJfZGF0YSIsIm8iLCJmaWxlbmFtZSIsImNyZWF0ZVJlYWRTdHJlYW0iLCJwYXRoIiwiX2dldEZvcm1EYXRhIiwiYXBwZW5kV2l0aEpzb24iLCJhdHRhY2giLCJvbiIsImVyciIsImNhbGxlZCIsImNhbGxiYWNrIiwiYWJvcnQiLCJ0eXBlIiwic2V0IiwiaW5jbHVkZXMiLCJnZXRUeXBlIiwiYWNjZXB0IiwicXVlcnkiLCJ2YWwiLCJwdXNoIiwiT2JqZWN0IiwiYXNzaWduIiwid3JpdGUiLCJkYXRhIiwiZW5jb2RpbmciLCJwaXBlIiwic3RyZWFtIiwicGlwZWQiLCJfcGlwZUNvbnRpbnVlIiwicmVzIiwiaXNSZWRpcmVjdCIsInN0YXR1c0NvZGUiLCJfbWF4UmVkaXJlY3RzIiwiX3JlZGlyZWN0IiwiX2VtaXRSZXNwb25zZSIsIl9hYm9ydGVkIiwiX3Nob3VsZFVuemlwIiwidW56aXBPYmoiLCJjcmVhdGVVbnppcCIsImNvZGUiLCJlbWl0IiwiX2J1ZmZlciIsImhlYWRlcnMiLCJsb2NhdGlvbiIsInJlc3VtZSIsImdldEhlYWRlcnMiLCJfaGVhZGVycyIsImNoYW5nZXNPcmlnaW4iLCJob3N0IiwiY2xlYW5IZWFkZXIiLCJfZW5kQ2FsbGVkIiwiX2NhbGxiYWNrIiwiYXV0aCIsInVzZXIiLCJwYXNzIiwiZW5jb2RlciIsInN0cmluZyIsIkJ1ZmZlciIsImZyb20iLCJ0b1N0cmluZyIsIl9hdXRoIiwiY2EiLCJjZXJ0IiwiX2NhIiwia2V5IiwiX2tleSIsInBmeCIsImlzQnVmZmVyIiwiX3BmeCIsIl9wYXNzcGhyYXNlIiwicGFzc3BocmFzZSIsIl9jZXJ0IiwiZGlzYWJsZVRMU0NlcnRzIiwiX2Rpc2FibGVUTFNDZXJ0cyIsImluZGljZXMiLCJzdHJpY3ROdWxsSGFuZGxpbmciLCJfZmluYWxpemVRdWVyeVN0cmluZyIsInJldHJpZXMiLCJfcmV0cmllcyIsInF1ZXJ5U3RyaW5nQmFja3RpY2tzIiwicXVlcnlTdGFydEluZGV4IiwiaW5kZXhPZiIsInF1ZXJ5U3RyaW5nIiwic2xpY2UiLCJtYXRjaCIsImkiLCJyZXBsYWNlIiwic2VhcmNoIiwicGF0aG5hbWUiLCJ0ZXN0IiwicHJvdG9jb2wiLCJzcGxpdCIsInVuaXhQYXJ0cyIsInNvY2tldFBhdGgiLCJfY29ubmVjdE92ZXJyaWRlIiwiaG9zdG5hbWUiLCJuZXdIb3N0IiwibmV3UG9ydCIsInBvcnQiLCJyZWplY3RVbmF1dGhvcml6ZWQiLCJOT0RFX1RMU19SRUpFQ1RfVU5BVVRIT1JJWkVEIiwic2VydmVybmFtZSIsIl90cnVzdExvY2FsaG9zdCIsIm1vZCIsInNldFByb3RvY29sIiwic2V0Tm9EZWxheSIsInNldEhlYWRlciIsInJlc3BvbnNlIiwidXNlcm5hbWUiLCJwYXNzd29yZCIsImhhc093blByb3BlcnR5IiwidG1wSmFyIiwic2V0Q29va2llcyIsImNvb2tpZSIsImdldENvb2tpZXMiLCJDb29raWVBY2Nlc3NJbmZvIiwiQWxsIiwidG9WYWx1ZVN0cmluZyIsIl9zaG91bGRSZXRyeSIsIl9yZXRyeSIsImZuIiwiY29uc29sZSIsIndhcm4iLCJfaXNSZXNwb25zZU9LIiwibXNnIiwiU1RBVFVTX0NPREVTIiwic3RhdHVzIiwiZXJyXyIsIl9tYXhSZXRyaWVzIiwibGlzdGVuZXJzIiwiX2lzSG9zdCIsIm9iaiIsImJvZHkiLCJmaWxlcyIsIl9lbmQiLCJfc2V0VGltZW91dHMiLCJfaGVhZGVyU2VudCIsImNvbnRlbnRUeXBlIiwiZ2V0SGVhZGVyIiwiX3NlcmlhbGl6ZXIiLCJpc0pTT04iLCJieXRlTGVuZ3RoIiwiX3Jlc3BvbnNlVGltZW91dFRpbWVyIiwibWF4IiwidG9Mb3dlckNhc2UiLCJ0cmltIiwibXVsdGlwYXJ0IiwicmVkaXJlY3QiLCJyZXNwb25zZVR5cGUiLCJfcmVzcG9uc2VUeXBlIiwicGFyc2VyIiwiX3BhcnNlciIsImltYWdlIiwiZm9ybSIsIkluY29taW5nRm9ybSIsImlzSW1hZ2VPclZpZGVvIiwidGV4dCIsImlzVGV4dCIsIl9yZXNCdWZmZXJlZCIsInBhcnNlckhhbmRsZXNFbmQiLCJyZXNwb25zZUJ5dGVzTGVmdCIsIl9tYXhSZXNwb25zZVNpemUiLCJidWYiLCJkZXN0cm95IiwidGltZWRvdXQiLCJnZXRQcm9ncmVzc01vbml0b3IiLCJsZW5ndGhDb21wdXRhYmxlIiwidG90YWwiLCJsb2FkZWQiLCJwcm9ncmVzcyIsIlRyYW5zZm9ybSIsIl90cmFuc2Zvcm0iLCJjaHVuayIsImNiIiwiZGlyZWN0aW9uIiwiYnVmZmVyVG9DaHVua3MiLCJjaHVua1NpemUiLCJjaHVua2luZyIsIlJlYWRhYmxlIiwidG90YWxMZW5ndGgiLCJyZW1haW5kZXIiLCJjdXRvZmYiLCJyZW1haW5kZXJCdWZmZXIiLCJmb3JtRGF0YSIsImdldExlbmd0aCIsImNvbm5lY3QiLCJjb25uZWN0T3ZlcnJpZGUiLCJ0cnVzdExvY2FsaG9zdCIsInRvZ2dsZSIsImZvckVhY2giLCJuYW1lIiwidG9VcHBlckNhc2UiLCJzZW5kIiwicGFydHMiLCJzdWJ0eXBlIl0sIm1hcHBpbmdzIjoiOzs7O0FBQUE7QUFDQTtBQUNBO0FBRUE7ZUFDbUNBLE9BQU8sQ0FBQyxLQUFELEM7SUFBbENDLEssWUFBQUEsSztJQUFPQyxNLFlBQUFBLE07SUFBUUMsTyxZQUFBQSxPOztBQUN2QixJQUFNQyxNQUFNLEdBQUdKLE9BQU8sQ0FBQyxRQUFELENBQXRCOztBQUNBLElBQU1LLEtBQUssR0FBR0wsT0FBTyxDQUFDLE9BQUQsQ0FBckI7O0FBQ0EsSUFBTU0sSUFBSSxHQUFHTixPQUFPLENBQUMsTUFBRCxDQUFwQjs7QUFDQSxJQUFNTyxFQUFFLEdBQUdQLE9BQU8sQ0FBQyxJQUFELENBQWxCOztBQUNBLElBQU1RLElBQUksR0FBR1IsT0FBTyxDQUFDLE1BQUQsQ0FBcEI7O0FBQ0EsSUFBTVMsSUFBSSxHQUFHVCxPQUFPLENBQUMsTUFBRCxDQUFwQjs7QUFDQSxJQUFNVSxFQUFFLEdBQUdWLE9BQU8sQ0FBQyxJQUFELENBQWxCOztBQUNBLElBQU1XLElBQUksR0FBR1gsT0FBTyxDQUFDLE1BQUQsQ0FBcEI7O0FBQ0EsSUFBSVksT0FBTyxHQUFHWixPQUFPLENBQUMsU0FBRCxDQUFyQjs7QUFDQSxJQUFNYSxRQUFRLEdBQUdiLE9BQU8sQ0FBQyx5QkFBRCxDQUF4Qjs7QUFDQSxJQUFNYyxVQUFVLEdBQUdkLE9BQU8sQ0FBQyxZQUFELENBQTFC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ZW50IjpbIi8qKlxuICogTW9kdWxlIGRlcGVuZGVuY2llcy5cbiAqL1xuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm9kZS9uby1kZXByZWNhdGVkLWFwaVxuY29uc3QgeyBwYXJzZSwgZm9ybWF0LCByZXNvbHZlIH0gPSByZXF1aXJlKCd1cmwnKTtcbmNvbnN0IFN0cmVhbSA9IHJlcXVpcmUoJ3N0cmVhbScpO1xuY29uc3QgaHR0cHMgPSByZXF1aXJlKCdodHRwcycpO1xuY29uc3QgaHR0cCA9IHJlcXVpcmUoJ2h0dHAnKTtcbmNvbnN0IGZzID0gcmVxdWlyZSgnZnMnKTtcbmNvbnN0IHpsaWIgPSByZXF1aXJlKCd6bGliJyk7XG5jb25zdCB1dGlsID0gcmVxdWlyZSgndXRpbCcpO1xuY29uc3QgcXMgPSByZXF1aXJlKCdxcycpO1xuY29uc3QgbWltZSA9IHJlcXVpcmUoJ21pbWUnKTtcbmxldCBtZXRob2RzID0gcmVxdWlyZSgnbWV0aG9kcycpO1xuY29uc3QgRm9ybURhdGEgPSByZXF1aXJlKCdmb3JtLWRhdGEtbWl4ZWQtZHJvcGJveCcpO1xuY29uc3QgZm9ybWlkYWJsZSA9IHJlcXVpcmUoJ2Zvcm1pZGFibGUnKTtcbmNvbnN0IGRlYnVnID0gcmVxdWlyZSgnZGVidWcnKSgnc3VwZXJhZ2VudCcpO1xuY29uc3QgQ29va2llSmFyID0gcmVxdWlyZSgnY29va2llamFyJyk7XG5jb25zdCBzZW12ZXIgPSByZXF1aXJlKCdzZW12ZXInKTtcbmNvbnN0IHNhZmVTdHJpbmdpZnkgPSByZXF1aXJlKCdmYXN0LXNhZmUtc3RyaW5naWZ5Jyk7XG5cbmNvbnN0IHV0aWxzID0gcmVxdWlyZSgnLi4vdXRpbHMnKTtcbmNvbnN0IFJlcXVlc3RCYXNlID0gcmVxdWlyZSgnLi4vcmVxdWVzdC1iYXNlJyk7XG5jb25zdCB7IHVuemlwIH0gPSByZXF1aXJlKCcuL3VuemlwJyk7XG5jb25zdCBSZXNwb25zZSA9IHJlcXVpcmUoJy4vcmVzcG9uc2UnKTtcblxubGV0IGh0dHAyO1xuXG5pZiAoc2VtdmVyLmd0ZShwcm9jZXNzLnZlcnNpb24sICd2MTAuMTAuMCcpKSBodHRwMiA9IHJlcXVpcmUoJy4vaHR0cDJ3cmFwcGVyJyk7XG5cbmZ1bmN0aW9uIHJlcXVlc3QobWV0aG9kLCB1cmwpIHtcbiAgLy8gY2FsbGJhY2tcbiAgaWYgKHR5cGVvZiB1cmwgPT09ICdmdW5jdGlvbicpIHtcbiAgICByZXR1cm4gbmV3IGV4cG9ydHMuUmVxdWVzdCgnR0VUJywgbWV0aG9kKS5lbmQodXJsKTtcbiAgfVxuXG4gIC8vIHVybCBmaXJzdFxuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMSkge1xuICAgIHJldHVybiBuZXcgZXhwb3J0cy5SZXF1ZXN0KCdHRVQnLCBtZXRob2QpO1xuICB9XG5cbiAgcmV0dXJuIG5ldyBleHBvcnRzLlJlcXVlc3QobWV0aG9kLCB1cmwpO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHJlcXVlc3Q7XG5leHBvcnRzID0gbW9kdWxlLmV4cG9ydHM7XG5cbi8qKlxuICogRXhwb3NlIGBSZXF1ZXN0YC5cbiAqL1xuXG5leHBvcnRzLlJlcXVlc3QgPSBSZXF1ZXN0O1xuXG4vKipcbiAqIEV4cG9zZSB0aGUgYWdlbnQgZnVuY3Rpb25cbiAqL1xuXG5leHBvcnRzLmFnZW50ID0gcmVxdWlyZSgnLi9hZ2VudCcpO1xuXG4vKipcbiAqIE5vb3AuXG4gKi9cblxuZnVuY3Rpb24gbm9vcCgpIHt9XG5cbi8qKlxuICogRXhwb3NlIGBSZXNwb25zZWAuXG4gKi9cblxuZXhwb3J0cy5SZXNwb25zZSA9IFJlc3BvbnNlO1xuXG4vKipcbiAqIERlZmluZSBcImZvcm1cIiBtaW1lIHR5cGUuXG4gKi9cblxubWltZS5kZWZpbmUoXG4gIHtcbiAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJzogWydmb3JtJywgJ3VybGVuY29kZWQnLCAnZm9ybS1kYXRhJ11cbiAgfSxcbiAgdHJ1ZVxuKTtcblxuLyoqXG4gKiBQcm90b2NvbCBtYXAuXG4gKi9cblxuZXhwb3J0cy5wcm90b2NvbHMgPSB7XG4gICdodHRwOic6IGh0dHAsXG4gICdodHRwczonOiBodHRwcyxcbiAgJ2h0dHAyOic6IGh0dHAyXG59O1xuXG4vKipcbiAqIERlZmF1bHQgc2VyaWFsaXphdGlvbiBtYXAuXG4gKlxuICogICAgIHN1cGVyYWdlbnQuc2VyaWFsaXplWydhcHBsaWNhdGlvbi94bWwnXSA9IGZ1bmN0aW9uKG9iail7XG4gKiAgICAgICByZXR1cm4gJ2dlbmVyYXRlZCB4bWwgaGVyZSc7XG4gKiAgICAgfTtcbiAqXG4gKi9cblxuZXhwb3J0cy5zZXJpYWxpemUgPSB7XG4gICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnOiBxcy5zdHJpbmdpZnksXG4gICdhcHBsaWNhdGlvbi9qc29uJzogc2FmZVN0cmluZ2lmeVxufTtcblxuLyoqXG4gKiBEZWZhdWx0IHBhcnNlcnMuXG4gKlxuICogICAgIHN1cGVyYWdlbnQucGFyc2VbJ2FwcGxpY2F0aW9uL3htbCddID0gZnVuY3Rpb24ocmVzLCBmbil7XG4gKiAgICAgICBmbihudWxsLCByZXMpO1xuICogICAgIH07XG4gKlxuICovXG5cbmV4cG9ydHMucGFyc2UgPSByZXF1aXJlKCcuL3BhcnNlcnMnKTtcblxuLyoqXG4gKiBEZWZhdWx0IGJ1ZmZlcmluZyBtYXAuIENhbiBiZSB1c2VkIHRvIHNldCBjZXJ0YWluXG4gKiByZXNwb25zZSB0eXBlcyB0byBidWZmZXIvbm90IGJ1ZmZlci5cbiAqXG4gKiAgICAgc3VwZXJhZ2VudC5idWZmZXJbJ2FwcGxpY2F0aW9uL3htbCddID0gdHJ1ZTtcbiAqL1xuZXhwb3J0cy5idWZmZXIgPSB7fTtcblxuLyoqXG4gKiBJbml0aWFsaXplIGludGVybmFsIGhlYWRlciB0cmFja2luZyBwcm9wZXJ0aWVzIG9uIGEgcmVxdWVzdCBpbnN0YW5jZS5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gcmVxIHRoZSBpbnN0YW5jZVxuICogQGFwaSBwcml2YXRlXG4gKi9cbmZ1bmN0aW9uIF9pbml0SGVhZGVycyhyZXEpIHtcbiAgcmVxLl9oZWFkZXIgPSB7XG4gICAgLy8gY29lcmNlcyBoZWFkZXIgbmFtZXMgdG8gbG93ZXJjYXNlXG4gIH07XG4gIHJlcS5oZWFkZXIgPSB7XG4gICAgLy8gcHJlc2VydmVzIGhlYWRlciBuYW1lIGNhc2VcbiAgfTtcbn1cblxuLyoqXG4gKiBJbml0aWFsaXplIGEgbmV3IGBSZXF1ZXN0YCB3aXRoIHRoZSBnaXZlbiBgbWV0aG9kYCBhbmQgYHVybGAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IG1ldGhvZFxuICogQHBhcmFtIHtTdHJpbmd8T2JqZWN0fSB1cmxcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuZnVuY3Rpb24gUmVxdWVzdChtZXRob2QsIHVybCkge1xuICBTdHJlYW0uY2FsbCh0aGlzKTtcbiAgaWYgKHR5cGVvZiB1cmwgIT09ICdzdHJpbmcnKSB1cmwgPSBmb3JtYXQodXJsKTtcbiAgdGhpcy5fZW5hYmxlSHR0cDIgPSBCb29sZWFuKHByb2Nlc3MuZW52LkhUVFAyX1RFU1QpOyAvLyBpbnRlcm5hbCBvbmx5XG4gIHRoaXMuX2FnZW50ID0gZmFsc2U7XG4gIHRoaXMuX2Zvcm1EYXRhID0gbnVsbDtcbiAgdGhpcy5tZXRob2QgPSBtZXRob2Q7XG4gIHRoaXMudXJsID0gdXJsO1xuICBfaW5pdEhlYWRlcnModGhpcyk7XG4gIHRoaXMud3JpdGFibGUgPSB0cnVlO1xuICB0aGlzLl9yZWRpcmVjdHMgPSAwO1xuICB0aGlzLnJlZGlyZWN0cyhtZXRob2QgPT09ICdIRUFEJyA/IDAgOiA1KTtcbiAgdGhpcy5jb29raWVzID0gJyc7XG4gIHRoaXMucXMgPSB7fTtcbiAgdGhpcy5fcXVlcnkgPSBbXTtcbiAgdGhpcy5xc1JhdyA9IHRoaXMuX3F1ZXJ5OyAvLyBVbnVzZWQsIGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eSBvbmx5XG4gIHRoaXMuX3JlZGlyZWN0TGlzdCA9IFtdO1xuICB0aGlzLl9zdHJlYW1SZXF1ZXN0ID0gZmFsc2U7XG4gIHRoaXMub25jZSgnZW5kJywgdGhpcy5jbGVhclRpbWVvdXQuYmluZCh0aGlzKSk7XG59XG5cbi8qKlxuICogSW5oZXJpdCBmcm9tIGBTdHJlYW1gICh3aGljaCBpbmhlcml0cyBmcm9tIGBFdmVudEVtaXR0ZXJgKS5cbiAqIE1peGluIGBSZXF1ZXN0QmFzZWAuXG4gKi9cbnV0aWwuaW5oZXJpdHMoUmVxdWVzdCwgU3RyZWFtKTtcbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuZXctY2FwXG5SZXF1ZXN0QmFzZShSZXF1ZXN0LnByb3RvdHlwZSk7XG5cbi8qKlxuICogRW5hYmxlIG9yIERpc2FibGUgaHR0cDIuXG4gKlxuICogRW5hYmxlIGh0dHAyLlxuICpcbiAqIGBgYCBqc1xuICogcmVxdWVzdC5nZXQoJ2h0dHA6Ly9sb2NhbGhvc3QvJylcbiAqICAgLmh0dHAyKClcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogcmVxdWVzdC5nZXQoJ2h0dHA6Ly9sb2NhbGhvc3QvJylcbiAqICAgLmh0dHAyKHRydWUpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogRGlzYWJsZSBodHRwMi5cbiAqXG4gKiBgYGAganNcbiAqIHJlcXVlc3QgPSByZXF1ZXN0Lmh0dHAyKCk7XG4gKiByZXF1ZXN0LmdldCgnaHR0cDovL2xvY2FsaG9zdC8nKVxuICogICAuaHR0cDIoZmFsc2UpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogQHBhcmFtIHtCb29sZWFufSBlbmFibGVcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5odHRwMiA9IGZ1bmN0aW9uIChib29sKSB7XG4gIGlmIChleHBvcnRzLnByb3RvY29sc1snaHR0cDI6J10gPT09IHVuZGVmaW5lZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICdzdXBlcmFnZW50OiB0aGlzIHZlcnNpb24gb2YgTm9kZS5qcyBkb2VzIG5vdCBzdXBwb3J0IGh0dHAyJ1xuICAgICk7XG4gIH1cblxuICB0aGlzLl9lbmFibGVIdHRwMiA9IGJvb2wgPT09IHVuZGVmaW5lZCA/IHRydWUgOiBib29sO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUXVldWUgdGhlIGdpdmVuIGBmaWxlYCBhcyBhbiBhdHRhY2htZW50IHRvIHRoZSBzcGVjaWZpZWQgYGZpZWxkYCxcbiAqIHdpdGggb3B0aW9uYWwgYG9wdGlvbnNgIChvciBmaWxlbmFtZSkuXG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmllbGQnLCBCdWZmZXIuZnJvbSgnPGI+SGVsbG8gd29ybGQ8L2I+JyksICdoZWxsby5odG1sJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBBIGZpbGVuYW1lIG1heSBhbHNvIGJlIHVzZWQ6XG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmlsZXMnLCAnaW1hZ2UuanBnJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gZmllbGRcbiAqIEBwYXJhbSB7U3RyaW5nfGZzLlJlYWRTdHJlYW18QnVmZmVyfSBmaWxlXG4gKiBAcGFyYW0ge1N0cmluZ3xPYmplY3R9IG9wdGlvbnNcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdHRhY2hXaXRoRGVzY3JpcHRpb24gPSBmdW5jdGlvbihmaWVsZCwgZmlsZSwgb3B0aW9ucywgdGV4dFZhbCl7XG4gIGlmIChmaWxlKSB7XG4gICAgaWYgKHRoaXMuX2RhdGEpIHtcbiAgICAgIHRocm93IEVycm9yKFwic3VwZXJhZ2VudCBjYW4ndCBtaXggLnNlbmQoKSBhbmQgLmF0dGFjaCgpXCIpO1xuICAgIH1cblxuICAgIGxldCBvID0gb3B0aW9ucyB8fCB7fTtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBvID0geyBmaWxlbmFtZTogb3B0aW9ucyB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZmlsZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmICghby5maWxlbmFtZSkgby5maWxlbmFtZSA9IGZpbGU7XG4gICAgICBkZWJ1ZygnY3JlYXRpbmcgYGZzLlJlYWRTdHJlYW1gIGluc3RhbmNlIGZvciBmaWxlOiAlcycsIGZpbGUpO1xuICAgICAgZmlsZSA9IGZzLmNyZWF0ZVJlYWRTdHJlYW0oZmlsZSk7XG4gICAgfSBlbHNlIGlmICghby5maWxlbmFtZSAmJiBmaWxlLnBhdGgpIHtcbiAgICAgIG8uZmlsZW5hbWUgPSBmaWxlLnBhdGg7XG4gICAgfVxuXG4gICAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmRXaXRoSnNvbihmaWVsZCwgZmlsZSwgbywgdGV4dFZhbCk7XG4gIH1cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdHRhY2ggPSBmdW5jdGlvbiAoZmllbGQsIGZpbGUsIG9wdGlvbnMpIHtcbiAgaWYgKGZpbGUpIHtcbiAgICBpZiAodGhpcy5fZGF0YSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwic3VwZXJhZ2VudCBjYW4ndCBtaXggLnNlbmQoKSBhbmQgLmF0dGFjaCgpXCIpO1xuICAgIH1cblxuICAgIGxldCBvID0gb3B0aW9ucyB8fCB7fTtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBvID0geyBmaWxlbmFtZTogb3B0aW9ucyB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZmlsZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmICghby5maWxlbmFtZSkgby5maWxlbmFtZSA9IGZpbGU7XG4gICAgICBkZWJ1ZygnY3JlYXRpbmcgYGZzLlJlYWRTdHJlYW1gIGluc3RhbmNlIGZvciBmaWxlOiAlcycsIGZpbGUpO1xuICAgICAgZmlsZSA9IGZzLmNyZWF0ZVJlYWRTdHJlYW0oZmlsZSk7XG4gICAgfSBlbHNlIGlmICghby5maWxlbmFtZSAmJiBmaWxlLnBhdGgpIHtcbiAgICAgIG8uZmlsZW5hbWUgPSBmaWxlLnBhdGg7XG4gICAgfVxuXG4gICAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmRXaXRoSnNvbihmaWVsZCwgZmlsZSwgbywgdGV4dFZhbCk7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLl9nZXRGb3JtRGF0YSA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKCF0aGlzLl9mb3JtRGF0YSkge1xuICAgIHRoaXMuX2Zvcm1EYXRhID0gbmV3IEZvcm1EYXRhKCk7XG4gICAgdGhpcy5fZm9ybURhdGEub24oJ2Vycm9yJywgKGVycikgPT4ge1xuICAgICAgZGVidWcoJ0Zvcm1EYXRhIGVycm9yJywgZXJyKTtcbiAgICAgIGlmICh0aGlzLmNhbGxlZCkge1xuICAgICAgICAvLyBUaGUgcmVxdWVzdCBoYXMgYWxyZWFkeSBmaW5pc2hlZCBhbmQgdGhlIGNhbGxiYWNrIHdhcyBjYWxsZWQuXG4gICAgICAgIC8vIFNpbGVudGx5IGlnbm9yZSB0aGUgZXJyb3IuXG4gICAgICAgIHJldHVybjtcbiAgICAgIH1cblxuICAgICAgdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgdGhpcy5hYm9ydCgpO1xuICAgIH0pO1xuICB9XG5cbiAgcmV0dXJuIHRoaXMuX2Zvcm1EYXRhO1xufTtcblxuLyoqXG4gKiBHZXRzL3NldHMgdGhlIGBBZ2VudGAgdG8gdXNlIGZvciB0aGlzIEhUVFAgcmVxdWVzdC4gVGhlIGRlZmF1bHQgKGlmIHRoaXNcbiAqIGZ1bmN0aW9uIGlzIG5vdCBjYWxsZWQpIGlzIHRvIG9wdCBvdXQgb2YgY29ubmVjdGlvbiBwb29saW5nIChgYWdlbnQ6IGZhbHNlYCkuXG4gKlxuICogQHBhcmFtIHtodHRwLkFnZW50fSBhZ2VudFxuICogQHJldHVybiB7aHR0cC5BZ2VudH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYWdlbnQgPSBmdW5jdGlvbiAoYWdlbnQpIHtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDApIHJldHVybiB0aGlzLl9hZ2VudDtcbiAgdGhpcy5fYWdlbnQgPSBhZ2VudDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCBfQ29udGVudC1UeXBlXyByZXNwb25zZSBoZWFkZXIgcGFzc2VkIHRocm91Z2ggYG1pbWUuZ2V0VHlwZSgpYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ3htbCcpXG4gKiAgICAgICAgLnNlbmQoeG1sc3RyaW5nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvJylcbiAqICAgICAgICAudHlwZSgnanNvbicpXG4gKiAgICAgICAgLnNlbmQoanNvbnN0cmluZylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ2FwcGxpY2F0aW9uL2pzb24nKVxuICogICAgICAgIC5zZW5kKGpzb25zdHJpbmcpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHR5cGVcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS50eXBlID0gZnVuY3Rpb24gKHR5cGUpIHtcbiAgcmV0dXJuIHRoaXMuc2V0KFxuICAgICdDb250ZW50LVR5cGUnLFxuICAgIHR5cGUuaW5jbHVkZXMoJy8nKSA/IHR5cGUgOiBtaW1lLmdldFR5cGUodHlwZSlcbiAgKTtcbn07XG5cbi8qKlxuICogU2V0IF9BY2NlcHRfIHJlc3BvbnNlIGhlYWRlciBwYXNzZWQgdGhyb3VnaCBgbWltZS5nZXRUeXBlKClgLlxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICAgICAgc3VwZXJhZ2VudC50eXBlcy5qc29uID0gJ2FwcGxpY2F0aW9uL2pzb24nO1xuICpcbiAqICAgICAgcmVxdWVzdC5nZXQoJy9hZ2VudCcpXG4gKiAgICAgICAgLmFjY2VwdCgnanNvbicpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogICAgICByZXF1ZXN0LmdldCgnL2FnZW50JylcbiAqICAgICAgICAuYWNjZXB0KCdhcHBsaWNhdGlvbi9qc29uJylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gYWNjZXB0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYWNjZXB0ID0gZnVuY3Rpb24gKHR5cGUpIHtcbiAgcmV0dXJuIHRoaXMuc2V0KCdBY2NlcHQnLCB0eXBlLmluY2x1ZGVzKCcvJykgPyB0eXBlIDogbWltZS5nZXRUeXBlKHR5cGUpKTtcbn07XG5cbi8qKlxuICogQWRkIHF1ZXJ5LXN0cmluZyBgdmFsYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgIHJlcXVlc3QuZ2V0KCcvc2hvZXMnKVxuICogICAgIC5xdWVyeSgnc2l6ZT0xMCcpXG4gKiAgICAgLnF1ZXJ5KHsgY29sb3I6ICdibHVlJyB9KVxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fFN0cmluZ30gdmFsXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucXVlcnkgPSBmdW5jdGlvbiAodmFsKSB7XG4gIGlmICh0eXBlb2YgdmFsID09PSAnc3RyaW5nJykge1xuICAgIHRoaXMuX3F1ZXJ5LnB1c2godmFsKTtcbiAgfSBlbHNlIHtcbiAgICBPYmplY3QuYXNzaWduKHRoaXMucXMsIHZhbCk7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogV3JpdGUgcmF3IGBkYXRhYCAvIGBlbmNvZGluZ2AgdG8gdGhlIHNvY2tldC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlcnxTdHJpbmd9IGRhdGFcbiAqIEBwYXJhbSB7U3RyaW5nfSBlbmNvZGluZ1xuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUud3JpdGUgPSBmdW5jdGlvbiAoZGF0YSwgZW5jb2RpbmcpIHtcbiAgY29uc3QgcmVxID0gdGhpcy5yZXF1ZXN0KCk7XG4gIGlmICghdGhpcy5fc3RyZWFtUmVxdWVzdCkge1xuICAgIHRoaXMuX3N0cmVhbVJlcXVlc3QgPSB0cnVlO1xuICB9XG5cbiAgcmV0dXJuIHJlcS53cml0ZShkYXRhLCBlbmNvZGluZyk7XG59O1xuXG4vKipcbiAqIFBpcGUgdGhlIHJlcXVlc3QgYm9keSB0byBgc3RyZWFtYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmVhbX0gc3RyZWFtXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0aW9uc1xuICogQHJldHVybiB7U3RyZWFtfVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5waXBlID0gZnVuY3Rpb24gKHN0cmVhbSwgb3B0aW9ucykge1xuICB0aGlzLnBpcGVkID0gdHJ1ZTsgLy8gSEFDSy4uLlxuICB0aGlzLmJ1ZmZlcihmYWxzZSk7XG4gIHRoaXMuZW5kKCk7XG4gIHJldHVybiB0aGlzLl9waXBlQ29udGludWUoc3RyZWFtLCBvcHRpb25zKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLl9waXBlQ29udGludWUgPSBmdW5jdGlvbiAoc3RyZWFtLCBvcHRpb25zKSB7XG4gIHRoaXMucmVxLm9uY2UoJ3Jlc3BvbnNlJywgKHJlcykgPT4ge1xuICAgIC8vIHJlZGlyZWN0XG4gICAgaWYgKFxuICAgICAgaXNSZWRpcmVjdChyZXMuc3RhdHVzQ29kZSkgJiZcbiAgICAgIHRoaXMuX3JlZGlyZWN0cysrICE9PSB0aGlzLl9tYXhSZWRpcmVjdHNcbiAgICApIHtcbiAgICAgIHJldHVybiB0aGlzLl9yZWRpcmVjdChyZXMpID09PSB0aGlzXG4gICAgICAgID8gdGhpcy5fcGlwZUNvbnRpbnVlKHN0cmVhbSwgb3B0aW9ucylcbiAgICAgICAgOiB1bmRlZmluZWQ7XG4gICAgfVxuXG4gICAgdGhpcy5yZXMgPSByZXM7XG4gICAgdGhpcy5fZW1pdFJlc3BvbnNlKCk7XG4gICAgaWYgKHRoaXMuX2Fib3J0ZWQpIHJldHVybjtcblxuICAgIGlmICh0aGlzLl9zaG91bGRVbnppcChyZXMpKSB7XG4gICAgICBjb25zdCB1bnppcE9iaiA9IHpsaWIuY3JlYXRlVW56aXAoKTtcbiAgICAgIHVuemlwT2JqLm9uKCdlcnJvcicsIChlcnIpID0+IHtcbiAgICAgICAgaWYgKGVyciAmJiBlcnIuY29kZSA9PT0gJ1pfQlVGX0VSUk9SJykge1xuICAgICAgICAgIC8vIHVuZXhwZWN0ZWQgZW5kIG9mIGZpbGUgaXMgaWdub3JlZCBieSBicm93c2VycyBhbmQgY3VybFxuICAgICAgICAgIHN0cmVhbS5lbWl0KCdlbmQnKTtcbiAgICAgICAgICByZXR1cm47XG4gICAgICAgIH1cblxuICAgICAgICBzdHJlYW0uZW1pdCgnZXJyb3InLCBlcnIpO1xuICAgICAgfSk7XG4gICAgICByZXMucGlwZSh1bnppcE9iaikucGlwZShzdHJlYW0sIG9wdGlvbnMpO1xuICAgIH0gZWxzZSB7XG4gICAgICByZXMucGlwZShzdHJlYW0sIG9wdGlvbnMpO1xuICAgIH1cblxuICAgIHJlcy5vbmNlKCdlbmQnLCAoKSA9PiB7XG4gICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgIH0pO1xuICB9KTtcbiAgcmV0dXJuIHN0cmVhbTtcbn07XG5cbi8qKlxuICogRW5hYmxlIC8gZGlzYWJsZSBidWZmZXJpbmcuXG4gKlxuICogQHJldHVybiB7Qm9vbGVhbn0gW3ZhbF1cbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5idWZmZXIgPSBmdW5jdGlvbiAodmFsKSB7XG4gIHRoaXMuX2J1ZmZlciA9IHZhbCAhPT0gZmFsc2U7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBSZWRpcmVjdCB0byBgdXJsXG4gKlxuICogQHBhcmFtIHtJbmNvbWluZ01lc3NhZ2V9IHJlc1xuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fcmVkaXJlY3QgPSBmdW5jdGlvbiAocmVzKSB7XG4gIGxldCB1cmwgPSByZXMuaGVhZGVycy5sb2NhdGlvbjtcbiAgaWYgKCF1cmwpIHtcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhuZXcgRXJyb3IoJ05vIGxvY2F0aW9uIGhlYWRlciBmb3IgcmVkaXJlY3QnKSwgcmVzKTtcbiAgfVxuXG4gIGRlYnVnKCdyZWRpcmVjdCAlcyAtPiAlcycsIHRoaXMudXJsLCB1cmwpO1xuXG4gIC8vIGxvY2F0aW9uXG4gIHVybCA9IHJlc29sdmUodGhpcy51cmwsIHVybCk7XG5cbiAgLy8gZW5zdXJlIHRoZSByZXNwb25zZSBpcyBiZWluZyBjb25zdW1lZFxuICAvLyB0aGlzIGlzIHJlcXVpcmVkIGZvciBOb2RlIHYwLjEwK1xuICByZXMucmVzdW1lKCk7XG5cbiAgbGV0IGhlYWRlcnMgPSB0aGlzLnJlcS5nZXRIZWFkZXJzID8gdGhpcy5yZXEuZ2V0SGVhZGVycygpIDogdGhpcy5yZXEuX2hlYWRlcnM7XG5cbiAgY29uc3QgY2hhbmdlc09yaWdpbiA9IHBhcnNlKHVybCkuaG9zdCAhPT0gcGFyc2UodGhpcy51cmwpLmhvc3Q7XG5cbiAgLy8gaW1wbGVtZW50YXRpb24gb2YgMzAyIGZvbGxvd2luZyBkZWZhY3RvIHN0YW5kYXJkXG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMzAxIHx8IHJlcy5zdGF0dXNDb2RlID09PSAzMDIpIHtcbiAgICAvLyBzdHJpcCBDb250ZW50LSogcmVsYXRlZCBmaWVsZHNcbiAgICAvLyBpbiBjYXNlIG9mIFBPU1QgZXRjXG4gICAgaGVhZGVycyA9IHV0aWxzLmNsZWFuSGVhZGVyKGhlYWRlcnMsIGNoYW5nZXNPcmlnaW4pO1xuXG4gICAgLy8gZm9yY2UgR0VUXG4gICAgdGhpcy5tZXRob2QgPSB0aGlzLm1ldGhvZCA9PT0gJ0hFQUQnID8gJ0hFQUQnIDogJ0dFVCc7XG5cbiAgICAvLyBjbGVhciBkYXRhXG4gICAgdGhpcy5fZGF0YSA9IG51bGw7XG4gIH1cblxuICAvLyAzMDMgaXMgYWx3YXlzIEdFVFxuICBpZiAocmVzLnN0YXR1c0NvZGUgPT09IDMwMykge1xuICAgIC8vIHN0cmlwIENvbnRlbnQtKiByZWxhdGVkIGZpZWxkc1xuICAgIC8vIGluIGNhc2Ugb2YgUE9TVCBldGNcbiAgICBoZWFkZXJzID0gdXRpbHMuY2xlYW5IZWFkZXIoaGVhZGVycywgY2hhbmdlc09yaWdpbik7XG5cbiAgICAvLyBmb3JjZSBtZXRob2RcbiAgICB0aGlzLm1ldGhvZCA9ICdHRVQnO1xuXG4gICAgLy8gY2xlYXIgZGF0YVxuICAgIHRoaXMuX2RhdGEgPSBudWxsO1xuICB9XG5cbiAgLy8gMzA3IHByZXNlcnZlcyBtZXRob2RcbiAgLy8gMzA4IHByZXNlcnZlcyBtZXRob2RcbiAgZGVsZXRlIGhlYWRlcnMuaG9zdDtcblxuICBkZWxldGUgdGhpcy5yZXE7XG4gIGRlbGV0ZSB0aGlzLl9mb3JtRGF0YTtcblxuICAvLyByZW1vdmUgYWxsIGFkZCBoZWFkZXIgZXhjZXB0IFVzZXItQWdlbnRcbiAgX2luaXRIZWFkZXJzKHRoaXMpO1xuXG4gIC8vIHJlZGlyZWN0XG4gIHRoaXMuX2VuZENhbGxlZCA9IGZhbHNlO1xuICB0aGlzLnVybCA9IHVybDtcbiAgdGhpcy5xcyA9IHt9O1xuICB0aGlzLl9xdWVyeS5sZW5ndGggPSAwO1xuICB0aGlzLnNldChoZWFkZXJzKTtcbiAgdGhpcy5lbWl0KCdyZWRpcmVjdCcsIHJlcyk7XG4gIHRoaXMuX3JlZGlyZWN0TGlzdC5wdXNoKHRoaXMudXJsKTtcbiAgdGhpcy5lbmQodGhpcy5fY2FsbGJhY2spO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IEF1dGhvcml6YXRpb24gZmllbGQgdmFsdWUgd2l0aCBgdXNlcmAgYW5kIGBwYXNzYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgIC5hdXRoKCd0b2JpJywgJ2xlYXJuYm9vc3QnKVxuICogICAuYXV0aCgndG9iaTpsZWFybmJvb3N0JylcbiAqICAgLmF1dGgoJ3RvYmknKVxuICogICAuYXV0aChhY2Nlc3NUb2tlbiwgeyB0eXBlOiAnYmVhcmVyJyB9KVxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB1c2VyXG4gKiBAcGFyYW0ge1N0cmluZ30gW3Bhc3NdXG4gKiBAcGFyYW0ge09iamVjdH0gW29wdGlvbnNdIG9wdGlvbnMgd2l0aCBhdXRob3JpemF0aW9uIHR5cGUgJ2Jhc2ljJyBvciAnYmVhcmVyJyAoJ2Jhc2ljJyBpcyBkZWZhdWx0KVxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmF1dGggPSBmdW5jdGlvbiAodXNlciwgcGFzcywgb3B0aW9ucykge1xuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMSkgcGFzcyA9ICcnO1xuICBpZiAodHlwZW9mIHBhc3MgPT09ICdvYmplY3QnICYmIHBhc3MgIT09IG51bGwpIHtcbiAgICAvLyBwYXNzIGlzIG9wdGlvbmFsIGFuZCBjYW4gYmUgcmVwbGFjZWQgd2l0aCBvcHRpb25zXG4gICAgb3B0aW9ucyA9IHBhc3M7XG4gICAgcGFzcyA9ICcnO1xuICB9XG5cbiAgaWYgKCFvcHRpb25zKSB7XG4gICAgb3B0aW9ucyA9IHsgdHlwZTogJ2Jhc2ljJyB9O1xuICB9XG5cbiAgY29uc3QgZW5jb2RlciA9IChzdHJpbmcpID0+IEJ1ZmZlci5mcm9tKHN0cmluZykudG9TdHJpbmcoJ2Jhc2U2NCcpO1xuXG4gIHJldHVybiB0aGlzLl9hdXRoKHVzZXIsIHBhc3MsIG9wdGlvbnMsIGVuY29kZXIpO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIGNlcnRpZmljYXRlIGF1dGhvcml0eSBvcHRpb24gZm9yIGh0dHBzIHJlcXVlc3QuXG4gKlxuICogQHBhcmFtIHtCdWZmZXIgfCBBcnJheX0gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmNhID0gZnVuY3Rpb24gKGNlcnQpIHtcbiAgdGhpcy5fY2EgPSBjZXJ0O1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IHRoZSBjbGllbnQgY2VydGlmaWNhdGUga2V5IG9wdGlvbiBmb3IgaHR0cHMgcmVxdWVzdC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlciB8IFN0cmluZ30gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmtleSA9IGZ1bmN0aW9uIChjZXJ0KSB7XG4gIHRoaXMuX2tleSA9IGNlcnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIGtleSwgY2VydGlmaWNhdGUsIGFuZCBDQSBjZXJ0cyBvZiB0aGUgY2xpZW50IGluIFBGWCBvciBQS0NTMTIgZm9ybWF0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyIHwgU3RyaW5nfSBjZXJ0XG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucGZ4ID0gZnVuY3Rpb24gKGNlcnQpIHtcbiAgaWYgKHR5cGVvZiBjZXJ0ID09PSAnb2JqZWN0JyAmJiAhQnVmZmVyLmlzQnVmZmVyKGNlcnQpKSB7XG4gICAgdGhpcy5fcGZ4ID0gY2VydC5wZng7XG4gICAgdGhpcy5fcGFzc3BocmFzZSA9IGNlcnQucGFzc3BocmFzZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLl9wZnggPSBjZXJ0O1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCB0aGUgY2xpZW50IGNlcnRpZmljYXRlIG9wdGlvbiBmb3IgaHR0cHMgcmVxdWVzdC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlciB8IFN0cmluZ30gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmNlcnQgPSBmdW5jdGlvbiAoY2VydCkge1xuICB0aGlzLl9jZXJ0ID0gY2VydDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIERvIG5vdCByZWplY3QgZXhwaXJlZCBvciBpbnZhbGlkIFRMUyBjZXJ0cy5cbiAqIHNldHMgYHJlamVjdFVuYXV0aG9yaXplZD10cnVlYC4gQmUgd2FybmVkIHRoYXQgdGhpcyBhbGxvd3MgTUlUTSBhdHRhY2tzLlxuICpcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5kaXNhYmxlVExTQ2VydHMgPSBmdW5jdGlvbiAoKSB7XG4gIHRoaXMuX2Rpc2FibGVUTFNDZXJ0cyA9IHRydWU7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBSZXR1cm4gYW4gaHR0cFtzXSByZXF1ZXN0LlxuICpcbiAqIEByZXR1cm4ge091dGdvaW5nTWVzc2FnZX1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG5SZXF1ZXN0LnByb3RvdHlwZS5yZXF1ZXN0ID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpcy5yZXEpIHJldHVybiB0aGlzLnJlcTtcblxuICBjb25zdCBvcHRpb25zID0ge307XG5cbiAgdHJ5IHtcbiAgICBjb25zdCBxdWVyeSA9IHFzLnN0cmluZ2lmeSh0aGlzLnFzLCB7XG4gICAgICBpbmRpY2VzOiBmYWxzZSxcbiAgICAgIHN0cmljdE51bGxIYW5kbGluZzogdHJ1ZVxuICAgIH0pO1xuICAgIGlmIChxdWVyeSkge1xuICAgICAgdGhpcy5xcyA9IHt9O1xuICAgICAgdGhpcy5fcXVlcnkucHVzaChxdWVyeSk7XG4gICAgfVxuXG4gICAgdGhpcy5fZmluYWxpemVRdWVyeVN0cmluZygpO1xuICB9IGNhdGNoIChlcnIpIHtcbiAgICByZXR1cm4gdGhpcy5lbWl0KCdlcnJvcicsIGVycik7XG4gIH1cblxuICBsZXQgeyB1cmwgfSA9IHRoaXM7XG4gIGNvbnN0IHJldHJpZXMgPSB0aGlzLl9yZXRyaWVzO1xuXG4gIC8vIENhcHR1cmUgYmFja3RpY2tzIGFzLWlzIGZyb20gdGhlIGZpbmFsIHF1ZXJ5IHN0cmluZyBidWlsdCBhYm92ZS5cbiAgLy8gTm90ZTogdGhpcydsbCBvbmx5IGZpbmQgYmFja3RpY2tzIGVudGVyZWQgaW4gcmVxLnF1ZXJ5KFN0cmluZylcbiAgLy8gY2FsbHMsIGJlY2F1c2UgcXMuc3RyaW5naWZ5IHVuY29uZGl0aW9uYWxseSBlbmNvZGVzIGJhY2t0aWNrcy5cbiAgbGV0IHF1ZXJ5U3RyaW5nQmFja3RpY2tzO1xuICBpZiAodXJsLmluY2x1ZGVzKCdgJykpIHtcbiAgICBjb25zdCBxdWVyeVN0YXJ0SW5kZXggPSB1cmwuaW5kZXhPZignPycpO1xuXG4gICAgaWYgKHF1ZXJ5U3RhcnRJbmRleCAhPT0gLTEpIHtcbiAgICAgIGNvbnN0IHF1ZXJ5U3RyaW5nID0gdXJsLnNsaWNlKHF1ZXJ5U3RhcnRJbmRleCArIDEpO1xuICAgICAgcXVlcnlTdHJpbmdCYWNrdGlja3MgPSBxdWVyeVN0cmluZy5tYXRjaCgvYHwlNjAvZyk7XG4gICAgfVxuICB9XG5cbiAgLy8gZGVmYXVsdCB0byBodHRwOi8vXG4gIGlmICh1cmwuaW5kZXhPZignaHR0cCcpICE9PSAwKSB1cmwgPSBgaHR0cDovLyR7dXJsfWA7XG4gIHVybCA9IHBhcnNlKHVybCk7XG5cbiAgLy8gU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS92aXNpb25tZWRpYS9zdXBlcmFnZW50L2lzc3Vlcy8xMzY3XG4gIGlmIChxdWVyeVN0cmluZ0JhY2t0aWNrcykge1xuICAgIGxldCBpID0gMDtcbiAgICB1cmwucXVlcnkgPSB1cmwucXVlcnkucmVwbGFjZSgvJTYwL2csICgpID0+IHF1ZXJ5U3RyaW5nQmFja3RpY2tzW2krK10pO1xuICAgIHVybC5zZWFyY2ggPSBgPyR7dXJsLnF1ZXJ5fWA7XG4gICAgdXJsLnBhdGggPSB1cmwucGF0aG5hbWUgKyB1cmwuc2VhcmNoO1xuICB9XG5cbiAgLy8gc3VwcG9ydCB1bml4IHNvY2tldHNcbiAgaWYgKC9eaHR0cHM/XFwrdW5peDovLnRlc3QodXJsLnByb3RvY29sKSA9PT0gdHJ1ZSkge1xuICAgIC8vIGdldCB0aGUgcHJvdG9jb2xcbiAgICB1cmwucHJvdG9jb2wgPSBgJHt1cmwucHJvdG9jb2wuc3BsaXQoJysnKVswXX06YDtcblxuICAgIC8vIGdldCB0aGUgc29ja2V0LCBwYXRoXG4gICAgY29uc3QgdW5peFBhcnRzID0gdXJsLnBhdGgubWF0Y2goL14oW14vXSspKC4rKSQvKTtcbiAgICBvcHRpb25zLnNvY2tldFBhdGggPSB1bml4UGFydHNbMV0ucmVwbGFjZSgvJTJGL2csICcvJyk7XG4gICAgdXJsLnBhdGggPSB1bml4UGFydHNbMl07XG4gIH1cblxuICAvLyBPdmVycmlkZSBJUCBhZGRyZXNzIG9mIGEgaG9zdG5hbWVcbiAgaWYgKHRoaXMuX2Nvbm5lY3RPdmVycmlkZSkge1xuICAgIGNvbnN0IHsgaG9zdG5hbWUgfSA9IHVybDtcbiAgICBjb25zdCBtYXRjaCA9XG4gICAgICBob3N0bmFtZSBpbiB0aGlzLl9jb25uZWN0T3ZlcnJpZGVcbiAgICAgICAgPyB0aGlzLl9jb25uZWN0T3ZlcnJpZGVbaG9zdG5hbWVdXG4gICAgICAgIDogdGhpcy5fY29ubmVjdE92ZXJyaWRlWycqJ107XG4gICAgaWYgKG1hdGNoKSB7XG4gICAgICAvLyBiYWNrdXAgdGhlIHJlYWwgaG9zdFxuICAgICAgaWYgKCF0aGlzLl9oZWFkZXIuaG9zdCkge1xuICAgICAgICB0aGlzLnNldCgnaG9zdCcsIHVybC5ob3N0KTtcbiAgICAgIH1cblxuICAgICAgbGV0IG5ld0hvc3Q7XG4gICAgICBsZXQgbmV3UG9ydDtcblxuICAgICAgaWYgKHR5cGVvZiBtYXRjaCA9PT0gJ29iamVjdCcpIHtcbiAgICAgICAgbmV3SG9zdCA9IG1hdGNoLmhvc3Q7XG4gICAgICAgIG5ld1BvcnQgPSBtYXRjaC5wb3J0O1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgbmV3SG9zdCA9IG1hdGNoO1xuICAgICAgICBuZXdQb3J0ID0gdXJsLnBvcnQ7XG4gICAgICB9XG5cbiAgICAgIC8vIHdyYXAgW2lwdjZdXG4gICAgICB1cmwuaG9zdCA9IC86Ly50ZXN0KG5ld0hvc3QpID8gYFske25ld0hvc3R9XWAgOiBuZXdIb3N0O1xuICAgICAgaWYgKG5ld1BvcnQpIHtcbiAgICAgICAgdXJsLmhvc3QgKz0gYDoke25ld1BvcnR9YDtcbiAgICAgICAgdXJsLnBvcnQgPSBuZXdQb3J0O1xuICAgICAgfVxuXG4gICAgICB1cmwuaG9zdG5hbWUgPSBuZXdIb3N0O1xuICAgIH1cbiAgfVxuXG4gIC8vIG9wdGlvbnNcbiAgb3B0aW9ucy5tZXRob2QgPSB0aGlzLm1ldGhvZDtcbiAgb3B0aW9ucy5wb3J0ID0gdXJsLnBvcnQ7XG4gIG9wdGlvbnMucGF0aCA9IHVybC5wYXRoO1xuICBvcHRpb25zLmhvc3QgPSB1cmwuaG9zdG5hbWU7XG4gIG9wdGlvbnMuY2EgPSB0aGlzLl9jYTtcbiAgb3B0aW9ucy5rZXkgPSB0aGlzLl9rZXk7XG4gIG9wdGlvbnMucGZ4ID0gdGhpcy5fcGZ4O1xuICBvcHRpb25zLmNlcnQgPSB0aGlzLl9jZXJ0O1xuICBvcHRpb25zLnBhc3NwaHJhc2UgPSB0aGlzLl9wYXNzcGhyYXNlO1xuICBvcHRpb25zLmFnZW50ID0gdGhpcy5fYWdlbnQ7XG4gIG9wdGlvbnMucmVqZWN0VW5hdXRob3JpemVkID1cbiAgICB0eXBlb2YgdGhpcy5fZGlzYWJsZVRMU0NlcnRzID09PSAnYm9vbGVhbidcbiAgICAgID8gIXRoaXMuX2Rpc2FibGVUTFNDZXJ0c1xuICAgICAgOiBwcm9jZXNzLmVudi5OT0RFX1RMU19SRUpFQ1RfVU5BVVRIT1JJWkVEICE9PSAnMCc7XG5cbiAgLy8gQWxsb3dzIHJlcXVlc3QuZ2V0KCdodHRwczovLzEuMi4zLjQvJykuc2V0KCdIb3N0JywgJ2V4YW1wbGUuY29tJylcbiAgaWYgKHRoaXMuX2hlYWRlci5ob3N0KSB7XG4gICAgb3B0aW9ucy5zZXJ2ZXJuYW1lID0gdGhpcy5faGVhZGVyLmhvc3QucmVwbGFjZSgvOlxcZCskLywgJycpO1xuICB9XG5cbiAgaWYgKFxuICAgIHRoaXMuX3RydXN0TG9jYWxob3N0ICYmXG4gICAgL14oPzpsb2NhbGhvc3R8MTI3XFwuMFxcLjBcXC5cXGQrfCgwKjopKzowKjEpJC8udGVzdCh1cmwuaG9zdG5hbWUpXG4gICkge1xuICAgIG9wdGlvbnMucmVqZWN0VW5hdXRob3JpemVkID0gZmFsc2U7XG4gIH1cblxuICAvLyBpbml0aWF0ZSByZXF1ZXN0XG4gIGNvbnN0IG1vZCA9IHRoaXMuX2VuYWJsZUh0dHAyXG4gICAgPyBleHBvcnRzLnByb3RvY29sc1snaHR0cDI6J10uc2V0UHJvdG9jb2wodXJsLnByb3RvY29sKVxuICAgIDogZXhwb3J0cy5wcm90b2NvbHNbdXJsLnByb3RvY29sXTtcblxuICAvLyByZXF1ZXN0XG4gIHRoaXMucmVxID0gbW9kLnJlcXVlc3Qob3B0aW9ucyk7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuXG4gIC8vIHNldCB0Y3Agbm8gZGVsYXlcbiAgcmVxLnNldE5vRGVsYXkodHJ1ZSk7XG5cbiAgaWYgKG9wdGlvbnMubWV0aG9kICE9PSAnSEVBRCcpIHtcbiAgICByZXEuc2V0SGVhZGVyKCdBY2NlcHQtRW5jb2RpbmcnLCAnZ3ppcCwgZGVmbGF0ZScpO1xuICB9XG5cbiAgdGhpcy5wcm90b2NvbCA9IHVybC5wcm90b2NvbDtcbiAgdGhpcy5ob3N0ID0gdXJsLmhvc3Q7XG5cbiAgLy8gZXhwb3NlIGV2ZW50c1xuICByZXEub25jZSgnZHJhaW4nLCAoKSA9PiB7XG4gICAgdGhpcy5lbWl0KCdkcmFpbicpO1xuICB9KTtcblxuICByZXEub24oJ2Vycm9yJywgKGVycikgPT4ge1xuICAgIC8vIGZsYWcgYWJvcnRpb24gaGVyZSBmb3Igb3V0IHRpbWVvdXRzXG4gICAgLy8gYmVjYXVzZSBub2RlIHdpbGwgZW1pdCBhIGZhdXgtZXJyb3IgXCJzb2NrZXQgaGFuZyB1cFwiXG4gICAgLy8gd2hlbiByZXF1ZXN0IGlzIGFib3J0ZWQgYmVmb3JlIGEgY29ubmVjdGlvbiBpcyBtYWRlXG4gICAgaWYgKHRoaXMuX2Fib3J0ZWQpIHJldHVybjtcbiAgICAvLyBpZiBub3QgdGhlIHNhbWUsIHdlIGFyZSBpbiB0aGUgKipvbGQqKiAoY2FuY2VsbGVkKSByZXF1ZXN0LFxuICAgIC8vIHNvIG5lZWQgdG8gY29udGludWUgKHNhbWUgYXMgZm9yIGFib3ZlKVxuICAgIGlmICh0aGlzLl9yZXRyaWVzICE9PSByZXRyaWVzKSByZXR1cm47XG4gICAgLy8gaWYgd2UndmUgcmVjZWl2ZWQgYSByZXNwb25zZSB0aGVuIHdlIGRvbid0IHdhbnQgdG8gbGV0XG4gICAgLy8gYW4gZXJyb3IgaW4gdGhlIHJlcXVlc3QgYmxvdyB1cCB0aGUgcmVzcG9uc2VcbiAgICBpZiAodGhpcy5yZXNwb25zZSkgcmV0dXJuO1xuICAgIHRoaXMuY2FsbGJhY2soZXJyKTtcbiAgfSk7XG5cbiAgLy8gYXV0aFxuICBpZiAodXJsLmF1dGgpIHtcbiAgICBjb25zdCBhdXRoID0gdXJsLmF1dGguc3BsaXQoJzonKTtcbiAgICB0aGlzLmF1dGgoYXV0aFswXSwgYXV0aFsxXSk7XG4gIH1cblxuICBpZiAodGhpcy51c2VybmFtZSAmJiB0aGlzLnBhc3N3b3JkKSB7XG4gICAgdGhpcy5hdXRoKHRoaXMudXNlcm5hbWUsIHRoaXMucGFzc3dvcmQpO1xuICB9XG5cbiAgZm9yIChjb25zdCBrZXkgaW4gdGhpcy5oZWFkZXIpIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHRoaXMuaGVhZGVyLCBrZXkpKVxuICAgICAgcmVxLnNldEhlYWRlcihrZXksIHRoaXMuaGVhZGVyW2tleV0pO1xuICB9XG5cbiAgLy8gYWRkIGNvb2tpZXNcbiAgaWYgKHRoaXMuY29va2llcykge1xuICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwodGhpcy5faGVhZGVyLCAnY29va2llJykpIHtcbiAgICAgIC8vIG1lcmdlXG4gICAgICBjb25zdCB0bXBKYXIgPSBuZXcgQ29va2llSmFyLkNvb2tpZUphcigpO1xuICAgICAgdG1wSmFyLnNldENvb2tpZXModGhpcy5faGVhZGVyLmNvb2tpZS5zcGxpdCgnOycpKTtcbiAgICAgIHRtcEphci5zZXRDb29raWVzKHRoaXMuY29va2llcy5zcGxpdCgnOycpKTtcbiAgICAgIHJlcS5zZXRIZWFkZXIoXG4gICAgICAgICdDb29raWUnLFxuICAgICAgICB0bXBKYXIuZ2V0Q29va2llcyhDb29raWVKYXIuQ29va2llQWNjZXNzSW5mby5BbGwpLnRvVmFsdWVTdHJpbmcoKVxuICAgICAgKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVxLnNldEhlYWRlcignQ29va2llJywgdGhpcy5jb29raWVzKTtcbiAgICB9XG4gIH1cblxuICByZXR1cm4gcmVxO1xufTtcblxuLyoqXG4gKiBJbnZva2UgdGhlIGNhbGxiYWNrIHdpdGggYGVycmAgYW5kIGByZXNgXG4gKiBhbmQgaGFuZGxlIGFyaXR5IGNoZWNrLlxuICpcbiAqIEBwYXJhbSB7RXJyb3J9IGVyclxuICogQHBhcmFtIHtSZXNwb25zZX0gcmVzXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYWxsYmFjayA9IGZ1bmN0aW9uIChlcnIsIHJlcykge1xuICBpZiAodGhpcy5fc2hvdWxkUmV0cnkoZXJyLCByZXMpKSB7XG4gICAgcmV0dXJuIHRoaXMuX3JldHJ5KCk7XG4gIH1cblxuICAvLyBBdm9pZCB0aGUgZXJyb3Igd2hpY2ggaXMgZW1pdHRlZCBmcm9tICdzb2NrZXQgaGFuZyB1cCcgdG8gY2F1c2UgdGhlIGZuIHVuZGVmaW5lZCBlcnJvciBvbiBKUyBydW50aW1lLlxuICBjb25zdCBmbiA9IHRoaXMuX2NhbGxiYWNrIHx8IG5vb3A7XG4gIHRoaXMuY2xlYXJUaW1lb3V0KCk7XG4gIGlmICh0aGlzLmNhbGxlZCkgcmV0dXJuIGNvbnNvbGUud2Fybignc3VwZXJhZ2VudDogZG91YmxlIGNhbGxiYWNrIGJ1ZycpO1xuICB0aGlzLmNhbGxlZCA9IHRydWU7XG5cbiAgaWYgKCFlcnIpIHtcbiAgICB0cnkge1xuICAgICAgaWYgKCF0aGlzLl9pc1Jlc3BvbnNlT0socmVzKSkge1xuICAgICAgICBsZXQgbXNnID0gJ1Vuc3VjY2Vzc2Z1bCBIVFRQIHJlc3BvbnNlJztcbiAgICAgICAgaWYgKHJlcykge1xuICAgICAgICAgIG1zZyA9IGh0dHAuU1RBVFVTX0NPREVTW3Jlcy5zdGF0dXNdIHx8IG1zZztcbiAgICAgICAgfVxuXG4gICAgICAgIGVyciA9IG5ldyBFcnJvcihtc2cpO1xuICAgICAgICBlcnIuc3RhdHVzID0gcmVzID8gcmVzLnN0YXR1cyA6IHVuZGVmaW5lZDtcbiAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJfKSB7XG4gICAgICBlcnIgPSBlcnJfO1xuICAgIH1cbiAgfVxuXG4gIC8vIEl0J3MgaW1wb3J0YW50IHRoYXQgdGhlIGNhbGxiYWNrIGlzIGNhbGxlZCBvdXRzaWRlIHRyeS9jYXRjaFxuICAvLyB0byBhdm9pZCBkb3VibGUgY2FsbGJhY2tcbiAgaWYgKCFlcnIpIHtcbiAgICByZXR1cm4gZm4obnVsbCwgcmVzKTtcbiAgfVxuXG4gIGVyci5yZXNwb25zZSA9IHJlcztcbiAgaWYgKHRoaXMuX21heFJldHJpZXMpIGVyci5yZXRyaWVzID0gdGhpcy5fcmV0cmllcyAtIDE7XG5cbiAgLy8gb25seSBlbWl0IGVycm9yIGV2ZW50IGlmIHRoZXJlIGlzIGEgbGlzdGVuZXJcbiAgLy8gb3RoZXJ3aXNlIHdlIGFzc3VtZSB0aGUgY2FsbGJhY2sgdG8gYC5lbmQoKWAgd2lsbCBnZXQgdGhlIGVycm9yXG4gIGlmIChlcnIgJiYgdGhpcy5saXN0ZW5lcnMoJ2Vycm9yJykubGVuZ3RoID4gMCkge1xuICAgIHRoaXMuZW1pdCgnZXJyb3InLCBlcnIpO1xuICB9XG5cbiAgZm4oZXJyLCByZXMpO1xufTtcblxuLyoqXG4gKiBDaGVjayBpZiBgb2JqYCBpcyBhIGhvc3Qgb2JqZWN0LFxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmogaG9zdCBvYmplY3RcbiAqIEByZXR1cm4ge0Jvb2xlYW59IGlzIGEgaG9zdCBvYmplY3RcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5SZXF1ZXN0LnByb3RvdHlwZS5faXNIb3N0ID0gZnVuY3Rpb24gKG9iaikge1xuICByZXR1cm4gKFxuICAgIEJ1ZmZlci5pc0J1ZmZlcihvYmopIHx8IG9iaiBpbnN0YW5jZW9mIFN0cmVhbSB8fCBvYmogaW5zdGFuY2VvZiBGb3JtRGF0YVxuICApO1xufTtcblxuLyoqXG4gKiBJbml0aWF0ZSByZXF1ZXN0LCBpbnZva2luZyBjYWxsYmFjayBgZm4oZXJyLCByZXMpYFxuICogd2l0aCBhbiBpbnN0YW5jZW9mIGBSZXNwb25zZWAuXG4gKlxuICogQHBhcmFtIHtGdW5jdGlvbn0gZm5cbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fZW1pdFJlc3BvbnNlID0gZnVuY3Rpb24gKGJvZHksIGZpbGVzKSB7XG4gIGNvbnN0IHJlc3BvbnNlID0gbmV3IFJlc3BvbnNlKHRoaXMpO1xuICB0aGlzLnJlc3BvbnNlID0gcmVzcG9uc2U7XG4gIHJlc3BvbnNlLnJlZGlyZWN0cyA9IHRoaXMuX3JlZGlyZWN0TGlzdDtcbiAgaWYgKHVuZGVmaW5lZCAhPT0gYm9keSkge1xuICAgIHJlc3BvbnNlLmJvZHkgPSBib2R5O1xuICB9XG5cbiAgcmVzcG9uc2UuZmlsZXMgPSBmaWxlcztcbiAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgIHJlc3BvbnNlLnBpcGUgPSBmdW5jdGlvbiAoKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXG4gICAgICAgIFwiZW5kKCkgaGFzIGFscmVhZHkgYmVlbiBjYWxsZWQsIHNvIGl0J3MgdG9vIGxhdGUgdG8gc3RhcnQgcGlwaW5nXCJcbiAgICAgICk7XG4gICAgfTtcbiAgfVxuXG4gIHRoaXMuZW1pdCgncmVzcG9uc2UnLCByZXNwb25zZSk7XG4gIHJldHVybiByZXNwb25zZTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLmVuZCA9IGZ1bmN0aW9uIChmbikge1xuICB0aGlzLnJlcXVlc3QoKTtcbiAgZGVidWcoJyVzICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsKTtcblxuICBpZiAodGhpcy5fZW5kQ2FsbGVkKSB7XG4gICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgJy5lbmQoKSB3YXMgY2FsbGVkIHR3aWNlLiBUaGlzIGlzIG5vdCBzdXBwb3J0ZWQgaW4gc3VwZXJhZ2VudCdcbiAgICApO1xuICB9XG5cbiAgdGhpcy5fZW5kQ2FsbGVkID0gdHJ1ZTtcblxuICAvLyBzdG9yZSBjYWxsYmFja1xuICB0aGlzLl9jYWxsYmFjayA9IGZuIHx8IG5vb3A7XG5cbiAgdGhpcy5fZW5kKCk7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fZW5kID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpcy5fYWJvcnRlZClcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhcbiAgICAgIG5ldyBFcnJvcignVGhlIHJlcXVlc3QgaGFzIGJlZW4gYWJvcnRlZCBldmVuIGJlZm9yZSAuZW5kKCkgd2FzIGNhbGxlZCcpXG4gICAgKTtcblxuICBsZXQgZGF0YSA9IHRoaXMuX2RhdGE7XG4gIGNvbnN0IHsgcmVxIH0gPSB0aGlzO1xuICBjb25zdCB7IG1ldGhvZCB9ID0gdGhpcztcblxuICB0aGlzLl9zZXRUaW1lb3V0cygpO1xuXG4gIC8vIGJvZHlcbiAgaWYgKG1ldGhvZCAhPT0gJ0hFQUQnICYmICFyZXEuX2hlYWRlclNlbnQpIHtcbiAgICAvLyBzZXJpYWxpemUgc3R1ZmZcbiAgICBpZiAodHlwZW9mIGRhdGEgIT09ICdzdHJpbmcnKSB7XG4gICAgICBsZXQgY29udGVudFR5cGUgPSByZXEuZ2V0SGVhZGVyKCdDb250ZW50LVR5cGUnKTtcbiAgICAgIC8vIFBhcnNlIG91dCBqdXN0IHRoZSBjb250ZW50IHR5cGUgZnJvbSB0aGUgaGVhZGVyIChpZ25vcmUgdGhlIGNoYXJzZXQpXG4gICAgICBpZiAoY29udGVudFR5cGUpIGNvbnRlbnRUeXBlID0gY29udGVudFR5cGUuc3BsaXQoJzsnKVswXTtcbiAgICAgIGxldCBzZXJpYWxpemUgPSB0aGlzLl9zZXJpYWxpemVyIHx8IGV4cG9ydHMuc2VyaWFsaXplW2NvbnRlbnRUeXBlXTtcbiAgICAgIGlmICghc2VyaWFsaXplICYmIGlzSlNPTihjb250ZW50VHlwZSkpIHtcbiAgICAgICAgc2VyaWFsaXplID0gZXhwb3J0cy5zZXJpYWxpemVbJ2FwcGxpY2F0aW9uL2pzb24nXTtcbiAgICAgIH1cblxuICAgICAgaWYgKHNlcmlhbGl6ZSkgZGF0YSA9IHNlcmlhbGl6ZShkYXRhKTtcbiAgICB9XG5cbiAgICAvLyBjb250ZW50LWxlbmd0aFxuICAgIGlmIChkYXRhICYmICFyZXEuZ2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcpKSB7XG4gICAgICByZXEuc2V0SGVhZGVyKFxuICAgICAgICAnQ29udGVudC1MZW5ndGgnLFxuICAgICAgICBCdWZmZXIuaXNCdWZmZXIoZGF0YSkgPyBkYXRhLmxlbmd0aCA6IEJ1ZmZlci5ieXRlTGVuZ3RoKGRhdGEpXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIC8vIHJlc3BvbnNlXG4gIC8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG4gIHJlcS5vbmNlKCdyZXNwb25zZScsIChyZXMpID0+IHtcbiAgICBkZWJ1ZygnJXMgJXMgLT4gJXMnLCB0aGlzLm1ldGhvZCwgdGhpcy51cmwsIHJlcy5zdGF0dXNDb2RlKTtcblxuICAgIGlmICh0aGlzLl9yZXNwb25zZVRpbWVvdXRUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHRoaXMuX3Jlc3BvbnNlVGltZW91dFRpbWVyKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5waXBlZCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIGNvbnN0IG1heCA9IHRoaXMuX21heFJlZGlyZWN0cztcbiAgICBjb25zdCBtaW1lID0gdXRpbHMudHlwZShyZXMuaGVhZGVyc1snY29udGVudC10eXBlJ10gfHwgJycpIHx8ICd0ZXh0L3BsYWluJztcbiAgICBsZXQgdHlwZSA9IG1pbWUuc3BsaXQoJy8nKVswXTtcbiAgICBpZiAodHlwZSkgdHlwZSA9IHR5cGUudG9Mb3dlckNhc2UoKS50cmltKCk7XG4gICAgY29uc3QgbXVsdGlwYXJ0ID0gdHlwZSA9PT0gJ211bHRpcGFydCc7XG4gICAgY29uc3QgcmVkaXJlY3QgPSBpc1JlZGlyZWN0KHJlcy5zdGF0dXNDb2RlKTtcbiAgICBjb25zdCByZXNwb25zZVR5cGUgPSB0aGlzLl9yZXNwb25zZVR5cGU7XG5cbiAgICB0aGlzLnJlcyA9IHJlcztcblxuICAgIC8vIHJlZGlyZWN0XG4gICAgaWYgKHJlZGlyZWN0ICYmIHRoaXMuX3JlZGlyZWN0cysrICE9PSBtYXgpIHtcbiAgICAgIHJldHVybiB0aGlzLl9yZWRpcmVjdChyZXMpO1xuICAgIH1cblxuICAgIGlmICh0aGlzLm1ldGhvZCA9PT0gJ0hFQUQnKSB7XG4gICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2UoKSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gemxpYiBzdXBwb3J0XG4gICAgaWYgKHRoaXMuX3Nob3VsZFVuemlwKHJlcykpIHtcbiAgICAgIHVuemlwKHJlcSwgcmVzKTtcbiAgICB9XG5cbiAgICBsZXQgYnVmZmVyID0gdGhpcy5fYnVmZmVyO1xuICAgIGlmIChidWZmZXIgPT09IHVuZGVmaW5lZCAmJiBtaW1lIGluIGV4cG9ydHMuYnVmZmVyKSB7XG4gICAgICBidWZmZXIgPSBCb29sZWFuKGV4cG9ydHMuYnVmZmVyW21pbWVdKTtcbiAgICB9XG5cbiAgICBsZXQgcGFyc2VyID0gdGhpcy5fcGFyc2VyO1xuICAgIGlmICh1bmRlZmluZWQgPT09IGJ1ZmZlcikge1xuICAgICAgaWYgKHBhcnNlcikge1xuICAgICAgICBjb25zb2xlLndhcm4oXG4gICAgICAgICAgXCJBIGN1c3RvbSBzdXBlcmFnZW50IHBhcnNlciBoYXMgYmVlbiBzZXQsIGJ1dCBidWZmZXJpbmcgc3RyYXRlZ3kgZm9yIHRoZSBwYXJzZXIgaGFzbid0IGJlZW4gY29uZmlndXJlZC4gQ2FsbCBgcmVxLmJ1ZmZlcih0cnVlIG9yIGZhbHNlKWAgb3Igc2V0IGBzdXBlcmFnZW50LmJ1ZmZlclttaW1lXSA9IHRydWUgb3IgZmFsc2VgXCJcbiAgICAgICAgKTtcbiAgICAgICAgYnVmZmVyID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICBpZiAoIXBhcnNlcikge1xuICAgICAgaWYgKHJlc3BvbnNlVHlwZSkge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlLmltYWdlOyAvLyBJdCdzIGFjdHVhbGx5IGEgZ2VuZXJpYyBCdWZmZXJcbiAgICAgICAgYnVmZmVyID0gdHJ1ZTtcbiAgICAgIH0gZWxzZSBpZiAobXVsdGlwYXJ0KSB7XG4gICAgICAgIGNvbnN0IGZvcm0gPSBuZXcgZm9ybWlkYWJsZS5JbmNvbWluZ0Zvcm0oKTtcbiAgICAgICAgcGFyc2VyID0gZm9ybS5wYXJzZS5iaW5kKGZvcm0pO1xuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfSBlbHNlIGlmIChpc0ltYWdlT3JWaWRlbyhtaW1lKSkge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlLmltYWdlO1xuICAgICAgICBidWZmZXIgPSB0cnVlOyAvLyBGb3IgYmFja3dhcmRzLWNvbXBhdGliaWxpdHkgYnVmZmVyaW5nIGRlZmF1bHQgaXMgYWQtaG9jIE1JTUUtZGVwZW5kZW50XG4gICAgICB9IGVsc2UgaWYgKGV4cG9ydHMucGFyc2VbbWltZV0pIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZVttaW1lXTtcbiAgICAgIH0gZWxzZSBpZiAodHlwZSA9PT0gJ3RleHQnKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UudGV4dDtcbiAgICAgICAgYnVmZmVyID0gYnVmZmVyICE9PSBmYWxzZTtcblxuICAgICAgICAvLyBldmVyeW9uZSB3YW50cyB0aGVpciBvd24gd2hpdGUtbGFiZWxlZCBqc29uXG4gICAgICB9IGVsc2UgaWYgKGlzSlNPTihtaW1lKSkge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlWydhcHBsaWNhdGlvbi9qc29uJ107XG4gICAgICAgIGJ1ZmZlciA9IGJ1ZmZlciAhPT0gZmFsc2U7XG4gICAgICB9IGVsc2UgaWYgKGJ1ZmZlcikge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlLnRleHQ7XG4gICAgICB9IGVsc2UgaWYgKHVuZGVmaW5lZCA9PT0gYnVmZmVyKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2UuaW1hZ2U7IC8vIEl0J3MgYWN0dWFsbHkgYSBnZW5lcmljIEJ1ZmZlclxuICAgICAgICBidWZmZXIgPSB0cnVlO1xuICAgICAgfVxuICAgIH1cblxuICAgIC8vIGJ5IGRlZmF1bHQgb25seSBidWZmZXIgdGV4dC8qLCBqc29uIGFuZCBtZXNzZWQgdXAgdGhpbmcgZnJvbSBoZWxsXG4gICAgaWYgKCh1bmRlZmluZWQgPT09IGJ1ZmZlciAmJiBpc1RleHQobWltZSkpIHx8IGlzSlNPTihtaW1lKSkge1xuICAgICAgYnVmZmVyID0gdHJ1ZTtcbiAgICB9XG5cbiAgICB0aGlzLl9yZXNCdWZmZXJlZCA9IGJ1ZmZlcjtcbiAgICBsZXQgcGFyc2VySGFuZGxlc0VuZCA9IGZhbHNlO1xuICAgIGlmIChidWZmZXIpIHtcbiAgICAgIC8vIFByb3RlY3Rpb25hIGFnYWluc3QgemlwIGJvbWJzIGFuZCBvdGhlciBudWlzYW5jZVxuICAgICAgbGV0IHJlc3BvbnNlQnl0ZXNMZWZ0ID0gdGhpcy5fbWF4UmVzcG9uc2VTaXplIHx8IDIwMDAwMDAwMDtcbiAgICAgIHJlcy5vbignZGF0YScsIChidWYpID0+IHtcbiAgICAgICAgcmVzcG9uc2VCeXRlc0xlZnQgLT0gYnVmLmJ5dGVMZW5ndGggfHwgYnVmLmxlbmd0aDtcbiAgICAgICAgaWYgKHJlc3BvbnNlQnl0ZXNMZWZ0IDwgMCkge1xuICAgICAgICAgIC8vIFRoaXMgd2lsbCBwcm9wYWdhdGUgdGhyb3VnaCBlcnJvciBldmVudFxuICAgICAgICAgIGNvbnN0IGVyciA9IG5ldyBFcnJvcignTWF4aW11bSByZXNwb25zZSBzaXplIHJlYWNoZWQnKTtcbiAgICAgICAgICBlcnIuY29kZSA9ICdFVE9PTEFSR0UnO1xuICAgICAgICAgIC8vIFBhcnNlcnMgYXJlbid0IHJlcXVpcmVkIHRvIG9ic2VydmUgZXJyb3IgZXZlbnQsXG4gICAgICAgICAgLy8gc28gd291bGQgaW5jb3JyZWN0bHkgcmVwb3J0IHN1Y2Nlc3NcbiAgICAgICAgICBwYXJzZXJIYW5kbGVzRW5kID0gZmFsc2U7XG4gICAgICAgICAgLy8gV2lsbCBlbWl0IGVycm9yIGV2ZW50XG4gICAgICAgICAgcmVzLmRlc3Ryb3koZXJyKTtcbiAgICAgICAgfVxuICAgICAgfSk7XG4gICAgfVxuXG4gICAgaWYgKHBhcnNlcikge1xuICAgICAgdHJ5IHtcbiAgICAgICAgLy8gVW5idWZmZXJlZCBwYXJzZXJzIGFyZSBzdXBwb3NlZCB0byBlbWl0IHJlc3BvbnNlIGVhcmx5LFxuICAgICAgICAvLyB3aGljaCBpcyB3ZWlyZCBCVFcsIGJlY2F1c2UgcmVzcG9uc2UuYm9keSB3b24ndCBiZSB0aGVyZS5cbiAgICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGJ1ZmZlcjtcblxuICAgICAgICBwYXJzZXIocmVzLCAoZXJyLCBvYmosIGZpbGVzKSA9PiB7XG4gICAgICAgICAgaWYgKHRoaXMudGltZWRvdXQpIHtcbiAgICAgICAgICAgIC8vIFRpbWVvdXQgaGFzIGFscmVhZHkgaGFuZGxlZCBhbGwgY2FsbGJhY2tzXG4gICAgICAgICAgICByZXR1cm47XG4gICAgICAgICAgfVxuXG4gICAgICAgICAgLy8gSW50ZW50aW9uYWwgKG5vbi10aW1lb3V0KSBhYm9ydCBpcyBzdXBwb3NlZCB0byBwcmVzZXJ2ZSBwYXJ0aWFsIHJlc3BvbnNlLFxuICAgICAgICAgIC8vIGV2ZW4gaWYgaXQgZG9lc24ndCBwYXJzZS5cbiAgICAgICAgICBpZiAoZXJyICYmICF0aGlzLl9hYm9ydGVkKSB7XG4gICAgICAgICAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIGlmIChwYXJzZXJIYW5kbGVzRW5kKSB7XG4gICAgICAgICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2Uob2JqLCBmaWxlcykpO1xuICAgICAgICAgIH1cbiAgICAgICAgfSk7XG4gICAgICB9IGNhdGNoIChlcnIpIHtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhlcnIpO1xuICAgICAgICByZXR1cm47XG4gICAgICB9XG4gICAgfVxuXG4gICAgdGhpcy5yZXMgPSByZXM7XG5cbiAgICAvLyB1bmJ1ZmZlcmVkXG4gICAgaWYgKCFidWZmZXIpIHtcbiAgICAgIGRlYnVnKCd1bmJ1ZmZlcmVkICVzICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsKTtcbiAgICAgIHRoaXMuY2FsbGJhY2sobnVsbCwgdGhpcy5fZW1pdFJlc3BvbnNlKCkpO1xuICAgICAgaWYgKG11bHRpcGFydCkgcmV0dXJuOyAvLyBhbGxvdyBtdWx0aXBhcnQgdG8gaGFuZGxlIGVuZCBldmVudFxuICAgICAgcmVzLm9uY2UoJ2VuZCcsICgpID0+IHtcbiAgICAgICAgZGVidWcoJ2VuZCAlcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG4gICAgICAgIHRoaXMuZW1pdCgnZW5kJyk7XG4gICAgICB9KTtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICAvLyB0ZXJtaW5hdGluZyBldmVudHNcbiAgICByZXMub25jZSgnZXJyb3InLCAoZXJyKSA9PiB7XG4gICAgICBwYXJzZXJIYW5kbGVzRW5kID0gZmFsc2U7XG4gICAgICB0aGlzLmNhbGxiYWNrKGVyciwgbnVsbCk7XG4gICAgfSk7XG4gICAgaWYgKCFwYXJzZXJIYW5kbGVzRW5kKVxuICAgICAgcmVzLm9uY2UoJ2VuZCcsICgpID0+IHtcbiAgICAgICAgZGVidWcoJ2VuZCAlcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG4gICAgICAgIC8vIFRPRE86IHVubGVzcyBidWZmZXJpbmcgZW1pdCBlYXJsaWVyIHRvIHN0cmVhbVxuICAgICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgICB0aGlzLmNhbGxiYWNrKG51bGwsIHRoaXMuX2VtaXRSZXNwb25zZSgpKTtcbiAgICAgIH0pO1xuICB9KTtcblxuICB0aGlzLmVtaXQoJ3JlcXVlc3QnLCB0aGlzKTtcblxuICBjb25zdCBnZXRQcm9ncmVzc01vbml0b3IgPSAoKSA9PiB7XG4gICAgY29uc3QgbGVuZ3RoQ29tcHV0YWJsZSA9IHRydWU7XG4gICAgY29uc3QgdG90YWwgPSByZXEuZ2V0SGVhZGVyKCdDb250ZW50LUxlbmd0aCcpO1xuICAgIGxldCBsb2FkZWQgPSAwO1xuXG4gICAgY29uc3QgcHJvZ3Jlc3MgPSBuZXcgU3RyZWFtLlRyYW5zZm9ybSgpO1xuICAgIHByb2dyZXNzLl90cmFuc2Zvcm0gPSAoY2h1bmssIGVuY29kaW5nLCBjYikgPT4ge1xuICAgICAgbG9hZGVkICs9IGNodW5rLmxlbmd0aDtcbiAgICAgIHRoaXMuZW1pdCgncHJvZ3Jlc3MnLCB7XG4gICAgICAgIGRpcmVjdGlvbjogJ3VwbG9hZCcsXG4gICAgICAgIGxlbmd0aENvbXB1dGFibGUsXG4gICAgICAgIGxvYWRlZCxcbiAgICAgICAgdG90YWxcbiAgICAgIH0pO1xuICAgICAgY2IobnVsbCwgY2h1bmspO1xuICAgIH07XG5cbiAgICByZXR1cm4gcHJvZ3Jlc3M7XG4gIH07XG5cbiAgY29uc3QgYnVmZmVyVG9DaHVua3MgPSAoYnVmZmVyKSA9PiB7XG4gICAgY29uc3QgY2h1bmtTaXplID0gMTYgKiAxMDI0OyAvLyBkZWZhdWx0IGhpZ2hXYXRlck1hcmsgdmFsdWVcbiAgICBjb25zdCBjaHVua2luZyA9IG5ldyBTdHJlYW0uUmVhZGFibGUoKTtcbiAgICBjb25zdCB0b3RhbExlbmd0aCA9IGJ1ZmZlci5sZW5ndGg7XG4gICAgY29uc3QgcmVtYWluZGVyID0gdG90YWxMZW5ndGggJSBjaHVua1NpemU7XG4gICAgY29uc3QgY3V0b2ZmID0gdG90YWxMZW5ndGggLSByZW1haW5kZXI7XG5cbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IGN1dG9mZjsgaSArPSBjaHVua1NpemUpIHtcbiAgICAgIGNvbnN0IGNodW5rID0gYnVmZmVyLnNsaWNlKGksIGkgKyBjaHVua1NpemUpO1xuICAgICAgY2h1bmtpbmcucHVzaChjaHVuayk7XG4gICAgfVxuXG4gICAgaWYgKHJlbWFpbmRlciA+IDApIHtcbiAgICAgIGNvbnN0IHJlbWFpbmRlckJ1ZmZlciA9IGJ1ZmZlci5zbGljZSgtcmVtYWluZGVyKTtcbiAgICAgIGNodW5raW5nLnB1c2gocmVtYWluZGVyQnVmZmVyKTtcbiAgICB9XG5cbiAgICBjaHVua2luZy5wdXNoKG51bGwpOyAvLyBubyBtb3JlIGRhdGFcblxuICAgIHJldHVybiBjaHVua2luZztcbiAgfTtcblxuICAvLyBpZiBhIEZvcm1EYXRhIGluc3RhbmNlIGdvdCBjcmVhdGVkLCB0aGVuIHdlIHNlbmQgdGhhdCBhcyB0aGUgcmVxdWVzdCBib2R5XG4gIGNvbnN0IGZvcm1EYXRhID0gdGhpcy5fZm9ybURhdGE7XG4gIGlmIChmb3JtRGF0YSkge1xuICAgIC8vIHNldCBoZWFkZXJzXG4gICAgY29uc3QgaGVhZGVycyA9IGZvcm1EYXRhLmdldEhlYWRlcnMoKTtcbiAgICBmb3IgKGNvbnN0IGkgaW4gaGVhZGVycykge1xuICAgICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbChoZWFkZXJzLCBpKSkge1xuICAgICAgICBkZWJ1Zygnc2V0dGluZyBGb3JtRGF0YSBoZWFkZXI6IFwiJXM6ICVzXCInLCBpLCBoZWFkZXJzW2ldKTtcbiAgICAgICAgcmVxLnNldEhlYWRlcihpLCBoZWFkZXJzW2ldKTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBhdHRlbXB0IHRvIGdldCBcIkNvbnRlbnQtTGVuZ3RoXCIgaGVhZGVyXG4gICAgZm9ybURhdGEuZ2V0TGVuZ3RoKChlcnIsIGxlbmd0aCkgPT4ge1xuICAgICAgLy8gVE9ETzogQWRkIGNodW5rZWQgZW5jb2Rpbmcgd2hlbiBubyBsZW5ndGggKGlmIGVycilcbiAgICAgIGlmIChlcnIpIGRlYnVnKCdmb3JtRGF0YS5nZXRMZW5ndGggaGFkIGVycm9yJywgZXJyLCBsZW5ndGgpO1xuXG4gICAgICBkZWJ1ZygnZ290IEZvcm1EYXRhIENvbnRlbnQtTGVuZ3RoOiAlcycsIGxlbmd0aCk7XG4gICAgICBpZiAodHlwZW9mIGxlbmd0aCA9PT0gJ251bWJlcicpIHtcbiAgICAgICAgcmVxLnNldEhlYWRlcignQ29udGVudC1MZW5ndGgnLCBsZW5ndGgpO1xuICAgICAgfVxuXG4gICAgICBmb3JtRGF0YS5waXBlKGdldFByb2dyZXNzTW9uaXRvcigpKS5waXBlKHJlcSk7XG4gICAgfSk7XG4gIH0gZWxzZSBpZiAoQnVmZmVyLmlzQnVmZmVyKGRhdGEpKSB7XG4gICAgYnVmZmVyVG9DaHVua3MoZGF0YSkucGlwZShnZXRQcm9ncmVzc01vbml0b3IoKSkucGlwZShyZXEpO1xuICB9IGVsc2Uge1xuICAgIHJlcS5lbmQoZGF0YSk7XG4gIH1cbn07XG5cbi8vIENoZWNrIHdoZXRoZXIgcmVzcG9uc2UgaGFzIGEgbm9uLTAtc2l6ZWQgZ3ppcC1lbmNvZGVkIGJvZHlcblJlcXVlc3QucHJvdG90eXBlLl9zaG91bGRVbnppcCA9IChyZXMpID0+IHtcbiAgaWYgKHJlcy5zdGF0dXNDb2RlID09PSAyMDQgfHwgcmVzLnN0YXR1c0NvZGUgPT09IDMwNCkge1xuICAgIC8vIFRoZXNlIGFyZW4ndCBzdXBwb3NlZCB0byBoYXZlIGFueSBib2R5XG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLy8gaGVhZGVyIGNvbnRlbnQgaXMgYSBzdHJpbmcsIGFuZCBkaXN0aW5jdGlvbiBiZXR3ZWVuIDAgYW5kIG5vIGluZm9ybWF0aW9uIGlzIGNydWNpYWxcbiAgaWYgKHJlcy5oZWFkZXJzWydjb250ZW50LWxlbmd0aCddID09PSAnMCcpIHtcbiAgICAvLyBXZSBrbm93IHRoYXQgdGhlIGJvZHkgaXMgZW1wdHkgKHVuZm9ydHVuYXRlbHksIHRoaXMgY2hlY2sgZG9lcyBub3QgY292ZXIgY2h1bmtlZCBlbmNvZGluZylcbiAgICByZXR1cm4gZmFsc2U7XG4gIH1cblxuICAvLyBjb25zb2xlLmxvZyhyZXMpO1xuICByZXR1cm4gL15cXHMqKD86ZGVmbGF0ZXxnemlwKVxccyokLy50ZXN0KHJlcy5oZWFkZXJzWydjb250ZW50LWVuY29kaW5nJ10pO1xufTtcblxuLyoqXG4gKiBPdmVycmlkZXMgRE5TIGZvciBzZWxlY3RlZCBob3N0bmFtZXMuIFRha2VzIG9iamVjdCBtYXBwaW5nIGhvc3RuYW1lcyB0byBJUCBhZGRyZXNzZXMuXG4gKlxuICogV2hlbiBtYWtpbmcgYSByZXF1ZXN0IHRvIGEgVVJMIHdpdGggYSBob3N0bmFtZSBleGFjdGx5IG1hdGNoaW5nIGEga2V5IGluIHRoZSBvYmplY3QsXG4gKiB1c2UgdGhlIGdpdmVuIElQIGFkZHJlc3MgdG8gY29ubmVjdCwgaW5zdGVhZCBvZiB1c2luZyBETlMgdG8gcmVzb2x2ZSB0aGUgaG9zdG5hbWUuXG4gKlxuICogQSBzcGVjaWFsIGhvc3QgYCpgIG1hdGNoZXMgZXZlcnkgaG9zdG5hbWUgKGtlZXAgcmVkaXJlY3RzIGluIG1pbmQhKVxuICpcbiAqICAgICAgcmVxdWVzdC5jb25uZWN0KHtcbiAqICAgICAgICAndGVzdC5leGFtcGxlLmNvbSc6ICcxMjcuMC4wLjEnLFxuICogICAgICAgICdpcHY2LmV4YW1wbGUuY29tJzogJzo6MScsXG4gKiAgICAgIH0pXG4gKi9cblJlcXVlc3QucHJvdG90eXBlLmNvbm5lY3QgPSBmdW5jdGlvbiAoY29ubmVjdE92ZXJyaWRlKSB7XG4gIGlmICh0eXBlb2YgY29ubmVjdE92ZXJyaWRlID09PSAnc3RyaW5nJykge1xuICAgIHRoaXMuX2Nvbm5lY3RPdmVycmlkZSA9IHsgJyonOiBjb25uZWN0T3ZlcnJpZGUgfTtcbiAgfSBlbHNlIGlmICh0eXBlb2YgY29ubmVjdE92ZXJyaWRlID09PSAnb2JqZWN0Jykge1xuICAgIHRoaXMuX2Nvbm5lY3RPdmVycmlkZSA9IGNvbm5lY3RPdmVycmlkZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLl9jb25uZWN0T3ZlcnJpZGUgPSB1bmRlZmluZWQ7XG4gIH1cblxuICByZXR1cm4gdGhpcztcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLnRydXN0TG9jYWxob3N0ID0gZnVuY3Rpb24gKHRvZ2dsZSkge1xuICB0aGlzLl90cnVzdExvY2FsaG9zdCA9IHRvZ2dsZSA9PT0gdW5kZWZpbmVkID8gdHJ1ZSA6IHRvZ2dsZTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vLyBnZW5lcmF0ZSBIVFRQIHZlcmIgbWV0aG9kc1xuaWYgKCFtZXRob2RzLmluY2x1ZGVzKCdkZWwnKSkge1xuICAvLyBjcmVhdGUgYSBjb3B5IHNvIHdlIGRvbid0IGNhdXNlIGNvbmZsaWN0cyB3aXRoXG4gIC8vIG90aGVyIHBhY2thZ2VzIHVzaW5nIHRoZSBtZXRob2RzIHBhY2thZ2UgYW5kXG4gIC8vIG5wbSAzLnhcbiAgbWV0aG9kcyA9IG1ldGhvZHMuc2xpY2UoMCk7XG4gIG1ldGhvZHMucHVzaCgnZGVsJyk7XG59XG5cbm1ldGhvZHMuZm9yRWFjaCgobWV0aG9kKSA9PiB7XG4gIGNvbnN0IG5hbWUgPSBtZXRob2Q7XG4gIG1ldGhvZCA9IG1ldGhvZCA9PT0gJ2RlbCcgPyAnZGVsZXRlJyA6IG1ldGhvZDtcblxuICBtZXRob2QgPSBtZXRob2QudG9VcHBlckNhc2UoKTtcbiAgcmVxdWVzdFtuYW1lXSA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gICAgY29uc3QgcmVxID0gcmVxdWVzdChtZXRob2QsIHVybCk7XG4gICAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgICBmbiA9IGRhdGE7XG4gICAgICBkYXRhID0gbnVsbDtcbiAgICB9XG5cbiAgICBpZiAoZGF0YSkge1xuICAgICAgaWYgKG1ldGhvZCA9PT0gJ0dFVCcgfHwgbWV0aG9kID09PSAnSEVBRCcpIHtcbiAgICAgICAgcmVxLnF1ZXJ5KGRhdGEpO1xuICAgICAgfSBlbHNlIHtcbiAgICAgICAgcmVxLnNlbmQoZGF0YSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKGZuKSByZXEuZW5kKGZuKTtcbiAgICByZXR1cm4gcmVxO1xuICB9O1xufSk7XG5cbi8qKlxuICogQ2hlY2sgaWYgYG1pbWVgIGlzIHRleHQgYW5kIHNob3VsZCBiZSBidWZmZXJlZC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gbWltZVxuICogQHJldHVybiB7Qm9vbGVhbn1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuZnVuY3Rpb24gaXNUZXh0KG1pbWUpIHtcbiAgY29uc3QgcGFydHMgPSBtaW1lLnNwbGl0KCcvJyk7XG4gIGxldCB0eXBlID0gcGFydHNbMF07XG4gIGlmICh0eXBlKSB0eXBlID0gdHlwZS50b0xvd2VyQ2FzZSgpLnRyaW0oKTtcbiAgbGV0IHN1YnR5cGUgPSBwYXJ0c1sxXTtcbiAgaWYgKHN1YnR5cGUpIHN1YnR5cGUgPSBzdWJ0eXBlLnRvTG93ZXJDYXNlKCkudHJpbSgpO1xuXG4gIHJldHVybiB0eXBlID09PSAndGV4dCcgfHwgc3VidHlwZSA9PT0gJ3gtd3d3LWZvcm0tdXJsZW5jb2RlZCc7XG59XG5cbmZ1bmN0aW9uIGlzSW1hZ2VPclZpZGVvKG1pbWUpIHtcbiAgbGV0IHR5cGUgPSBtaW1lLnNwbGl0KCcvJylbMF07XG4gIGlmICh0eXBlKSB0eXBlID0gdHlwZS50b0xvd2VyQ2FzZSgpLnRyaW0oKTtcblxuICByZXR1cm4gdHlwZSA9PT0gJ2ltYWdlJyB8fCB0eXBlID09PSAndmlkZW8nO1xufVxuXG4vKipcbiAqIENoZWNrIGlmIGBtaW1lYCBpcyBqc29uIG9yIGhhcyAranNvbiBzdHJ1Y3R1cmVkIHN5bnRheCBzdWZmaXguXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IG1pbWVcbiAqIEByZXR1cm4ge0Jvb2xlYW59XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBpc0pTT04obWltZSkge1xuICAvLyBzaG91bGQgbWF0Y2ggL2pzb24gb3IgK2pzb25cbiAgLy8gYnV0IG5vdCAvanNvbi1zZXFcbiAgcmV0dXJuIC9bLytdanNvbigkfFteLVxcd10pL2kudGVzdChtaW1lKTtcbn1cblxuLyoqXG4gKiBDaGVjayBpZiB3ZSBzaG91bGQgZm9sbG93IHRoZSByZWRpcmVjdCBgY29kZWAuXG4gKlxuICogQHBhcmFtIHtOdW1iZXJ9IGNvZGVcbiAqIEByZXR1cm4ge0Jvb2xlYW59XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5mdW5jdGlvbiBpc1JlZGlyZWN0KGNvZGUpIHtcbiAgcmV0dXJuIFszMDEsIDMwMiwgMzAzLCAzMDUsIDMwNywgMzA4XS5pbmNsdWRlcyhjb2RlKTtcbn1cbiJdfQ==