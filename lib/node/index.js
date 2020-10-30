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

    this._getFormData().append(field, file, o);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uLy4uL3NyYy9ub2RlL2luZGV4LmpzIl0sIm5hbWVzIjpbInJlcXVpcmUiLCJwYXJzZSIsImZvcm1hdCIsInJlc29sdmUiLCJTdHJlYW0iLCJodHRwcyIsImh0dHAiLCJmcyIsInpsaWIiLCJ1dGlsIiwicXMiLCJtaW1lIiwibWV0aG9kcyIsIkZvcm1EYXRhIiwiZm9ybWlkYWJsZSIsImRlYnVnIiwiQ29va2llSmFyIiwic2VtdmVyIiwic2FmZVN0cmluZ2lmeSIsInV0aWxzIiwiUmVxdWVzdEJhc2UiLCJ1bnppcCIsIlJlc3BvbnNlIiwiaHR0cDIiLCJndGUiLCJwcm9jZXNzIiwidmVyc2lvbiIsInJlcXVlc3QiLCJtZXRob2QiLCJ1cmwiLCJleHBvcnRzIiwiUmVxdWVzdCIsImVuZCIsImFyZ3VtZW50cyIsImxlbmd0aCIsIm1vZHVsZSIsImFnZW50Iiwibm9vcCIsImRlZmluZSIsInByb3RvY29scyIsInNlcmlhbGl6ZSIsInN0cmluZ2lmeSIsImJ1ZmZlciIsIl9pbml0SGVhZGVycyIsInJlcSIsIl9oZWFkZXIiLCJoZWFkZXIiLCJjYWxsIiwiX2VuYWJsZUh0dHAyIiwiQm9vbGVhbiIsImVudiIsIkhUVFAyX1RFU1QiLCJfYWdlbnQiLCJfZm9ybURhdGEiLCJ3cml0YWJsZSIsIl9yZWRpcmVjdHMiLCJyZWRpcmVjdHMiLCJjb29raWVzIiwiX3F1ZXJ5IiwicXNSYXciLCJfcmVkaXJlY3RMaXN0IiwiX3N0cmVhbVJlcXVlc3QiLCJvbmNlIiwiY2xlYXJUaW1lb3V0IiwiYmluZCIsImluaGVyaXRzIiwicHJvdG90eXBlIiwiYm9vbCIsInVuZGVmaW5lZCIsIkVycm9yIiwiYXR0YWNoV2l0aERlc2NyaXB0aW9uIiwiZmllbGQiLCJmaWxlIiwib3B0aW9ucyIsInRleHRWYWwiLCJfZGF0YSIsIm8iLCJmaWxlbmFtZSIsImNyZWF0ZVJlYWRTdHJlYW0iLCJwYXRoIiwiX2dldEZvcm1EYXRhIiwiYXBwZW5kV2l0aEpzb24iLCJhdHRhY2giLCJhcHBlbmQiLCJvbiIsImVyciIsImNhbGxlZCIsImNhbGxiYWNrIiwiYWJvcnQiLCJ0eXBlIiwic2V0IiwiaW5jbHVkZXMiLCJnZXRUeXBlIiwiYWNjZXB0IiwicXVlcnkiLCJ2YWwiLCJwdXNoIiwiT2JqZWN0IiwiYXNzaWduIiwid3JpdGUiLCJkYXRhIiwiZW5jb2RpbmciLCJwaXBlIiwic3RyZWFtIiwicGlwZWQiLCJfcGlwZUNvbnRpbnVlIiwicmVzIiwiaXNSZWRpcmVjdCIsInN0YXR1c0NvZGUiLCJfbWF4UmVkaXJlY3RzIiwiX3JlZGlyZWN0IiwiX2VtaXRSZXNwb25zZSIsIl9hYm9ydGVkIiwiX3Nob3VsZFVuemlwIiwidW56aXBPYmoiLCJjcmVhdGVVbnppcCIsImNvZGUiLCJlbWl0IiwiX2J1ZmZlciIsImhlYWRlcnMiLCJsb2NhdGlvbiIsInJlc3VtZSIsImdldEhlYWRlcnMiLCJfaGVhZGVycyIsImNoYW5nZXNPcmlnaW4iLCJob3N0IiwiY2xlYW5IZWFkZXIiLCJfZW5kQ2FsbGVkIiwiX2NhbGxiYWNrIiwiYXV0aCIsInVzZXIiLCJwYXNzIiwiZW5jb2RlciIsInN0cmluZyIsIkJ1ZmZlciIsImZyb20iLCJ0b1N0cmluZyIsIl9hdXRoIiwiY2EiLCJjZXJ0IiwiX2NhIiwia2V5IiwiX2tleSIsInBmeCIsImlzQnVmZmVyIiwiX3BmeCIsIl9wYXNzcGhyYXNlIiwicGFzc3BocmFzZSIsIl9jZXJ0IiwiZGlzYWJsZVRMU0NlcnRzIiwiX2Rpc2FibGVUTFNDZXJ0cyIsImluZGljZXMiLCJzdHJpY3ROdWxsSGFuZGxpbmciLCJfZmluYWxpemVRdWVyeVN0cmluZyIsInJldHJpZXMiLCJfcmV0cmllcyIsInF1ZXJ5U3RyaW5nQmFja3RpY2tzIiwicXVlcnlTdGFydEluZGV4IiwiaW5kZXhPZiIsInF1ZXJ5U3RyaW5nIiwic2xpY2UiLCJtYXRjaCIsImkiLCJyZXBsYWNlIiwic2VhcmNoIiwicGF0aG5hbWUiLCJ0ZXN0IiwicHJvdG9jb2wiLCJzcGxpdCIsInVuaXhQYXJ0cyIsInNvY2tldFBhdGgiLCJfY29ubmVjdE92ZXJyaWRlIiwiaG9zdG5hbWUiLCJuZXdIb3N0IiwibmV3UG9ydCIsInBvcnQiLCJyZWplY3RVbmF1dGhvcml6ZWQiLCJOT0RFX1RMU19SRUpFQ1RfVU5BVVRIT1JJWkVEIiwic2VydmVybmFtZSIsIl90cnVzdExvY2FsaG9zdCIsIm1vZCIsInNldFByb3RvY29sIiwic2V0Tm9EZWxheSIsInNldEhlYWRlciIsInJlc3BvbnNlIiwidXNlcm5hbWUiLCJwYXNzd29yZCIsImhhc093blByb3BlcnR5IiwidG1wSmFyIiwic2V0Q29va2llcyIsImNvb2tpZSIsImdldENvb2tpZXMiLCJDb29raWVBY2Nlc3NJbmZvIiwiQWxsIiwidG9WYWx1ZVN0cmluZyIsIl9zaG91bGRSZXRyeSIsIl9yZXRyeSIsImZuIiwiY29uc29sZSIsIndhcm4iLCJfaXNSZXNwb25zZU9LIiwibXNnIiwiU1RBVFVTX0NPREVTIiwic3RhdHVzIiwiZXJyXyIsIl9tYXhSZXRyaWVzIiwibGlzdGVuZXJzIiwiX2lzSG9zdCIsIm9iaiIsImJvZHkiLCJmaWxlcyIsIl9lbmQiLCJfc2V0VGltZW91dHMiLCJfaGVhZGVyU2VudCIsImNvbnRlbnRUeXBlIiwiZ2V0SGVhZGVyIiwiX3NlcmlhbGl6ZXIiLCJpc0pTT04iLCJieXRlTGVuZ3RoIiwiX3Jlc3BvbnNlVGltZW91dFRpbWVyIiwibWF4IiwidG9Mb3dlckNhc2UiLCJ0cmltIiwibXVsdGlwYXJ0IiwicmVkaXJlY3QiLCJyZXNwb25zZVR5cGUiLCJfcmVzcG9uc2VUeXBlIiwicGFyc2VyIiwiX3BhcnNlciIsImltYWdlIiwiZm9ybSIsIkluY29taW5nRm9ybSIsImlzSW1hZ2VPclZpZGVvIiwidGV4dCIsImlzVGV4dCIsIl9yZXNCdWZmZXJlZCIsInBhcnNlckhhbmRsZXNFbmQiLCJyZXNwb25zZUJ5dGVzTGVmdCIsIl9tYXhSZXNwb25zZVNpemUiLCJidWYiLCJkZXN0cm95IiwidGltZWRvdXQiLCJnZXRQcm9ncmVzc01vbml0b3IiLCJsZW5ndGhDb21wdXRhYmxlIiwidG90YWwiLCJsb2FkZWQiLCJwcm9ncmVzcyIsIlRyYW5zZm9ybSIsIl90cmFuc2Zvcm0iLCJjaHVuayIsImNiIiwiZGlyZWN0aW9uIiwiYnVmZmVyVG9DaHVua3MiLCJjaHVua1NpemUiLCJjaHVua2luZyIsIlJlYWRhYmxlIiwidG90YWxMZW5ndGgiLCJyZW1haW5kZXIiLCJjdXRvZmYiLCJyZW1haW5kZXJCdWZmZXIiLCJmb3JtRGF0YSIsImdldExlbmd0aCIsImNvbm5lY3QiLCJjb25uZWN0T3ZlcnJpZGUiLCJ0cnVzdExvY2FsaG9zdCIsInRvZ2dsZSIsImZvckVhY2giLCJuYW1lIiwidG9VcHBlckNhc2UiLCJzZW5kIiwicGFydHMiLCJzdWJ0eXBlIl0sIm1hcHBpbmdzIjoiOzs7O0FBQUE7QUFDQTtBQUNBO0FBRUE7ZUFDbUNBLE9BQU8sQ0FBQyxLQUFELEM7SUFBbENDLEssWUFBQUEsSztJQUFPQyxNLFlBQUFBLE07SUFBUUMsTyxZQUFBQSxPOztBQUN2QixJQUFNQyxNQUFNLEdBQUdKLE9BQU8sQ0FBQyxRQUFELENBQXRCOztBQUNBLElBQU1LLEtBQUssR0FBR0wsT0FBTyxDQUFDLE9BQUQsQ0FBckI7O0FBQ0EsSUFBTU0sSUFBSSxHQUFHTixPQUFPLENBQUMsTUFBRCxDQUFwQjs7QUFDQSxJQUFNTyxFQUFFLEdBQUdQLE9BQU8sQ0FBQyxJQUFELENBQWxCOztBQUNBLElBQU1RLElBQUksR0FBR1IsT0FBTyxDQUFDLE1BQUQsQ0FBcEI7O0FBQ0EsSUFBTVMsSUFBSSxHQUFHVCxPQUFPLENBQUMsTUFBRCxDQUFwQjs7QUFDQSxJQUFNVSxFQUFFLEdBQUdWLE9BQU8sQ0FBQyxJQUFELENBQWxCOztBQUNBLElBQU1XLElBQUksR0FBR1gsT0FBTyxDQUFDLE1BQUQsQ0FBcEI7O0FBQ0EsSUFBSVksT0FBTyxHQUFHWixPQUFPLENBQUMsU0FBRCxDQUFyQjs7QUFDQSxJQUFNYSxRQUFRLEdBQUdiLE9BQU8sQ0FBQyx5QkFBRCxDQUF4Qjs7QUFDQSxJQUFNYyxVQUFVLEdBQUdkLE9BQU8sQ0FBQyxZ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ZW50IjpbIi8qKlxuICogTW9kdWxlIGRlcGVuZGVuY2llcy5cbiAqL1xuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbm9kZS9uby1kZXByZWNhdGVkLWFwaVxuY29uc3QgeyBwYXJzZSwgZm9ybWF0LCByZXNvbHZlIH0gPSByZXF1aXJlKCd1cmwnKTtcbmNvbnN0IFN0cmVhbSA9IHJlcXVpcmUoJ3N0cmVhbScpO1xuY29uc3QgaHR0cHMgPSByZXF1aXJlKCdodHRwcycpO1xuY29uc3QgaHR0cCA9IHJlcXVpcmUoJ2h0dHAnKTtcbmNvbnN0IGZzID0gcmVxdWlyZSgnZnMnKTtcbmNvbnN0IHpsaWIgPSByZXF1aXJlKCd6bGliJyk7XG5jb25zdCB1dGlsID0gcmVxdWlyZSgndXRpbCcpO1xuY29uc3QgcXMgPSByZXF1aXJlKCdxcycpO1xuY29uc3QgbWltZSA9IHJlcXVpcmUoJ21pbWUnKTtcbmxldCBtZXRob2RzID0gcmVxdWlyZSgnbWV0aG9kcycpO1xuY29uc3QgRm9ybURhdGEgPSByZXF1aXJlKCdmb3JtLWRhdGEtbWl4ZWQtZHJvcGJveCcpO1xuY29uc3QgZm9ybWlkYWJsZSA9IHJlcXVpcmUoJ2Zvcm1pZGFibGUnKTtcbmNvbnN0IGRlYnVnID0gcmVxdWlyZSgnZGVidWcnKSgnc3VwZXJhZ2VudCcpO1xuY29uc3QgQ29va2llSmFyID0gcmVxdWlyZSgnY29va2llamFyJyk7XG5jb25zdCBzZW12ZXIgPSByZXF1aXJlKCdzZW12ZXInKTtcbmNvbnN0IHNhZmVTdHJpbmdpZnkgPSByZXF1aXJlKCdmYXN0LXNhZmUtc3RyaW5naWZ5Jyk7XG5cbmNvbnN0IHV0aWxzID0gcmVxdWlyZSgnLi4vdXRpbHMnKTtcbmNvbnN0IFJlcXVlc3RCYXNlID0gcmVxdWlyZSgnLi4vcmVxdWVzdC1iYXNlJyk7XG5jb25zdCB7IHVuemlwIH0gPSByZXF1aXJlKCcuL3VuemlwJyk7XG5jb25zdCBSZXNwb25zZSA9IHJlcXVpcmUoJy4vcmVzcG9uc2UnKTtcblxubGV0IGh0dHAyO1xuXG5pZiAoc2VtdmVyLmd0ZShwcm9jZXNzLnZlcnNpb24sICd2MTAuMTAuMCcpKSBodHRwMiA9IHJlcXVpcmUoJy4vaHR0cDJ3cmFwcGVyJyk7XG5cbmZ1bmN0aW9uIHJlcXVlc3QobWV0aG9kLCB1cmwpIHtcbiAgLy8gY2FsbGJhY2tcbiAgaWYgKHR5cGVvZiB1cmwgPT09ICdmdW5jdGlvbicpIHtcbiAgICByZXR1cm4gbmV3IGV4cG9ydHMuUmVxdWVzdCgnR0VUJywgbWV0aG9kKS5lbmQodXJsKTtcbiAgfVxuXG4gIC8vIHVybCBmaXJzdFxuICBpZiAoYXJndW1lbnRzLmxlbmd0aCA9PT0gMSkge1xuICAgIHJldHVybiBuZXcgZXhwb3J0cy5SZXF1ZXN0KCdHRVQnLCBtZXRob2QpO1xuICB9XG5cbiAgcmV0dXJuIG5ldyBleHBvcnRzLlJlcXVlc3QobWV0aG9kLCB1cmwpO1xufVxuXG5tb2R1bGUuZXhwb3J0cyA9IHJlcXVlc3Q7XG5leHBvcnRzID0gbW9kdWxlLmV4cG9ydHM7XG5cbi8qKlxuICogRXhwb3NlIGBSZXF1ZXN0YC5cbiAqL1xuXG5leHBvcnRzLlJlcXVlc3QgPSBSZXF1ZXN0O1xuXG4vKipcbiAqIEV4cG9zZSB0aGUgYWdlbnQgZnVuY3Rpb25cbiAqL1xuXG5leHBvcnRzLmFnZW50ID0gcmVxdWlyZSgnLi9hZ2VudCcpO1xuXG4vKipcbiAqIE5vb3AuXG4gKi9cblxuZnVuY3Rpb24gbm9vcCgpIHt9XG5cbi8qKlxuICogRXhwb3NlIGBSZXNwb25zZWAuXG4gKi9cblxuZXhwb3J0cy5SZXNwb25zZSA9IFJlc3BvbnNlO1xuXG4vKipcbiAqIERlZmluZSBcImZvcm1cIiBtaW1lIHR5cGUuXG4gKi9cblxubWltZS5kZWZpbmUoXG4gIHtcbiAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJzogWydmb3JtJywgJ3VybGVuY29kZWQnLCAnZm9ybS1kYXRhJ11cbiAgfSxcbiAgdHJ1ZVxuKTtcblxuLyoqXG4gKiBQcm90b2NvbCBtYXAuXG4gKi9cblxuZXhwb3J0cy5wcm90b2NvbHMgPSB7XG4gICdodHRwOic6IGh0dHAsXG4gICdodHRwczonOiBodHRwcyxcbiAgJ2h0dHAyOic6IGh0dHAyXG59O1xuXG4vKipcbiAqIERlZmF1bHQgc2VyaWFsaXphdGlvbiBtYXAuXG4gKlxuICogICAgIHN1cGVyYWdlbnQuc2VyaWFsaXplWydhcHBsaWNhdGlvbi94bWwnXSA9IGZ1bmN0aW9uKG9iail7XG4gKiAgICAgICByZXR1cm4gJ2dlbmVyYXRlZCB4bWwgaGVyZSc7XG4gKiAgICAgfTtcbiAqXG4gKi9cblxuZXhwb3J0cy5zZXJpYWxpemUgPSB7XG4gICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnOiBxcy5zdHJpbmdpZnksXG4gICdhcHBsaWNhdGlvbi9qc29uJzogc2FmZVN0cmluZ2lmeVxufTtcblxuLyoqXG4gKiBEZWZhdWx0IHBhcnNlcnMuXG4gKlxuICogICAgIHN1cGVyYWdlbnQucGFyc2VbJ2FwcGxpY2F0aW9uL3htbCddID0gZnVuY3Rpb24ocmVzLCBmbil7XG4gKiAgICAgICBmbihudWxsLCByZXMpO1xuICogICAgIH07XG4gKlxuICovXG5cbmV4cG9ydHMucGFyc2UgPSByZXF1aXJlKCcuL3BhcnNlcnMnKTtcblxuLyoqXG4gKiBEZWZhdWx0IGJ1ZmZlcmluZyBtYXAuIENhbiBiZSB1c2VkIHRvIHNldCBjZXJ0YWluXG4gKiByZXNwb25zZSB0eXBlcyB0byBidWZmZXIvbm90IGJ1ZmZlci5cbiAqXG4gKiAgICAgc3VwZXJhZ2VudC5idWZmZXJbJ2FwcGxpY2F0aW9uL3htbCddID0gdHJ1ZTtcbiAqL1xuZXhwb3J0cy5idWZmZXIgPSB7fTtcblxuLyoqXG4gKiBJbml0aWFsaXplIGludGVybmFsIGhlYWRlciB0cmFja2luZyBwcm9wZXJ0aWVzIG9uIGEgcmVxdWVzdCBpbnN0YW5jZS5cbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gcmVxIHRoZSBpbnN0YW5jZVxuICogQGFwaSBwcml2YXRlXG4gKi9cbmZ1bmN0aW9uIF9pbml0SGVhZGVycyhyZXEpIHtcbiAgcmVxLl9oZWFkZXIgPSB7XG4gICAgLy8gY29lcmNlcyBoZWFkZXIgbmFtZXMgdG8gbG93ZXJjYXNlXG4gIH07XG4gIHJlcS5oZWFkZXIgPSB7XG4gICAgLy8gcHJlc2VydmVzIGhlYWRlciBuYW1lIGNhc2VcbiAgfTtcbn1cblxuLyoqXG4gKiBJbml0aWFsaXplIGEgbmV3IGBSZXF1ZXN0YCB3aXRoIHRoZSBnaXZlbiBgbWV0aG9kYCBhbmQgYHVybGAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IG1ldGhvZFxuICogQHBhcmFtIHtTdHJpbmd8T2JqZWN0fSB1cmxcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuZnVuY3Rpb24gUmVxdWVzdChtZXRob2QsIHVybCkge1xuICBTdHJlYW0uY2FsbCh0aGlzKTtcbiAgaWYgKHR5cGVvZiB1cmwgIT09ICdzdHJpbmcnKSB1cmwgPSBmb3JtYXQodXJsKTtcbiAgdGhpcy5fZW5hYmxlSHR0cDIgPSBCb29sZWFuKHByb2Nlc3MuZW52LkhUVFAyX1RFU1QpOyAvLyBpbnRlcm5hbCBvbmx5XG4gIHRoaXMuX2FnZW50ID0gZmFsc2U7XG4gIHRoaXMuX2Zvcm1EYXRhID0gbnVsbDtcbiAgdGhpcy5tZXRob2QgPSBtZXRob2Q7XG4gIHRoaXMudXJsID0gdXJsO1xuICBfaW5pdEhlYWRlcnModGhpcyk7XG4gIHRoaXMud3JpdGFibGUgPSB0cnVlO1xuICB0aGlzLl9yZWRpcmVjdHMgPSAwO1xuICB0aGlzLnJlZGlyZWN0cyhtZXRob2QgPT09ICdIRUFEJyA/IDAgOiA1KTtcbiAgdGhpcy5jb29raWVzID0gJyc7XG4gIHRoaXMucXMgPSB7fTtcbiAgdGhpcy5fcXVlcnkgPSBbXTtcbiAgdGhpcy5xc1JhdyA9IHRoaXMuX3F1ZXJ5OyAvLyBVbnVzZWQsIGZvciBiYWNrd2FyZHMgY29tcGF0aWJpbGl0eSBvbmx5XG4gIHRoaXMuX3JlZGlyZWN0TGlzdCA9IFtdO1xuICB0aGlzLl9zdHJlYW1SZXF1ZXN0ID0gZmFsc2U7XG4gIHRoaXMub25jZSgnZW5kJywgdGhpcy5jbGVhclRpbWVvdXQuYmluZCh0aGlzKSk7XG59XG5cbi8qKlxuICogSW5oZXJpdCBmcm9tIGBTdHJlYW1gICh3aGljaCBpbmhlcml0cyBmcm9tIGBFdmVudEVtaXR0ZXJgKS5cbiAqIE1peGluIGBSZXF1ZXN0QmFzZWAuXG4gKi9cbnV0aWwuaW5oZXJpdHMoUmVxdWVzdCwgU3RyZWFtKTtcbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuZXctY2FwXG5SZXF1ZXN0QmFzZShSZXF1ZXN0LnByb3RvdHlwZSk7XG5cbi8qKlxuICogRW5hYmxlIG9yIERpc2FibGUgaHR0cDIuXG4gKlxuICogRW5hYmxlIGh0dHAyLlxuICpcbiAqIGBgYCBqc1xuICogcmVxdWVzdC5nZXQoJ2h0dHA6Ly9sb2NhbGhvc3QvJylcbiAqICAgLmh0dHAyKClcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogcmVxdWVzdC5nZXQoJ2h0dHA6Ly9sb2NhbGhvc3QvJylcbiAqICAgLmh0dHAyKHRydWUpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogRGlzYWJsZSBodHRwMi5cbiAqXG4gKiBgYGAganNcbiAqIHJlcXVlc3QgPSByZXF1ZXN0Lmh0dHAyKCk7XG4gKiByZXF1ZXN0LmdldCgnaHR0cDovL2xvY2FsaG9zdC8nKVxuICogICAuaHR0cDIoZmFsc2UpXG4gKiAgIC5lbmQoY2FsbGJhY2spO1xuICogYGBgXG4gKlxuICogQHBhcmFtIHtCb29sZWFufSBlbmFibGVcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5odHRwMiA9IGZ1bmN0aW9uIChib29sKSB7XG4gIGlmIChleHBvcnRzLnByb3RvY29sc1snaHR0cDI6J10gPT09IHVuZGVmaW5lZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICdzdXBlcmFnZW50OiB0aGlzIHZlcnNpb24gb2YgTm9kZS5qcyBkb2VzIG5vdCBzdXBwb3J0IGh0dHAyJ1xuICAgICk7XG4gIH1cblxuICB0aGlzLl9lbmFibGVIdHRwMiA9IGJvb2wgPT09IHVuZGVmaW5lZCA/IHRydWUgOiBib29sO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUXVldWUgdGhlIGdpdmVuIGBmaWxlYCBhcyBhbiBhdHRhY2htZW50IHRvIHRoZSBzcGVjaWZpZWQgYGZpZWxkYCxcbiAqIHdpdGggb3B0aW9uYWwgYG9wdGlvbnNgIChvciBmaWxlbmFtZSkuXG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmllbGQnLCBCdWZmZXIuZnJvbSgnPGI+SGVsbG8gd29ybGQ8L2I+JyksICdoZWxsby5odG1sJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBBIGZpbGVuYW1lIG1heSBhbHNvIGJlIHVzZWQ6XG4gKlxuICogYGBgIGpzXG4gKiByZXF1ZXN0LnBvc3QoJ2h0dHA6Ly9sb2NhbGhvc3QvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnZmlsZXMnLCAnaW1hZ2UuanBnJylcbiAqICAgLmVuZChjYWxsYmFjayk7XG4gKiBgYGBcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gZmllbGRcbiAqIEBwYXJhbSB7U3RyaW5nfGZzLlJlYWRTdHJlYW18QnVmZmVyfSBmaWxlXG4gKiBAcGFyYW0ge1N0cmluZ3xPYmplY3R9IG9wdGlvbnNcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdHRhY2hXaXRoRGVzY3JpcHRpb24gPSBmdW5jdGlvbihmaWVsZCwgZmlsZSwgb3B0aW9ucywgdGV4dFZhbCl7XG4gIGlmIChmaWxlKSB7XG4gICAgaWYgKHRoaXMuX2RhdGEpIHtcbiAgICAgIHRocm93IEVycm9yKFwic3VwZXJhZ2VudCBjYW4ndCBtaXggLnNlbmQoKSBhbmQgLmF0dGFjaCgpXCIpO1xuICAgIH1cblxuICAgIGxldCBvID0gb3B0aW9ucyB8fCB7fTtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBvID0geyBmaWxlbmFtZTogb3B0aW9ucyB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZmlsZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmICghby5maWxlbmFtZSkgby5maWxlbmFtZSA9IGZpbGU7XG4gICAgICBkZWJ1ZygnY3JlYXRpbmcgYGZzLlJlYWRTdHJlYW1gIGluc3RhbmNlIGZvciBmaWxlOiAlcycsIGZpbGUpO1xuICAgICAgZmlsZSA9IGZzLmNyZWF0ZVJlYWRTdHJlYW0oZmlsZSk7XG4gICAgfSBlbHNlIGlmICghby5maWxlbmFtZSAmJiBmaWxlLnBhdGgpIHtcbiAgICAgIG8uZmlsZW5hbWUgPSBmaWxlLnBhdGg7XG4gICAgfVxuXG4gICAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmRXaXRoSnNvbihmaWVsZCwgZmlsZSwgbywgdGV4dFZhbCk7XG4gIH1cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdHRhY2ggPSBmdW5jdGlvbiAoZmllbGQsIGZpbGUsIG9wdGlvbnMpIHtcbiAgaWYgKGZpbGUpIHtcbiAgICBpZiAodGhpcy5fZGF0YSkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFwic3VwZXJhZ2VudCBjYW4ndCBtaXggLnNlbmQoKSBhbmQgLmF0dGFjaCgpXCIpO1xuICAgIH1cblxuICAgIGxldCBvID0gb3B0aW9ucyB8fCB7fTtcbiAgICBpZiAodHlwZW9mIG9wdGlvbnMgPT09ICdzdHJpbmcnKSB7XG4gICAgICBvID0geyBmaWxlbmFtZTogb3B0aW9ucyB9O1xuICAgIH1cblxuICAgIGlmICh0eXBlb2YgZmlsZSA9PT0gJ3N0cmluZycpIHtcbiAgICAgIGlmICghby5maWxlbmFtZSkgby5maWxlbmFtZSA9IGZpbGU7XG4gICAgICBkZWJ1ZygnY3JlYXRpbmcgYGZzLlJlYWRTdHJlYW1gIGluc3RhbmNlIGZvciBmaWxlOiAlcycsIGZpbGUpO1xuICAgICAgZmlsZSA9IGZzLmNyZWF0ZVJlYWRTdHJlYW0oZmlsZSk7XG4gICAgfSBlbHNlIGlmICghby5maWxlbmFtZSAmJiBmaWxlLnBhdGgpIHtcbiAgICAgIG8uZmlsZW5hbWUgPSBmaWxlLnBhdGg7XG4gICAgfVxuXG4gICAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmQoZmllbGQsIGZpbGUsIG8pO1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fZ2V0Rm9ybURhdGEgPSBmdW5jdGlvbiAoKSB7XG4gIGlmICghdGhpcy5fZm9ybURhdGEpIHtcbiAgICB0aGlzLl9mb3JtRGF0YSA9IG5ldyBGb3JtRGF0YSgpO1xuICAgIHRoaXMuX2Zvcm1EYXRhLm9uKCdlcnJvcicsIChlcnIpID0+IHtcbiAgICAgIGRlYnVnKCdGb3JtRGF0YSBlcnJvcicsIGVycik7XG4gICAgICBpZiAodGhpcy5jYWxsZWQpIHtcbiAgICAgICAgLy8gVGhlIHJlcXVlc3QgaGFzIGFscmVhZHkgZmluaXNoZWQgYW5kIHRoZSBjYWxsYmFjayB3YXMgY2FsbGVkLlxuICAgICAgICAvLyBTaWxlbnRseSBpZ25vcmUgdGhlIGVycm9yLlxuICAgICAgICByZXR1cm47XG4gICAgICB9XG5cbiAgICAgIHRoaXMuY2FsbGJhY2soZXJyKTtcbiAgICAgIHRoaXMuYWJvcnQoKTtcbiAgICB9KTtcbiAgfVxuXG4gIHJldHVybiB0aGlzLl9mb3JtRGF0YTtcbn07XG5cbi8qKlxuICogR2V0cy9zZXRzIHRoZSBgQWdlbnRgIHRvIHVzZSBmb3IgdGhpcyBIVFRQIHJlcXVlc3QuIFRoZSBkZWZhdWx0IChpZiB0aGlzXG4gKiBmdW5jdGlvbiBpcyBub3QgY2FsbGVkKSBpcyB0byBvcHQgb3V0IG9mIGNvbm5lY3Rpb24gcG9vbGluZyAoYGFnZW50OiBmYWxzZWApLlxuICpcbiAqIEBwYXJhbSB7aHR0cC5BZ2VudH0gYWdlbnRcbiAqIEByZXR1cm4ge2h0dHAuQWdlbnR9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmFnZW50ID0gZnVuY3Rpb24gKGFnZW50KSB7XG4gIGlmIChhcmd1bWVudHMubGVuZ3RoID09PSAwKSByZXR1cm4gdGhpcy5fYWdlbnQ7XG4gIHRoaXMuX2FnZW50ID0gYWdlbnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgX0NvbnRlbnQtVHlwZV8gcmVzcG9uc2UgaGVhZGVyIHBhc3NlZCB0aHJvdWdoIGBtaW1lLmdldFR5cGUoKWAuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICAgICByZXF1ZXN0LnBvc3QoJy8nKVxuICogICAgICAgIC50eXBlKCd4bWwnKVxuICogICAgICAgIC5zZW5kKHhtbHN0cmluZylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ2pzb24nKVxuICogICAgICAgIC5zZW5kKGpzb25zdHJpbmcpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogICAgICByZXF1ZXN0LnBvc3QoJy8nKVxuICogICAgICAgIC50eXBlKCdhcHBsaWNhdGlvbi9qc29uJylcbiAqICAgICAgICAuc2VuZChqc29uc3RyaW5nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB0eXBlXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUudHlwZSA9IGZ1bmN0aW9uICh0eXBlKSB7XG4gIHJldHVybiB0aGlzLnNldChcbiAgICAnQ29udGVudC1UeXBlJyxcbiAgICB0eXBlLmluY2x1ZGVzKCcvJykgPyB0eXBlIDogbWltZS5nZXRUeXBlKHR5cGUpXG4gICk7XG59O1xuXG4vKipcbiAqIFNldCBfQWNjZXB0XyByZXNwb25zZSBoZWFkZXIgcGFzc2VkIHRocm91Z2ggYG1pbWUuZ2V0VHlwZSgpYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgICAgIHN1cGVyYWdlbnQudHlwZXMuanNvbiA9ICdhcHBsaWNhdGlvbi9qc29uJztcbiAqXG4gKiAgICAgIHJlcXVlc3QuZ2V0KCcvYWdlbnQnKVxuICogICAgICAgIC5hY2NlcHQoJ2pzb24nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqICAgICAgcmVxdWVzdC5nZXQoJy9hZ2VudCcpXG4gKiAgICAgICAgLmFjY2VwdCgnYXBwbGljYXRpb24vanNvbicpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IGFjY2VwdFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmFjY2VwdCA9IGZ1bmN0aW9uICh0eXBlKSB7XG4gIHJldHVybiB0aGlzLnNldCgnQWNjZXB0JywgdHlwZS5pbmNsdWRlcygnLycpID8gdHlwZSA6IG1pbWUuZ2V0VHlwZSh0eXBlKSk7XG59O1xuXG4vKipcbiAqIEFkZCBxdWVyeS1zdHJpbmcgYHZhbGAuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICByZXF1ZXN0LmdldCgnL3Nob2VzJylcbiAqICAgICAucXVlcnkoJ3NpemU9MTAnKVxuICogICAgIC5xdWVyeSh7IGNvbG9yOiAnYmx1ZScgfSlcbiAqXG4gKiBAcGFyYW0ge09iamVjdHxTdHJpbmd9IHZhbFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnF1ZXJ5ID0gZnVuY3Rpb24gKHZhbCkge1xuICBpZiAodHlwZW9mIHZhbCA9PT0gJ3N0cmluZycpIHtcbiAgICB0aGlzLl9xdWVyeS5wdXNoKHZhbCk7XG4gIH0gZWxzZSB7XG4gICAgT2JqZWN0LmFzc2lnbih0aGlzLnFzLCB2YWwpO1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFdyaXRlIHJhdyBgZGF0YWAgLyBgZW5jb2RpbmdgIHRvIHRoZSBzb2NrZXQuXG4gKlxuICogQHBhcmFtIHtCdWZmZXJ8U3RyaW5nfSBkYXRhXG4gKiBAcGFyYW0ge1N0cmluZ30gZW5jb2RpbmdcbiAqIEByZXR1cm4ge0Jvb2xlYW59XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLndyaXRlID0gZnVuY3Rpb24gKGRhdGEsIGVuY29kaW5nKSB7XG4gIGNvbnN0IHJlcSA9IHRoaXMucmVxdWVzdCgpO1xuICBpZiAoIXRoaXMuX3N0cmVhbVJlcXVlc3QpIHtcbiAgICB0aGlzLl9zdHJlYW1SZXF1ZXN0ID0gdHJ1ZTtcbiAgfVxuXG4gIHJldHVybiByZXEud3JpdGUoZGF0YSwgZW5jb2RpbmcpO1xufTtcblxuLyoqXG4gKiBQaXBlIHRoZSByZXF1ZXN0IGJvZHkgdG8gYHN0cmVhbWAuXG4gKlxuICogQHBhcmFtIHtTdHJlYW19IHN0cmVhbVxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcbiAqIEByZXR1cm4ge1N0cmVhbX1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucGlwZSA9IGZ1bmN0aW9uIChzdHJlYW0sIG9wdGlvbnMpIHtcbiAgdGhpcy5waXBlZCA9IHRydWU7IC8vIEhBQ0suLi5cbiAgdGhpcy5idWZmZXIoZmFsc2UpO1xuICB0aGlzLmVuZCgpO1xuICByZXR1cm4gdGhpcy5fcGlwZUNvbnRpbnVlKHN0cmVhbSwgb3B0aW9ucyk7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5fcGlwZUNvbnRpbnVlID0gZnVuY3Rpb24gKHN0cmVhbSwgb3B0aW9ucykge1xuICB0aGlzLnJlcS5vbmNlKCdyZXNwb25zZScsIChyZXMpID0+IHtcbiAgICAvLyByZWRpcmVjdFxuICAgIGlmIChcbiAgICAgIGlzUmVkaXJlY3QocmVzLnN0YXR1c0NvZGUpICYmXG4gICAgICB0aGlzLl9yZWRpcmVjdHMrKyAhPT0gdGhpcy5fbWF4UmVkaXJlY3RzXG4gICAgKSB7XG4gICAgICByZXR1cm4gdGhpcy5fcmVkaXJlY3QocmVzKSA9PT0gdGhpc1xuICAgICAgICA/IHRoaXMuX3BpcGVDb250aW51ZShzdHJlYW0sIG9wdGlvbnMpXG4gICAgICAgIDogdW5kZWZpbmVkO1xuICAgIH1cblxuICAgIHRoaXMucmVzID0gcmVzO1xuICAgIHRoaXMuX2VtaXRSZXNwb25zZSgpO1xuICAgIGlmICh0aGlzLl9hYm9ydGVkKSByZXR1cm47XG5cbiAgICBpZiAodGhpcy5fc2hvdWxkVW56aXAocmVzKSkge1xuICAgICAgY29uc3QgdW56aXBPYmogPSB6bGliLmNyZWF0ZVVuemlwKCk7XG4gICAgICB1bnppcE9iai5vbignZXJyb3InLCAoZXJyKSA9PiB7XG4gICAgICAgIGlmIChlcnIgJiYgZXJyLmNvZGUgPT09ICdaX0JVRl9FUlJPUicpIHtcbiAgICAgICAgICAvLyB1bmV4cGVjdGVkIGVuZCBvZiBmaWxlIGlzIGlnbm9yZWQgYnkgYnJvd3NlcnMgYW5kIGN1cmxcbiAgICAgICAgICBzdHJlYW0uZW1pdCgnZW5kJyk7XG4gICAgICAgICAgcmV0dXJuO1xuICAgICAgICB9XG5cbiAgICAgICAgc3RyZWFtLmVtaXQoJ2Vycm9yJywgZXJyKTtcbiAgICAgIH0pO1xuICAgICAgcmVzLnBpcGUodW56aXBPYmopLnBpcGUoc3RyZWFtLCBvcHRpb25zKTtcbiAgICB9IGVsc2Uge1xuICAgICAgcmVzLnBpcGUoc3RyZWFtLCBvcHRpb25zKTtcbiAgICB9XG5cbiAgICByZXMub25jZSgnZW5kJywgKCkgPT4ge1xuICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICB9KTtcbiAgfSk7XG4gIHJldHVybiBzdHJlYW07XG59O1xuXG4vKipcbiAqIEVuYWJsZSAvIGRpc2FibGUgYnVmZmVyaW5nLlxuICpcbiAqIEByZXR1cm4ge0Jvb2xlYW59IFt2YWxdXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuYnVmZmVyID0gZnVuY3Rpb24gKHZhbCkge1xuICB0aGlzLl9idWZmZXIgPSB2YWwgIT09IGZhbHNlO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUmVkaXJlY3QgdG8gYHVybFxuICpcbiAqIEBwYXJhbSB7SW5jb21pbmdNZXNzYWdlfSByZXNcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwcml2YXRlXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuX3JlZGlyZWN0ID0gZnVuY3Rpb24gKHJlcykge1xuICBsZXQgdXJsID0gcmVzLmhlYWRlcnMubG9jYXRpb247XG4gIGlmICghdXJsKSB7XG4gICAgcmV0dXJuIHRoaXMuY2FsbGJhY2sobmV3IEVycm9yKCdObyBsb2NhdGlvbiBoZWFkZXIgZm9yIHJlZGlyZWN0JyksIHJlcyk7XG4gIH1cblxuICBkZWJ1ZygncmVkaXJlY3QgJXMgLT4gJXMnLCB0aGlzLnVybCwgdXJsKTtcblxuICAvLyBsb2NhdGlvblxuICB1cmwgPSByZXNvbHZlKHRoaXMudXJsLCB1cmwpO1xuXG4gIC8vIGVuc3VyZSB0aGUgcmVzcG9uc2UgaXMgYmVpbmcgY29uc3VtZWRcbiAgLy8gdGhpcyBpcyByZXF1aXJlZCBmb3IgTm9kZSB2MC4xMCtcbiAgcmVzLnJlc3VtZSgpO1xuXG4gIGxldCBoZWFkZXJzID0gdGhpcy5yZXEuZ2V0SGVhZGVycyA/IHRoaXMucmVxLmdldEhlYWRlcnMoKSA6IHRoaXMucmVxLl9oZWFkZXJzO1xuXG4gIGNvbnN0IGNoYW5nZXNPcmlnaW4gPSBwYXJzZSh1cmwpLmhvc3QgIT09IHBhcnNlKHRoaXMudXJsKS5ob3N0O1xuXG4gIC8vIGltcGxlbWVudGF0aW9uIG9mIDMwMiBmb2xsb3dpbmcgZGVmYWN0byBzdGFuZGFyZFxuICBpZiAocmVzLnN0YXR1c0NvZGUgPT09IDMwMSB8fCByZXMuc3RhdHVzQ29kZSA9PT0gMzAyKSB7XG4gICAgLy8gc3RyaXAgQ29udGVudC0qIHJlbGF0ZWQgZmllbGRzXG4gICAgLy8gaW4gY2FzZSBvZiBQT1NUIGV0Y1xuICAgIGhlYWRlcnMgPSB1dGlscy5jbGVhbkhlYWRlcihoZWFkZXJzLCBjaGFuZ2VzT3JpZ2luKTtcblxuICAgIC8vIGZvcmNlIEdFVFxuICAgIHRoaXMubWV0aG9kID0gdGhpcy5tZXRob2QgPT09ICdIRUFEJyA/ICdIRUFEJyA6ICdHRVQnO1xuXG4gICAgLy8gY2xlYXIgZGF0YVxuICAgIHRoaXMuX2RhdGEgPSBudWxsO1xuICB9XG5cbiAgLy8gMzAzIGlzIGFsd2F5cyBHRVRcbiAgaWYgKHJlcy5zdGF0dXNDb2RlID09PSAzMDMpIHtcbiAgICAvLyBzdHJpcCBDb250ZW50LSogcmVsYXRlZCBmaWVsZHNcbiAgICAvLyBpbiBjYXNlIG9mIFBPU1QgZXRjXG4gICAgaGVhZGVycyA9IHV0aWxzLmNsZWFuSGVhZGVyKGhlYWRlcnMsIGNoYW5nZXNPcmlnaW4pO1xuXG4gICAgLy8gZm9yY2UgbWV0aG9kXG4gICAgdGhpcy5tZXRob2QgPSAnR0VUJztcblxuICAgIC8vIGNsZWFyIGRhdGFcbiAgICB0aGlzLl9kYXRhID0gbnVsbDtcbiAgfVxuXG4gIC8vIDMwNyBwcmVzZXJ2ZXMgbWV0aG9kXG4gIC8vIDMwOCBwcmVzZXJ2ZXMgbWV0aG9kXG4gIGRlbGV0ZSBoZWFkZXJzLmhvc3Q7XG5cbiAgZGVsZXRlIHRoaXMucmVxO1xuICBkZWxldGUgdGhpcy5fZm9ybURhdGE7XG5cbiAgLy8gcmVtb3ZlIGFsbCBhZGQgaGVhZGVyIGV4Y2VwdCBVc2VyLUFnZW50XG4gIF9pbml0SGVhZGVycyh0aGlzKTtcblxuICAvLyByZWRpcmVjdFxuICB0aGlzLl9lbmRDYWxsZWQgPSBmYWxzZTtcbiAgdGhpcy51cmwgPSB1cmw7XG4gIHRoaXMucXMgPSB7fTtcbiAgdGhpcy5fcXVlcnkubGVuZ3RoID0gMDtcbiAgdGhpcy5zZXQoaGVhZGVycyk7XG4gIHRoaXMuZW1pdCgncmVkaXJlY3QnLCByZXMpO1xuICB0aGlzLl9yZWRpcmVjdExpc3QucHVzaCh0aGlzLnVybCk7XG4gIHRoaXMuZW5kKHRoaXMuX2NhbGxiYWNrKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCBBdXRob3JpemF0aW9uIGZpZWxkIHZhbHVlIHdpdGggYHVzZXJgIGFuZCBgcGFzc2AuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICAuYXV0aCgndG9iaScsICdsZWFybmJvb3N0JylcbiAqICAgLmF1dGgoJ3RvYmk6bGVhcm5ib29zdCcpXG4gKiAgIC5hdXRoKCd0b2JpJylcbiAqICAgLmF1dGgoYWNjZXNzVG9rZW4sIHsgdHlwZTogJ2JlYXJlcicgfSlcbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdXNlclxuICogQHBhcmFtIHtTdHJpbmd9IFtwYXNzXVxuICogQHBhcmFtIHtPYmplY3R9IFtvcHRpb25zXSBvcHRpb25zIHdpdGggYXV0aG9yaXphdGlvbiB0eXBlICdiYXNpYycgb3IgJ2JlYXJlcicgKCdiYXNpYycgaXMgZGVmYXVsdClcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdXRoID0gZnVuY3Rpb24gKHVzZXIsIHBhc3MsIG9wdGlvbnMpIHtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDEpIHBhc3MgPSAnJztcbiAgaWYgKHR5cGVvZiBwYXNzID09PSAnb2JqZWN0JyAmJiBwYXNzICE9PSBudWxsKSB7XG4gICAgLy8gcGFzcyBpcyBvcHRpb25hbCBhbmQgY2FuIGJlIHJlcGxhY2VkIHdpdGggb3B0aW9uc1xuICAgIG9wdGlvbnMgPSBwYXNzO1xuICAgIHBhc3MgPSAnJztcbiAgfVxuXG4gIGlmICghb3B0aW9ucykge1xuICAgIG9wdGlvbnMgPSB7IHR5cGU6ICdiYXNpYycgfTtcbiAgfVxuXG4gIGNvbnN0IGVuY29kZXIgPSAoc3RyaW5nKSA9PiBCdWZmZXIuZnJvbShzdHJpbmcpLnRvU3RyaW5nKCdiYXNlNjQnKTtcblxuICByZXR1cm4gdGhpcy5fYXV0aCh1c2VyLCBwYXNzLCBvcHRpb25zLCBlbmNvZGVyKTtcbn07XG5cbi8qKlxuICogU2V0IHRoZSBjZXJ0aWZpY2F0ZSBhdXRob3JpdHkgb3B0aW9uIGZvciBodHRwcyByZXF1ZXN0LlxuICpcbiAqIEBwYXJhbSB7QnVmZmVyIHwgQXJyYXl9IGNlcnRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYSA9IGZ1bmN0aW9uIChjZXJ0KSB7XG4gIHRoaXMuX2NhID0gY2VydDtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCB0aGUgY2xpZW50IGNlcnRpZmljYXRlIGtleSBvcHRpb24gZm9yIGh0dHBzIHJlcXVlc3QuXG4gKlxuICogQHBhcmFtIHtCdWZmZXIgfCBTdHJpbmd9IGNlcnRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5rZXkgPSBmdW5jdGlvbiAoY2VydCkge1xuICB0aGlzLl9rZXkgPSBjZXJ0O1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogU2V0IHRoZSBrZXksIGNlcnRpZmljYXRlLCBhbmQgQ0EgY2VydHMgb2YgdGhlIGNsaWVudCBpbiBQRlggb3IgUEtDUzEyIGZvcm1hdC5cbiAqXG4gKiBAcGFyYW0ge0J1ZmZlciB8IFN0cmluZ30gY2VydFxuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLnBmeCA9IGZ1bmN0aW9uIChjZXJ0KSB7XG4gIGlmICh0eXBlb2YgY2VydCA9PT0gJ29iamVjdCcgJiYgIUJ1ZmZlci5pc0J1ZmZlcihjZXJ0KSkge1xuICAgIHRoaXMuX3BmeCA9IGNlcnQucGZ4O1xuICAgIHRoaXMuX3Bhc3NwaHJhc2UgPSBjZXJ0LnBhc3NwaHJhc2U7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy5fcGZ4ID0gY2VydDtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgdGhlIGNsaWVudCBjZXJ0aWZpY2F0ZSBvcHRpb24gZm9yIGh0dHBzIHJlcXVlc3QuXG4gKlxuICogQHBhcmFtIHtCdWZmZXIgfCBTdHJpbmd9IGNlcnRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jZXJ0ID0gZnVuY3Rpb24gKGNlcnQpIHtcbiAgdGhpcy5fY2VydCA9IGNlcnQ7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBEbyBub3QgcmVqZWN0IGV4cGlyZWQgb3IgaW52YWxpZCBUTFMgY2VydHMuXG4gKiBzZXRzIGByZWplY3RVbmF1dGhvcml6ZWQ9dHJ1ZWAuIEJlIHdhcm5lZCB0aGF0IHRoaXMgYWxsb3dzIE1JVE0gYXR0YWNrcy5cbiAqXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuZGlzYWJsZVRMU0NlcnRzID0gZnVuY3Rpb24gKCkge1xuICB0aGlzLl9kaXNhYmxlVExTQ2VydHMgPSB0cnVlO1xuICByZXR1cm4gdGhpcztcbn07XG5cbi8qKlxuICogUmV0dXJuIGFuIGh0dHBbc10gcmVxdWVzdC5cbiAqXG4gKiBAcmV0dXJuIHtPdXRnb2luZ01lc3NhZ2V9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgY29tcGxleGl0eVxuUmVxdWVzdC5wcm90b3R5cGUucmVxdWVzdCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKHRoaXMucmVxKSByZXR1cm4gdGhpcy5yZXE7XG5cbiAgY29uc3Qgb3B0aW9ucyA9IHt9O1xuXG4gIHRyeSB7XG4gICAgY29uc3QgcXVlcnkgPSBxcy5zdHJpbmdpZnkodGhpcy5xcywge1xuICAgICAgaW5kaWNlczogZmFsc2UsXG4gICAgICBzdHJpY3ROdWxsSGFuZGxpbmc6IHRydWVcbiAgICB9KTtcbiAgICBpZiAocXVlcnkpIHtcbiAgICAgIHRoaXMucXMgPSB7fTtcbiAgICAgIHRoaXMuX3F1ZXJ5LnB1c2gocXVlcnkpO1xuICAgIH1cblxuICAgIHRoaXMuX2ZpbmFsaXplUXVlcnlTdHJpbmcoKTtcbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgcmV0dXJuIHRoaXMuZW1pdCgnZXJyb3InLCBlcnIpO1xuICB9XG5cbiAgbGV0IHsgdXJsIH0gPSB0aGlzO1xuICBjb25zdCByZXRyaWVzID0gdGhpcy5fcmV0cmllcztcblxuICAvLyBDYXB0dXJlIGJhY2t0aWNrcyBhcy1pcyBmcm9tIHRoZSBmaW5hbCBxdWVyeSBzdHJpbmcgYnVpbHQgYWJvdmUuXG4gIC8vIE5vdGU6IHRoaXMnbGwgb25seSBmaW5kIGJhY2t0aWNrcyBlbnRlcmVkIGluIHJlcS5xdWVyeShTdHJpbmcpXG4gIC8vIGNhbGxzLCBiZWNhdXNlIHFzLnN0cmluZ2lmeSB1bmNvbmRpdGlvbmFsbHkgZW5jb2RlcyBiYWNrdGlja3MuXG4gIGxldCBxdWVyeVN0cmluZ0JhY2t0aWNrcztcbiAgaWYgKHVybC5pbmNsdWRlcygnYCcpKSB7XG4gICAgY29uc3QgcXVlcnlTdGFydEluZGV4ID0gdXJsLmluZGV4T2YoJz8nKTtcblxuICAgIGlmIChxdWVyeVN0YXJ0SW5kZXggIT09IC0xKSB7XG4gICAgICBjb25zdCBxdWVyeVN0cmluZyA9IHVybC5zbGljZShxdWVyeVN0YXJ0SW5kZXggKyAxKTtcbiAgICAgIHF1ZXJ5U3RyaW5nQmFja3RpY2tzID0gcXVlcnlTdHJpbmcubWF0Y2goL2B8JTYwL2cpO1xuICAgIH1cbiAgfVxuXG4gIC8vIGRlZmF1bHQgdG8gaHR0cDovL1xuICBpZiAodXJsLmluZGV4T2YoJ2h0dHAnKSAhPT0gMCkgdXJsID0gYGh0dHA6Ly8ke3VybH1gO1xuICB1cmwgPSBwYXJzZSh1cmwpO1xuXG4gIC8vIFNlZSBodHRwczovL2dpdGh1Yi5jb20vdmlzaW9ubWVkaWEvc3VwZXJhZ2VudC9pc3N1ZXMvMTM2N1xuICBpZiAocXVlcnlTdHJpbmdCYWNrdGlja3MpIHtcbiAgICBsZXQgaSA9IDA7XG4gICAgdXJsLnF1ZXJ5ID0gdXJsLnF1ZXJ5LnJlcGxhY2UoLyU2MC9nLCAoKSA9PiBxdWVyeVN0cmluZ0JhY2t0aWNrc1tpKytdKTtcbiAgICB1cmwuc2VhcmNoID0gYD8ke3VybC5xdWVyeX1gO1xuICAgIHVybC5wYXRoID0gdXJsLnBhdGhuYW1lICsgdXJsLnNlYXJjaDtcbiAgfVxuXG4gIC8vIHN1cHBvcnQgdW5peCBzb2NrZXRzXG4gIGlmICgvXmh0dHBzP1xcK3VuaXg6Ly50ZXN0KHVybC5wcm90b2NvbCkgPT09IHRydWUpIHtcbiAgICAvLyBnZXQgdGhlIHByb3RvY29sXG4gICAgdXJsLnByb3RvY29sID0gYCR7dXJsLnByb3RvY29sLnNwbGl0KCcrJylbMF19OmA7XG5cbiAgICAvLyBnZXQgdGhlIHNvY2tldCwgcGF0aFxuICAgIGNvbnN0IHVuaXhQYXJ0cyA9IHVybC5wYXRoLm1hdGNoKC9eKFteL10rKSguKykkLyk7XG4gICAgb3B0aW9ucy5zb2NrZXRQYXRoID0gdW5peFBhcnRzWzFdLnJlcGxhY2UoLyUyRi9nLCAnLycpO1xuICAgIHVybC5wYXRoID0gdW5peFBhcnRzWzJdO1xuICB9XG5cbiAgLy8gT3ZlcnJpZGUgSVAgYWRkcmVzcyBvZiBhIGhvc3RuYW1lXG4gIGlmICh0aGlzLl9jb25uZWN0T3ZlcnJpZGUpIHtcbiAgICBjb25zdCB7IGhvc3RuYW1lIH0gPSB1cmw7XG4gICAgY29uc3QgbWF0Y2ggPVxuICAgICAgaG9zdG5hbWUgaW4gdGhpcy5fY29ubmVjdE92ZXJyaWRlXG4gICAgICAgID8gdGhpcy5fY29ubmVjdE92ZXJyaWRlW2hvc3RuYW1lXVxuICAgICAgICA6IHRoaXMuX2Nvbm5lY3RPdmVycmlkZVsnKiddO1xuICAgIGlmIChtYXRjaCkge1xuICAgICAgLy8gYmFja3VwIHRoZSByZWFsIGhvc3RcbiAgICAgIGlmICghdGhpcy5faGVhZGVyLmhvc3QpIHtcbiAgICAgICAgdGhpcy5zZXQoJ2hvc3QnLCB1cmwuaG9zdCk7XG4gICAgICB9XG5cbiAgICAgIGxldCBuZXdIb3N0O1xuICAgICAgbGV0IG5ld1BvcnQ7XG5cbiAgICAgIGlmICh0eXBlb2YgbWF0Y2ggPT09ICdvYmplY3QnKSB7XG4gICAgICAgIG5ld0hvc3QgPSBtYXRjaC5ob3N0O1xuICAgICAgICBuZXdQb3J0ID0gbWF0Y2gucG9ydDtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIG5ld0hvc3QgPSBtYXRjaDtcbiAgICAgICAgbmV3UG9ydCA9IHVybC5wb3J0O1xuICAgICAgfVxuXG4gICAgICAvLyB3cmFwIFtpcHY2XVxuICAgICAgdXJsLmhvc3QgPSAvOi8udGVzdChuZXdIb3N0KSA/IGBbJHtuZXdIb3N0fV1gIDogbmV3SG9zdDtcbiAgICAgIGlmIChuZXdQb3J0KSB7XG4gICAgICAgIHVybC5ob3N0ICs9IGA6JHtuZXdQb3J0fWA7XG4gICAgICAgIHVybC5wb3J0ID0gbmV3UG9ydDtcbiAgICAgIH1cblxuICAgICAgdXJsLmhvc3RuYW1lID0gbmV3SG9zdDtcbiAgICB9XG4gIH1cblxuICAvLyBvcHRpb25zXG4gIG9wdGlvbnMubWV0aG9kID0gdGhpcy5tZXRob2Q7XG4gIG9wdGlvbnMucG9ydCA9IHVybC5wb3J0O1xuICBvcHRpb25zLnBhdGggPSB1cmwucGF0aDtcbiAgb3B0aW9ucy5ob3N0ID0gdXJsLmhvc3RuYW1lO1xuICBvcHRpb25zLmNhID0gdGhpcy5fY2E7XG4gIG9wdGlvbnMua2V5ID0gdGhpcy5fa2V5O1xuICBvcHRpb25zLnBmeCA9IHRoaXMuX3BmeDtcbiAgb3B0aW9ucy5jZXJ0ID0gdGhpcy5fY2VydDtcbiAgb3B0aW9ucy5wYXNzcGhyYXNlID0gdGhpcy5fcGFzc3BocmFzZTtcbiAgb3B0aW9ucy5hZ2VudCA9IHRoaXMuX2FnZW50O1xuICBvcHRpb25zLnJlamVjdFVuYXV0aG9yaXplZCA9XG4gICAgdHlwZW9mIHRoaXMuX2Rpc2FibGVUTFNDZXJ0cyA9PT0gJ2Jvb2xlYW4nXG4gICAgICA/ICF0aGlzLl9kaXNhYmxlVExTQ2VydHNcbiAgICAgIDogcHJvY2Vzcy5lbnYuTk9ERV9UTFNfUkVKRUNUX1VOQVVUSE9SSVpFRCAhPT0gJzAnO1xuXG4gIC8vIEFsbG93cyByZXF1ZXN0LmdldCgnaHR0cHM6Ly8xLjIuMy40LycpLnNldCgnSG9zdCcsICdleGFtcGxlLmNvbScpXG4gIGlmICh0aGlzLl9oZWFkZXIuaG9zdCkge1xuICAgIG9wdGlvbnMuc2VydmVybmFtZSA9IHRoaXMuX2hlYWRlci5ob3N0LnJlcGxhY2UoLzpcXGQrJC8sICcnKTtcbiAgfVxuXG4gIGlmIChcbiAgICB0aGlzLl90cnVzdExvY2FsaG9zdCAmJlxuICAgIC9eKD86bG9jYWxob3N0fDEyN1xcLjBcXC4wXFwuXFxkK3woMCo6KSs6MCoxKSQvLnRlc3QodXJsLmhvc3RuYW1lKVxuICApIHtcbiAgICBvcHRpb25zLnJlamVjdFVuYXV0aG9yaXplZCA9IGZhbHNlO1xuICB9XG5cbiAgLy8gaW5pdGlhdGUgcmVxdWVzdFxuICBjb25zdCBtb2QgPSB0aGlzLl9lbmFibGVIdHRwMlxuICAgID8gZXhwb3J0cy5wcm90b2NvbHNbJ2h0dHAyOiddLnNldFByb3RvY29sKHVybC5wcm90b2NvbClcbiAgICA6IGV4cG9ydHMucHJvdG9jb2xzW3VybC5wcm90b2NvbF07XG5cbiAgLy8gcmVxdWVzdFxuICB0aGlzLnJlcSA9IG1vZC5yZXF1ZXN0KG9wdGlvbnMpO1xuICBjb25zdCB7IHJlcSB9ID0gdGhpcztcblxuICAvLyBzZXQgdGNwIG5vIGRlbGF5XG4gIHJlcS5zZXROb0RlbGF5KHRydWUpO1xuXG4gIGlmIChvcHRpb25zLm1ldGhvZCAhPT0gJ0hFQUQnKSB7XG4gICAgcmVxLnNldEhlYWRlcignQWNjZXB0LUVuY29kaW5nJywgJ2d6aXAsIGRlZmxhdGUnKTtcbiAgfVxuXG4gIHRoaXMucHJvdG9jb2wgPSB1cmwucHJvdG9jb2w7XG4gIHRoaXMuaG9zdCA9IHVybC5ob3N0O1xuXG4gIC8vIGV4cG9zZSBldmVudHNcbiAgcmVxLm9uY2UoJ2RyYWluJywgKCkgPT4ge1xuICAgIHRoaXMuZW1pdCgnZHJhaW4nKTtcbiAgfSk7XG5cbiAgcmVxLm9uKCdlcnJvcicsIChlcnIpID0+IHtcbiAgICAvLyBmbGFnIGFib3J0aW9uIGhlcmUgZm9yIG91dCB0aW1lb3V0c1xuICAgIC8vIGJlY2F1c2Ugbm9kZSB3aWxsIGVtaXQgYSBmYXV4LWVycm9yIFwic29ja2V0IGhhbmcgdXBcIlxuICAgIC8vIHdoZW4gcmVxdWVzdCBpcyBhYm9ydGVkIGJlZm9yZSBhIGNvbm5lY3Rpb24gaXMgbWFkZVxuICAgIGlmICh0aGlzLl9hYm9ydGVkKSByZXR1cm47XG4gICAgLy8gaWYgbm90IHRoZSBzYW1lLCB3ZSBhcmUgaW4gdGhlICoqb2xkKiogKGNhbmNlbGxlZCkgcmVxdWVzdCxcbiAgICAvLyBzbyBuZWVkIHRvIGNvbnRpbnVlIChzYW1lIGFzIGZvciBhYm92ZSlcbiAgICBpZiAodGhpcy5fcmV0cmllcyAhPT0gcmV0cmllcykgcmV0dXJuO1xuICAgIC8vIGlmIHdlJ3ZlIHJlY2VpdmVkIGEgcmVzcG9uc2UgdGhlbiB3ZSBkb24ndCB3YW50IHRvIGxldFxuICAgIC8vIGFuIGVycm9yIGluIHRoZSByZXF1ZXN0IGJsb3cgdXAgdGhlIHJlc3BvbnNlXG4gICAgaWYgKHRoaXMucmVzcG9uc2UpIHJldHVybjtcbiAgICB0aGlzLmNhbGxiYWNrKGVycik7XG4gIH0pO1xuXG4gIC8vIGF1dGhcbiAgaWYgKHVybC5hdXRoKSB7XG4gICAgY29uc3QgYXV0aCA9IHVybC5hdXRoLnNwbGl0KCc6Jyk7XG4gICAgdGhpcy5hdXRoKGF1dGhbMF0sIGF1dGhbMV0pO1xuICB9XG5cbiAgaWYgKHRoaXMudXNlcm5hbWUgJiYgdGhpcy5wYXNzd29yZCkge1xuICAgIHRoaXMuYXV0aCh0aGlzLnVzZXJuYW1lLCB0aGlzLnBhc3N3b3JkKTtcbiAgfVxuXG4gIGZvciAoY29uc3Qga2V5IGluIHRoaXMuaGVhZGVyKSB7XG4gICAgaWYgKE9iamVjdC5wcm90b3R5cGUuaGFzT3duUHJvcGVydHkuY2FsbCh0aGlzLmhlYWRlciwga2V5KSlcbiAgICAgIHJlcS5zZXRIZWFkZXIoa2V5LCB0aGlzLmhlYWRlcltrZXldKTtcbiAgfVxuXG4gIC8vIGFkZCBjb29raWVzXG4gIGlmICh0aGlzLmNvb2tpZXMpIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHRoaXMuX2hlYWRlciwgJ2Nvb2tpZScpKSB7XG4gICAgICAvLyBtZXJnZVxuICAgICAgY29uc3QgdG1wSmFyID0gbmV3IENvb2tpZUphci5Db29raWVKYXIoKTtcbiAgICAgIHRtcEphci5zZXRDb29raWVzKHRoaXMuX2hlYWRlci5jb29raWUuc3BsaXQoJzsnKSk7XG4gICAgICB0bXBKYXIuc2V0Q29va2llcyh0aGlzLmNvb2tpZXMuc3BsaXQoJzsnKSk7XG4gICAgICByZXEuc2V0SGVhZGVyKFxuICAgICAgICAnQ29va2llJyxcbiAgICAgICAgdG1wSmFyLmdldENvb2tpZXMoQ29va2llSmFyLkNvb2tpZUFjY2Vzc0luZm8uQWxsKS50b1ZhbHVlU3RyaW5nKClcbiAgICAgICk7XG4gICAgfSBlbHNlIHtcbiAgICAgIHJlcS5zZXRIZWFkZXIoJ0Nvb2tpZScsIHRoaXMuY29va2llcyk7XG4gICAgfVxuICB9XG5cbiAgcmV0dXJuIHJlcTtcbn07XG5cbi8qKlxuICogSW52b2tlIHRoZSBjYWxsYmFjayB3aXRoIGBlcnJgIGFuZCBgcmVzYFxuICogYW5kIGhhbmRsZSBhcml0eSBjaGVjay5cbiAqXG4gKiBAcGFyYW0ge0Vycm9yfSBlcnJcbiAqIEBwYXJhbSB7UmVzcG9uc2V9IHJlc1xuICogQGFwaSBwcml2YXRlXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuY2FsbGJhY2sgPSBmdW5jdGlvbiAoZXJyLCByZXMpIHtcbiAgaWYgKHRoaXMuX3Nob3VsZFJldHJ5KGVyciwgcmVzKSkge1xuICAgIHJldHVybiB0aGlzLl9yZXRyeSgpO1xuICB9XG5cbiAgLy8gQXZvaWQgdGhlIGVycm9yIHdoaWNoIGlzIGVtaXR0ZWQgZnJvbSAnc29ja2V0IGhhbmcgdXAnIHRvIGNhdXNlIHRoZSBmbiB1bmRlZmluZWQgZXJyb3Igb24gSlMgcnVudGltZS5cbiAgY29uc3QgZm4gPSB0aGlzLl9jYWxsYmFjayB8fCBub29wO1xuICB0aGlzLmNsZWFyVGltZW91dCgpO1xuICBpZiAodGhpcy5jYWxsZWQpIHJldHVybiBjb25zb2xlLndhcm4oJ3N1cGVyYWdlbnQ6IGRvdWJsZSBjYWxsYmFjayBidWcnKTtcbiAgdGhpcy5jYWxsZWQgPSB0cnVlO1xuXG4gIGlmICghZXJyKSB7XG4gICAgdHJ5IHtcbiAgICAgIGlmICghdGhpcy5faXNSZXNwb25zZU9LKHJlcykpIHtcbiAgICAgICAgbGV0IG1zZyA9ICdVbnN1Y2Nlc3NmdWwgSFRUUCByZXNwb25zZSc7XG4gICAgICAgIGlmIChyZXMpIHtcbiAgICAgICAgICBtc2cgPSBodHRwLlNUQVRVU19DT0RFU1tyZXMuc3RhdHVzXSB8fCBtc2c7XG4gICAgICAgIH1cblxuICAgICAgICBlcnIgPSBuZXcgRXJyb3IobXNnKTtcbiAgICAgICAgZXJyLnN0YXR1cyA9IHJlcyA/IHJlcy5zdGF0dXMgOiB1bmRlZmluZWQ7XG4gICAgICB9XG4gICAgfSBjYXRjaCAoZXJyXykge1xuICAgICAgZXJyID0gZXJyXztcbiAgICB9XG4gIH1cblxuICAvLyBJdCdzIGltcG9ydGFudCB0aGF0IHRoZSBjYWxsYmFjayBpcyBjYWxsZWQgb3V0c2lkZSB0cnkvY2F0Y2hcbiAgLy8gdG8gYXZvaWQgZG91YmxlIGNhbGxiYWNrXG4gIGlmICghZXJyKSB7XG4gICAgcmV0dXJuIGZuKG51bGwsIHJlcyk7XG4gIH1cblxuICBlcnIucmVzcG9uc2UgPSByZXM7XG4gIGlmICh0aGlzLl9tYXhSZXRyaWVzKSBlcnIucmV0cmllcyA9IHRoaXMuX3JldHJpZXMgLSAxO1xuXG4gIC8vIG9ubHkgZW1pdCBlcnJvciBldmVudCBpZiB0aGVyZSBpcyBhIGxpc3RlbmVyXG4gIC8vIG90aGVyd2lzZSB3ZSBhc3N1bWUgdGhlIGNhbGxiYWNrIHRvIGAuZW5kKClgIHdpbGwgZ2V0IHRoZSBlcnJvclxuICBpZiAoZXJyICYmIHRoaXMubGlzdGVuZXJzKCdlcnJvcicpLmxlbmd0aCA+IDApIHtcbiAgICB0aGlzLmVtaXQoJ2Vycm9yJywgZXJyKTtcbiAgfVxuXG4gIGZuKGVyciwgcmVzKTtcbn07XG5cbi8qKlxuICogQ2hlY2sgaWYgYG9iamAgaXMgYSBob3N0IG9iamVjdCxcbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqIGhvc3Qgb2JqZWN0XG4gKiBAcmV0dXJuIHtCb29sZWFufSBpcyBhIGhvc3Qgb2JqZWN0XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuUmVxdWVzdC5wcm90b3R5cGUuX2lzSG9zdCA9IGZ1bmN0aW9uIChvYmopIHtcbiAgcmV0dXJuIChcbiAgICBCdWZmZXIuaXNCdWZmZXIob2JqKSB8fCBvYmogaW5zdGFuY2VvZiBTdHJlYW0gfHwgb2JqIGluc3RhbmNlb2YgRm9ybURhdGFcbiAgKTtcbn07XG5cbi8qKlxuICogSW5pdGlhdGUgcmVxdWVzdCwgaW52b2tpbmcgY2FsbGJhY2sgYGZuKGVyciwgcmVzKWBcbiAqIHdpdGggYW4gaW5zdGFuY2VvZiBgUmVzcG9uc2VgLlxuICpcbiAqIEBwYXJhbSB7RnVuY3Rpb259IGZuXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuX2VtaXRSZXNwb25zZSA9IGZ1bmN0aW9uIChib2R5LCBmaWxlcykge1xuICBjb25zdCByZXNwb25zZSA9IG5ldyBSZXNwb25zZSh0aGlzKTtcbiAgdGhpcy5yZXNwb25zZSA9IHJlc3BvbnNlO1xuICByZXNwb25zZS5yZWRpcmVjdHMgPSB0aGlzLl9yZWRpcmVjdExpc3Q7XG4gIGlmICh1bmRlZmluZWQgIT09IGJvZHkpIHtcbiAgICByZXNwb25zZS5ib2R5ID0gYm9keTtcbiAgfVxuXG4gIHJlc3BvbnNlLmZpbGVzID0gZmlsZXM7XG4gIGlmICh0aGlzLl9lbmRDYWxsZWQpIHtcbiAgICByZXNwb25zZS5waXBlID0gZnVuY3Rpb24gKCkge1xuICAgICAgdGhyb3cgbmV3IEVycm9yKFxuICAgICAgICBcImVuZCgpIGhhcyBhbHJlYWR5IGJlZW4gY2FsbGVkLCBzbyBpdCdzIHRvbyBsYXRlIHRvIHN0YXJ0IHBpcGluZ1wiXG4gICAgICApO1xuICAgIH07XG4gIH1cblxuICB0aGlzLmVtaXQoJ3Jlc3BvbnNlJywgcmVzcG9uc2UpO1xuICByZXR1cm4gcmVzcG9uc2U7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5lbmQgPSBmdW5jdGlvbiAoZm4pIHtcbiAgdGhpcy5yZXF1ZXN0KCk7XG4gIGRlYnVnKCclcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG5cbiAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgIHRocm93IG5ldyBFcnJvcihcbiAgICAgICcuZW5kKCkgd2FzIGNhbGxlZCB0d2ljZS4gVGhpcyBpcyBub3Qgc3VwcG9ydGVkIGluIHN1cGVyYWdlbnQnXG4gICAgKTtcbiAgfVxuXG4gIHRoaXMuX2VuZENhbGxlZCA9IHRydWU7XG5cbiAgLy8gc3RvcmUgY2FsbGJhY2tcbiAgdGhpcy5fY2FsbGJhY2sgPSBmbiB8fCBub29wO1xuXG4gIHRoaXMuX2VuZCgpO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUuX2VuZCA9IGZ1bmN0aW9uICgpIHtcbiAgaWYgKHRoaXMuX2Fib3J0ZWQpXG4gICAgcmV0dXJuIHRoaXMuY2FsbGJhY2soXG4gICAgICBuZXcgRXJyb3IoJ1RoZSByZXF1ZXN0IGhhcyBiZWVuIGFib3J0ZWQgZXZlbiBiZWZvcmUgLmVuZCgpIHdhcyBjYWxsZWQnKVxuICAgICk7XG5cbiAgbGV0IGRhdGEgPSB0aGlzLl9kYXRhO1xuICBjb25zdCB7IHJlcSB9ID0gdGhpcztcbiAgY29uc3QgeyBtZXRob2QgfSA9IHRoaXM7XG5cbiAgdGhpcy5fc2V0VGltZW91dHMoKTtcblxuICAvLyBib2R5XG4gIGlmIChtZXRob2QgIT09ICdIRUFEJyAmJiAhcmVxLl9oZWFkZXJTZW50KSB7XG4gICAgLy8gc2VyaWFsaXplIHN0dWZmXG4gICAgaWYgKHR5cGVvZiBkYXRhICE9PSAnc3RyaW5nJykge1xuICAgICAgbGV0IGNvbnRlbnRUeXBlID0gcmVxLmdldEhlYWRlcignQ29udGVudC1UeXBlJyk7XG4gICAgICAvLyBQYXJzZSBvdXQganVzdCB0aGUgY29udGVudCB0eXBlIGZyb20gdGhlIGhlYWRlciAoaWdub3JlIHRoZSBjaGFyc2V0KVxuICAgICAgaWYgKGNvbnRlbnRUeXBlKSBjb250ZW50VHlwZSA9IGNvbnRlbnRUeXBlLnNwbGl0KCc7JylbMF07XG4gICAgICBsZXQgc2VyaWFsaXplID0gdGhpcy5fc2VyaWFsaXplciB8fCBleHBvcnRzLnNlcmlhbGl6ZVtjb250ZW50VHlwZV07XG4gICAgICBpZiAoIXNlcmlhbGl6ZSAmJiBpc0pTT04oY29udGVudFR5cGUpKSB7XG4gICAgICAgIHNlcmlhbGl6ZSA9IGV4cG9ydHMuc2VyaWFsaXplWydhcHBsaWNhdGlvbi9qc29uJ107XG4gICAgICB9XG5cbiAgICAgIGlmIChzZXJpYWxpemUpIGRhdGEgPSBzZXJpYWxpemUoZGF0YSk7XG4gICAgfVxuXG4gICAgLy8gY29udGVudC1sZW5ndGhcbiAgICBpZiAoZGF0YSAmJiAhcmVxLmdldEhlYWRlcignQ29udGVudC1MZW5ndGgnKSkge1xuICAgICAgcmVxLnNldEhlYWRlcihcbiAgICAgICAgJ0NvbnRlbnQtTGVuZ3RoJyxcbiAgICAgICAgQnVmZmVyLmlzQnVmZmVyKGRhdGEpID8gZGF0YS5sZW5ndGggOiBCdWZmZXIuYnl0ZUxlbmd0aChkYXRhKVxuICAgICAgKTtcbiAgICB9XG4gIH1cblxuICAvLyByZXNwb25zZVxuICAvLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgY29tcGxleGl0eVxuICByZXEub25jZSgncmVzcG9uc2UnLCAocmVzKSA9PiB7XG4gICAgZGVidWcoJyVzICVzIC0+ICVzJywgdGhpcy5tZXRob2QsIHRoaXMudXJsLCByZXMuc3RhdHVzQ29kZSk7XG5cbiAgICBpZiAodGhpcy5fcmVzcG9uc2VUaW1lb3V0VGltZXIpIHtcbiAgICAgIGNsZWFyVGltZW91dCh0aGlzLl9yZXNwb25zZVRpbWVvdXRUaW1lcik7XG4gICAgfVxuXG4gICAgaWYgKHRoaXMucGlwZWQpIHtcbiAgICAgIHJldHVybjtcbiAgICB9XG5cbiAgICBjb25zdCBtYXggPSB0aGlzLl9tYXhSZWRpcmVjdHM7XG4gICAgY29uc3QgbWltZSA9IHV0aWxzLnR5cGUocmVzLmhlYWRlcnNbJ2NvbnRlbnQtdHlwZSddIHx8ICcnKSB8fCAndGV4dC9wbGFpbic7XG4gICAgbGV0IHR5cGUgPSBtaW1lLnNwbGl0KCcvJylbMF07XG4gICAgaWYgKHR5cGUpIHR5cGUgPSB0eXBlLnRvTG93ZXJDYXNlKCkudHJpbSgpO1xuICAgIGNvbnN0IG11bHRpcGFydCA9IHR5cGUgPT09ICdtdWx0aXBhcnQnO1xuICAgIGNvbnN0IHJlZGlyZWN0ID0gaXNSZWRpcmVjdChyZXMuc3RhdHVzQ29kZSk7XG4gICAgY29uc3QgcmVzcG9uc2VUeXBlID0gdGhpcy5fcmVzcG9uc2VUeXBlO1xuXG4gICAgdGhpcy5yZXMgPSByZXM7XG5cbiAgICAvLyByZWRpcmVjdFxuICAgIGlmIChyZWRpcmVjdCAmJiB0aGlzLl9yZWRpcmVjdHMrKyAhPT0gbWF4KSB7XG4gICAgICByZXR1cm4gdGhpcy5fcmVkaXJlY3QocmVzKTtcbiAgICB9XG5cbiAgICBpZiAodGhpcy5tZXRob2QgPT09ICdIRUFEJykge1xuICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICAgIHRoaXMuY2FsbGJhY2sobnVsbCwgdGhpcy5fZW1pdFJlc3BvbnNlKCkpO1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIHpsaWIgc3VwcG9ydFxuICAgIGlmICh0aGlzLl9zaG91bGRVbnppcChyZXMpKSB7XG4gICAgICB1bnppcChyZXEsIHJlcyk7XG4gICAgfVxuXG4gICAgbGV0IGJ1ZmZlciA9IHRoaXMuX2J1ZmZlcjtcbiAgICBpZiAoYnVmZmVyID09PSB1bmRlZmluZWQgJiYgbWltZSBpbiBleHBvcnRzLmJ1ZmZlcikge1xuICAgICAgYnVmZmVyID0gQm9vbGVhbihleHBvcnRzLmJ1ZmZlclttaW1lXSk7XG4gICAgfVxuXG4gICAgbGV0IHBhcnNlciA9IHRoaXMuX3BhcnNlcjtcbiAgICBpZiAodW5kZWZpbmVkID09PSBidWZmZXIpIHtcbiAgICAgIGlmIChwYXJzZXIpIHtcbiAgICAgICAgY29uc29sZS53YXJuKFxuICAgICAgICAgIFwiQSBjdXN0b20gc3VwZXJhZ2VudCBwYXJzZXIgaGFzIGJlZW4gc2V0LCBidXQgYnVmZmVyaW5nIHN0cmF0ZWd5IGZvciB0aGUgcGFyc2VyIGhhc24ndCBiZWVuIGNvbmZpZ3VyZWQuIENhbGwgYHJlcS5idWZmZXIodHJ1ZSBvciBmYWxzZSlgIG9yIHNldCBgc3VwZXJhZ2VudC5idWZmZXJbbWltZV0gPSB0cnVlIG9yIGZhbHNlYFwiXG4gICAgICAgICk7XG4gICAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgICB9XG4gICAgfVxuXG4gICAgaWYgKCFwYXJzZXIpIHtcbiAgICAgIGlmIChyZXNwb25zZVR5cGUpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS5pbWFnZTsgLy8gSXQncyBhY3R1YWxseSBhIGdlbmVyaWMgQnVmZmVyXG4gICAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgICB9IGVsc2UgaWYgKG11bHRpcGFydCkge1xuICAgICAgICBjb25zdCBmb3JtID0gbmV3IGZvcm1pZGFibGUuSW5jb21pbmdGb3JtKCk7XG4gICAgICAgIHBhcnNlciA9IGZvcm0ucGFyc2UuYmluZChmb3JtKTtcbiAgICAgICAgYnVmZmVyID0gdHJ1ZTtcbiAgICAgIH0gZWxzZSBpZiAoaXNJbWFnZU9yVmlkZW8obWltZSkpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS5pbWFnZTtcbiAgICAgICAgYnVmZmVyID0gdHJ1ZTsgLy8gRm9yIGJhY2t3YXJkcy1jb21wYXRpYmlsaXR5IGJ1ZmZlcmluZyBkZWZhdWx0IGlzIGFkLWhvYyBNSU1FLWRlcGVuZGVudFxuICAgICAgfSBlbHNlIGlmIChleHBvcnRzLnBhcnNlW21pbWVdKSB7XG4gICAgICAgIHBhcnNlciA9IGV4cG9ydHMucGFyc2VbbWltZV07XG4gICAgICB9IGVsc2UgaWYgKHR5cGUgPT09ICd0ZXh0Jykge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlLnRleHQ7XG4gICAgICAgIGJ1ZmZlciA9IGJ1ZmZlciAhPT0gZmFsc2U7XG5cbiAgICAgICAgLy8gZXZlcnlvbmUgd2FudHMgdGhlaXIgb3duIHdoaXRlLWxhYmVsZWQganNvblxuICAgICAgfSBlbHNlIGlmIChpc0pTT04obWltZSkpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZVsnYXBwbGljYXRpb24vanNvbiddO1xuICAgICAgICBidWZmZXIgPSBidWZmZXIgIT09IGZhbHNlO1xuICAgICAgfSBlbHNlIGlmIChidWZmZXIpIHtcbiAgICAgICAgcGFyc2VyID0gZXhwb3J0cy5wYXJzZS50ZXh0O1xuICAgICAgfSBlbHNlIGlmICh1bmRlZmluZWQgPT09IGJ1ZmZlcikge1xuICAgICAgICBwYXJzZXIgPSBleHBvcnRzLnBhcnNlLmltYWdlOyAvLyBJdCdzIGFjdHVhbGx5IGEgZ2VuZXJpYyBCdWZmZXJcbiAgICAgICAgYnVmZmVyID0gdHJ1ZTtcbiAgICAgIH1cbiAgICB9XG5cbiAgICAvLyBieSBkZWZhdWx0IG9ubHkgYnVmZmVyIHRleHQvKiwganNvbiBhbmQgbWVzc2VkIHVwIHRoaW5nIGZyb20gaGVsbFxuICAgIGlmICgodW5kZWZpbmVkID09PSBidWZmZXIgJiYgaXNUZXh0KG1pbWUpKSB8fCBpc0pTT04obWltZSkpIHtcbiAgICAgIGJ1ZmZlciA9IHRydWU7XG4gICAgfVxuXG4gICAgdGhpcy5fcmVzQnVmZmVyZWQgPSBidWZmZXI7XG4gICAgbGV0IHBhcnNlckhhbmRsZXNFbmQgPSBmYWxzZTtcbiAgICBpZiAoYnVmZmVyKSB7XG4gICAgICAvLyBQcm90ZWN0aW9uYSBhZ2FpbnN0IHppcCBib21icyBhbmQgb3RoZXIgbnVpc2FuY2VcbiAgICAgIGxldCByZXNwb25zZUJ5dGVzTGVmdCA9IHRoaXMuX21heFJlc3BvbnNlU2l6ZSB8fCAyMDAwMDAwMDA7XG4gICAgICByZXMub24oJ2RhdGEnLCAoYnVmKSA9PiB7XG4gICAgICAgIHJlc3BvbnNlQnl0ZXNMZWZ0IC09IGJ1Zi5ieXRlTGVuZ3RoIHx8IGJ1Zi5sZW5ndGg7XG4gICAgICAgIGlmIChyZXNwb25zZUJ5dGVzTGVmdCA8IDApIHtcbiAgICAgICAgICAvLyBUaGlzIHdpbGwgcHJvcGFnYXRlIHRocm91Z2ggZXJyb3IgZXZlbnRcbiAgICAgICAgICBjb25zdCBlcnIgPSBuZXcgRXJyb3IoJ01heGltdW0gcmVzcG9uc2Ugc2l6ZSByZWFjaGVkJyk7XG4gICAgICAgICAgZXJyLmNvZGUgPSAnRVRPT0xBUkdFJztcbiAgICAgICAgICAvLyBQYXJzZXJzIGFyZW4ndCByZXF1aXJlZCB0byBvYnNlcnZlIGVycm9yIGV2ZW50LFxuICAgICAgICAgIC8vIHNvIHdvdWxkIGluY29ycmVjdGx5IHJlcG9ydCBzdWNjZXNzXG4gICAgICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGZhbHNlO1xuICAgICAgICAgIC8vIFdpbGwgZW1pdCBlcnJvciBldmVudFxuICAgICAgICAgIHJlcy5kZXN0cm95KGVycik7XG4gICAgICAgIH1cbiAgICAgIH0pO1xuICAgIH1cblxuICAgIGlmIChwYXJzZXIpIHtcbiAgICAgIHRyeSB7XG4gICAgICAgIC8vIFVuYnVmZmVyZWQgcGFyc2VycyBhcmUgc3VwcG9zZWQgdG8gZW1pdCByZXNwb25zZSBlYXJseSxcbiAgICAgICAgLy8gd2hpY2ggaXMgd2VpcmQgQlRXLCBiZWNhdXNlIHJlc3BvbnNlLmJvZHkgd29uJ3QgYmUgdGhlcmUuXG4gICAgICAgIHBhcnNlckhhbmRsZXNFbmQgPSBidWZmZXI7XG5cbiAgICAgICAgcGFyc2VyKHJlcywgKGVyciwgb2JqLCBmaWxlcykgPT4ge1xuICAgICAgICAgIGlmICh0aGlzLnRpbWVkb3V0KSB7XG4gICAgICAgICAgICAvLyBUaW1lb3V0IGhhcyBhbHJlYWR5IGhhbmRsZWQgYWxsIGNhbGxiYWNrc1xuICAgICAgICAgICAgcmV0dXJuO1xuICAgICAgICAgIH1cblxuICAgICAgICAgIC8vIEludGVudGlvbmFsIChub24tdGltZW91dCkgYWJvcnQgaXMgc3VwcG9zZWQgdG8gcHJlc2VydmUgcGFydGlhbCByZXNwb25zZSxcbiAgICAgICAgICAvLyBldmVuIGlmIGl0IGRvZXNuJ3QgcGFyc2UuXG4gICAgICAgICAgaWYgKGVyciAmJiAhdGhpcy5fYWJvcnRlZCkge1xuICAgICAgICAgICAgcmV0dXJuIHRoaXMuY2FsbGJhY2soZXJyKTtcbiAgICAgICAgICB9XG5cbiAgICAgICAgICBpZiAocGFyc2VySGFuZGxlc0VuZCkge1xuICAgICAgICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICAgICAgICAgIHRoaXMuY2FsbGJhY2sobnVsbCwgdGhpcy5fZW1pdFJlc3BvbnNlKG9iaiwgZmlsZXMpKTtcbiAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgfSBjYXRjaCAoZXJyKSB7XG4gICAgICAgIHRoaXMuY2FsbGJhY2soZXJyKTtcbiAgICAgICAgcmV0dXJuO1xuICAgICAgfVxuICAgIH1cblxuICAgIHRoaXMucmVzID0gcmVzO1xuXG4gICAgLy8gdW5idWZmZXJlZFxuICAgIGlmICghYnVmZmVyKSB7XG4gICAgICBkZWJ1ZygndW5idWZmZXJlZCAlcyAlcycsIHRoaXMubWV0aG9kLCB0aGlzLnVybCk7XG4gICAgICB0aGlzLmNhbGxiYWNrKG51bGwsIHRoaXMuX2VtaXRSZXNwb25zZSgpKTtcbiAgICAgIGlmIChtdWx0aXBhcnQpIHJldHVybjsgLy8gYWxsb3cgbXVsdGlwYXJ0IHRvIGhhbmRsZSBlbmQgZXZlbnRcbiAgICAgIHJlcy5vbmNlKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgIGRlYnVnKCdlbmQgJXMgJXMnLCB0aGlzLm1ldGhvZCwgdGhpcy51cmwpO1xuICAgICAgICB0aGlzLmVtaXQoJ2VuZCcpO1xuICAgICAgfSk7XG4gICAgICByZXR1cm47XG4gICAgfVxuXG4gICAgLy8gdGVybWluYXRpbmcgZXZlbnRzXG4gICAgcmVzLm9uY2UoJ2Vycm9yJywgKGVycikgPT4ge1xuICAgICAgcGFyc2VySGFuZGxlc0VuZCA9IGZhbHNlO1xuICAgICAgdGhpcy5jYWxsYmFjayhlcnIsIG51bGwpO1xuICAgIH0pO1xuICAgIGlmICghcGFyc2VySGFuZGxlc0VuZClcbiAgICAgIHJlcy5vbmNlKCdlbmQnLCAoKSA9PiB7XG4gICAgICAgIGRlYnVnKCdlbmQgJXMgJXMnLCB0aGlzLm1ldGhvZCwgdGhpcy51cmwpO1xuICAgICAgICAvLyBUT0RPOiB1bmxlc3MgYnVmZmVyaW5nIGVtaXQgZWFybGllciB0byBzdHJlYW1cbiAgICAgICAgdGhpcy5lbWl0KCdlbmQnKTtcbiAgICAgICAgdGhpcy5jYWxsYmFjayhudWxsLCB0aGlzLl9lbWl0UmVzcG9uc2UoKSk7XG4gICAgICB9KTtcbiAgfSk7XG5cbiAgdGhpcy5lbWl0KCdyZXF1ZXN0JywgdGhpcyk7XG5cbiAgY29uc3QgZ2V0UHJvZ3Jlc3NNb25pdG9yID0gKCkgPT4ge1xuICAgIGNvbnN0IGxlbmd0aENvbXB1dGFibGUgPSB0cnVlO1xuICAgIGNvbnN0IHRvdGFsID0gcmVxLmdldEhlYWRlcignQ29udGVudC1MZW5ndGgnKTtcbiAgICBsZXQgbG9hZGVkID0gMDtcblxuICAgIGNvbnN0IHByb2dyZXNzID0gbmV3IFN0cmVhbS5UcmFuc2Zvcm0oKTtcbiAgICBwcm9ncmVzcy5fdHJhbnNmb3JtID0gKGNodW5rLCBlbmNvZGluZywgY2IpID0+IHtcbiAgICAgIGxvYWRlZCArPSBjaHVuay5sZW5ndGg7XG4gICAgICB0aGlzLmVtaXQoJ3Byb2dyZXNzJywge1xuICAgICAgICBkaXJlY3Rpb246ICd1cGxvYWQnLFxuICAgICAgICBsZW5ndGhDb21wdXRhYmxlLFxuICAgICAgICBsb2FkZWQsXG4gICAgICAgIHRvdGFsXG4gICAgICB9KTtcbiAgICAgIGNiKG51bGwsIGNodW5rKTtcbiAgICB9O1xuXG4gICAgcmV0dXJuIHByb2dyZXNzO1xuICB9O1xuXG4gIGNvbnN0IGJ1ZmZlclRvQ2h1bmtzID0gKGJ1ZmZlcikgPT4ge1xuICAgIGNvbnN0IGNodW5rU2l6ZSA9IDE2ICogMTAyNDsgLy8gZGVmYXVsdCBoaWdoV2F0ZXJNYXJrIHZhbHVlXG4gICAgY29uc3QgY2h1bmtpbmcgPSBuZXcgU3RyZWFtLlJlYWRhYmxlKCk7XG4gICAgY29uc3QgdG90YWxMZW5ndGggPSBidWZmZXIubGVuZ3RoO1xuICAgIGNvbnN0IHJlbWFpbmRlciA9IHRvdGFsTGVuZ3RoICUgY2h1bmtTaXplO1xuICAgIGNvbnN0IGN1dG9mZiA9IHRvdGFsTGVuZ3RoIC0gcmVtYWluZGVyO1xuXG4gICAgZm9yIChsZXQgaSA9IDA7IGkgPCBjdXRvZmY7IGkgKz0gY2h1bmtTaXplKSB7XG4gICAgICBjb25zdCBjaHVuayA9IGJ1ZmZlci5zbGljZShpLCBpICsgY2h1bmtTaXplKTtcbiAgICAgIGNodW5raW5nLnB1c2goY2h1bmspO1xuICAgIH1cblxuICAgIGlmIChyZW1haW5kZXIgPiAwKSB7XG4gICAgICBjb25zdCByZW1haW5kZXJCdWZmZXIgPSBidWZmZXIuc2xpY2UoLXJlbWFpbmRlcik7XG4gICAgICBjaHVua2luZy5wdXNoKHJlbWFpbmRlckJ1ZmZlcik7XG4gICAgfVxuXG4gICAgY2h1bmtpbmcucHVzaChudWxsKTsgLy8gbm8gbW9yZSBkYXRhXG5cbiAgICByZXR1cm4gY2h1bmtpbmc7XG4gIH07XG5cbiAgLy8gaWYgYSBGb3JtRGF0YSBpbnN0YW5jZSBnb3QgY3JlYXRlZCwgdGhlbiB3ZSBzZW5kIHRoYXQgYXMgdGhlIHJlcXVlc3QgYm9keVxuICBjb25zdCBmb3JtRGF0YSA9IHRoaXMuX2Zvcm1EYXRhO1xuICBpZiAoZm9ybURhdGEpIHtcbiAgICAvLyBzZXQgaGVhZGVyc1xuICAgIGNvbnN0IGhlYWRlcnMgPSBmb3JtRGF0YS5nZXRIZWFkZXJzKCk7XG4gICAgZm9yIChjb25zdCBpIGluIGhlYWRlcnMpIHtcbiAgICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwoaGVhZGVycywgaSkpIHtcbiAgICAgICAgZGVidWcoJ3NldHRpbmcgRm9ybURhdGEgaGVhZGVyOiBcIiVzOiAlc1wiJywgaSwgaGVhZGVyc1tpXSk7XG4gICAgICAgIHJlcS5zZXRIZWFkZXIoaSwgaGVhZGVyc1tpXSk7XG4gICAgICB9XG4gICAgfVxuXG4gICAgLy8gYXR0ZW1wdCB0byBnZXQgXCJDb250ZW50LUxlbmd0aFwiIGhlYWRlclxuICAgIGZvcm1EYXRhLmdldExlbmd0aCgoZXJyLCBsZW5ndGgpID0+IHtcbiAgICAgIC8vIFRPRE86IEFkZCBjaHVua2VkIGVuY29kaW5nIHdoZW4gbm8gbGVuZ3RoIChpZiBlcnIpXG4gICAgICBpZiAoZXJyKSBkZWJ1ZygnZm9ybURhdGEuZ2V0TGVuZ3RoIGhhZCBlcnJvcicsIGVyciwgbGVuZ3RoKTtcblxuICAgICAgZGVidWcoJ2dvdCBGb3JtRGF0YSBDb250ZW50LUxlbmd0aDogJXMnLCBsZW5ndGgpO1xuICAgICAgaWYgKHR5cGVvZiBsZW5ndGggPT09ICdudW1iZXInKSB7XG4gICAgICAgIHJlcS5zZXRIZWFkZXIoJ0NvbnRlbnQtTGVuZ3RoJywgbGVuZ3RoKTtcbiAgICAgIH1cblxuICAgICAgZm9ybURhdGEucGlwZShnZXRQcm9ncmVzc01vbml0b3IoKSkucGlwZShyZXEpO1xuICAgIH0pO1xuICB9IGVsc2UgaWYgKEJ1ZmZlci5pc0J1ZmZlcihkYXRhKSkge1xuICAgIGJ1ZmZlclRvQ2h1bmtzKGRhdGEpLnBpcGUoZ2V0UHJvZ3Jlc3NNb25pdG9yKCkpLnBpcGUocmVxKTtcbiAgfSBlbHNlIHtcbiAgICByZXEuZW5kKGRhdGEpO1xuICB9XG59O1xuXG4vLyBDaGVjayB3aGV0aGVyIHJlc3BvbnNlIGhhcyBhIG5vbi0wLXNpemVkIGd6aXAtZW5jb2RlZCBib2R5XG5SZXF1ZXN0LnByb3RvdHlwZS5fc2hvdWxkVW56aXAgPSAocmVzKSA9PiB7XG4gIGlmIChyZXMuc3RhdHVzQ29kZSA9PT0gMjA0IHx8IHJlcy5zdGF0dXNDb2RlID09PSAzMDQpIHtcbiAgICAvLyBUaGVzZSBhcmVuJ3Qgc3VwcG9zZWQgdG8gaGF2ZSBhbnkgYm9keVxuICAgIHJldHVybiBmYWxzZTtcbiAgfVxuXG4gIC8vIGhlYWRlciBjb250ZW50IGlzIGEgc3RyaW5nLCBhbmQgZGlzdGluY3Rpb24gYmV0d2VlbiAwIGFuZCBubyBpbmZvcm1hdGlvbiBpcyBjcnVjaWFsXG4gIGlmIChyZXMuaGVhZGVyc1snY29udGVudC1sZW5ndGgnXSA9PT0gJzAnKSB7XG4gICAgLy8gV2Uga25vdyB0aGF0IHRoZSBib2R5IGlzIGVtcHR5ICh1bmZvcnR1bmF0ZWx5LCB0aGlzIGNoZWNrIGRvZXMgbm90IGNvdmVyIGNodW5rZWQgZW5jb2RpbmcpXG4gICAgcmV0dXJuIGZhbHNlO1xuICB9XG5cbiAgLy8gY29uc29sZS5sb2cocmVzKTtcbiAgcmV0dXJuIC9eXFxzKig/OmRlZmxhdGV8Z3ppcClcXHMqJC8udGVzdChyZXMuaGVhZGVyc1snY29udGVudC1lbmNvZGluZyddKTtcbn07XG5cbi8qKlxuICogT3ZlcnJpZGVzIEROUyBmb3Igc2VsZWN0ZWQgaG9zdG5hbWVzLiBUYWtlcyBvYmplY3QgbWFwcGluZyBob3N0bmFtZXMgdG8gSVAgYWRkcmVzc2VzLlxuICpcbiAqIFdoZW4gbWFraW5nIGEgcmVxdWVzdCB0byBhIFVSTCB3aXRoIGEgaG9zdG5hbWUgZXhhY3RseSBtYXRjaGluZyBhIGtleSBpbiB0aGUgb2JqZWN0LFxuICogdXNlIHRoZSBnaXZlbiBJUCBhZGRyZXNzIHRvIGNvbm5lY3QsIGluc3RlYWQgb2YgdXNpbmcgRE5TIHRvIHJlc29sdmUgdGhlIGhvc3RuYW1lLlxuICpcbiAqIEEgc3BlY2lhbCBob3N0IGAqYCBtYXRjaGVzIGV2ZXJ5IGhvc3RuYW1lIChrZWVwIHJlZGlyZWN0cyBpbiBtaW5kISlcbiAqXG4gKiAgICAgIHJlcXVlc3QuY29ubmVjdCh7XG4gKiAgICAgICAgJ3Rlc3QuZXhhbXBsZS5jb20nOiAnMTI3LjAuMC4xJyxcbiAqICAgICAgICAnaXB2Ni5leGFtcGxlLmNvbSc6ICc6OjEnLFxuICogICAgICB9KVxuICovXG5SZXF1ZXN0LnByb3RvdHlwZS5jb25uZWN0ID0gZnVuY3Rpb24gKGNvbm5lY3RPdmVycmlkZSkge1xuICBpZiAodHlwZW9mIGNvbm5lY3RPdmVycmlkZSA9PT0gJ3N0cmluZycpIHtcbiAgICB0aGlzLl9jb25uZWN0T3ZlcnJpZGUgPSB7ICcqJzogY29ubmVjdE92ZXJyaWRlIH07XG4gIH0gZWxzZSBpZiAodHlwZW9mIGNvbm5lY3RPdmVycmlkZSA9PT0gJ29iamVjdCcpIHtcbiAgICB0aGlzLl9jb25uZWN0T3ZlcnJpZGUgPSBjb25uZWN0T3ZlcnJpZGU7XG4gIH0gZWxzZSB7XG4gICAgdGhpcy5fY29ubmVjdE92ZXJyaWRlID0gdW5kZWZpbmVkO1xuICB9XG5cbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS50cnVzdExvY2FsaG9zdCA9IGZ1bmN0aW9uICh0b2dnbGUpIHtcbiAgdGhpcy5fdHJ1c3RMb2NhbGhvc3QgPSB0b2dnbGUgPT09IHVuZGVmaW5lZCA/IHRydWUgOiB0b2dnbGU7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLy8gZ2VuZXJhdGUgSFRUUCB2ZXJiIG1ldGhvZHNcbmlmICghbWV0aG9kcy5pbmNsdWRlcygnZGVsJykpIHtcbiAgLy8gY3JlYXRlIGEgY29weSBzbyB3ZSBkb24ndCBjYXVzZSBjb25mbGljdHMgd2l0aFxuICAvLyBvdGhlciBwYWNrYWdlcyB1c2luZyB0aGUgbWV0aG9kcyBwYWNrYWdlIGFuZFxuICAvLyBucG0gMy54XG4gIG1ldGhvZHMgPSBtZXRob2RzLnNsaWNlKDApO1xuICBtZXRob2RzLnB1c2goJ2RlbCcpO1xufVxuXG5tZXRob2RzLmZvckVhY2goKG1ldGhvZCkgPT4ge1xuICBjb25zdCBuYW1lID0gbWV0aG9kO1xuICBtZXRob2QgPSBtZXRob2QgPT09ICdkZWwnID8gJ2RlbGV0ZScgOiBtZXRob2Q7XG5cbiAgbWV0aG9kID0gbWV0aG9kLnRvVXBwZXJDYXNlKCk7XG4gIHJlcXVlc3RbbmFtZV0gPSAodXJsLCBkYXRhLCBmbikgPT4ge1xuICAgIGNvbnN0IHJlcSA9IHJlcXVlc3QobWV0aG9kLCB1cmwpO1xuICAgIGlmICh0eXBlb2YgZGF0YSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgICAgZm4gPSBkYXRhO1xuICAgICAgZGF0YSA9IG51bGw7XG4gICAgfVxuXG4gICAgaWYgKGRhdGEpIHtcbiAgICAgIGlmIChtZXRob2QgPT09ICdHRVQnIHx8IG1ldGhvZCA9PT0gJ0hFQUQnKSB7XG4gICAgICAgIHJlcS5xdWVyeShkYXRhKTtcbiAgICAgIH0gZWxzZSB7XG4gICAgICAgIHJlcS5zZW5kKGRhdGEpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGlmIChmbikgcmVxLmVuZChmbik7XG4gICAgcmV0dXJuIHJlcTtcbiAgfTtcbn0pO1xuXG4vKipcbiAqIENoZWNrIGlmIGBtaW1lYCBpcyB0ZXh0IGFuZCBzaG91bGQgYmUgYnVmZmVyZWQuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IG1pbWVcbiAqIEByZXR1cm4ge0Jvb2xlYW59XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIGlzVGV4dChtaW1lKSB7XG4gIGNvbnN0IHBhcnRzID0gbWltZS5zcGxpdCgnLycpO1xuICBsZXQgdHlwZSA9IHBhcnRzWzBdO1xuICBpZiAodHlwZSkgdHlwZSA9IHR5cGUudG9Mb3dlckNhc2UoKS50cmltKCk7XG4gIGxldCBzdWJ0eXBlID0gcGFydHNbMV07XG4gIGlmIChzdWJ0eXBlKSBzdWJ0eXBlID0gc3VidHlwZS50b0xvd2VyQ2FzZSgpLnRyaW0oKTtcblxuICByZXR1cm4gdHlwZSA9PT0gJ3RleHQnIHx8IHN1YnR5cGUgPT09ICd4LXd3dy1mb3JtLXVybGVuY29kZWQnO1xufVxuXG5mdW5jdGlvbiBpc0ltYWdlT3JWaWRlbyhtaW1lKSB7XG4gIGxldCB0eXBlID0gbWltZS5zcGxpdCgnLycpWzBdO1xuICBpZiAodHlwZSkgdHlwZSA9IHR5cGUudG9Mb3dlckNhc2UoKS50cmltKCk7XG5cbiAgcmV0dXJuIHR5cGUgPT09ICdpbWFnZScgfHwgdHlwZSA9PT0gJ3ZpZGVvJztcbn1cblxuLyoqXG4gKiBDaGVjayBpZiBgbWltZWAgaXMganNvbiBvciBoYXMgK2pzb24gc3RydWN0dXJlZCBzeW50YXggc3VmZml4LlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBtaW1lXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gaXNKU09OKG1pbWUpIHtcbiAgLy8gc2hvdWxkIG1hdGNoIC9qc29uIG9yICtqc29uXG4gIC8vIGJ1dCBub3QgL2pzb24tc2VxXG4gIHJldHVybiAvWy8rXWpzb24oJHxbXi1cXHddKS9pLnRlc3QobWltZSk7XG59XG5cbi8qKlxuICogQ2hlY2sgaWYgd2Ugc2hvdWxkIGZvbGxvdyB0aGUgcmVkaXJlY3QgYGNvZGVgLlxuICpcbiAqIEBwYXJhbSB7TnVtYmVyfSBjb2RlXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gaXNSZWRpcmVjdChjb2RlKSB7XG4gIHJldHVybiBbMzAxLCAzMDIsIDMwMywgMzA1LCAzMDcsIDMwOF0uaW5jbHVkZXMoY29kZSk7XG59XG4iXX0=