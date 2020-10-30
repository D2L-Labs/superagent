"use strict";

function _typeof(obj) { "@babel/helpers - typeof"; if (typeof Symbol === "function" && typeof Symbol.iterator === "symbol") { _typeof = function _typeof(obj) { return typeof obj; }; } else { _typeof = function _typeof(obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; }; } return _typeof(obj); }

/**
 * Root reference for iframes.
 */
var root;

if (typeof window !== 'undefined') {
  // Browser window
  root = window;
} else if (typeof self === 'undefined') {
  // Other environments
  console.warn('Using browser-only version of superagent in non-browser environment');
  root = void 0;
} else {
  // Web Worker
  root = self;
}

var Emitter = require('component-emitter');

var safeStringify = require('fast-safe-stringify');

var qs = require('qs');

var RequestBase = require('./request-base');

var isObject = require('./is-object');

var ResponseBase = require('./response-base');

var Agent = require('./agent-base');
/**
 * Noop.
 */


function noop() {}
/**
 * Expose `request`.
 */


module.exports = function (method, url) {
  // callback
  if (typeof url === 'function') {
    return new exports.Request('GET', method).end(url);
  } // url first


  if (arguments.length === 1) {
    return new exports.Request('GET', method);
  }

  return new exports.Request(method, url);
};

exports = module.exports;
var request = exports;
exports.Request = Request;
/**
 * Determine XHR.
 */

request.getXHR = function () {
  if (root.XMLHttpRequest && (!root.location || root.location.protocol !== 'file:' || !root.ActiveXObject)) {
    return new XMLHttpRequest();
  }

  try {
    return new ActiveXObject('Microsoft.XMLHTTP');
  } catch (_unused) {}

  try {
    return new ActiveXObject('Msxml2.XMLHTTP.6.0');
  } catch (_unused2) {}

  try {
    return new ActiveXObject('Msxml2.XMLHTTP.3.0');
  } catch (_unused3) {}

  try {
    return new ActiveXObject('Msxml2.XMLHTTP');
  } catch (_unused4) {}

  throw new Error('Browser-only version of superagent could not find XHR');
};
/**
 * Removes leading and trailing whitespace, added to support IE.
 *
 * @param {String} s
 * @return {String}
 * @api private
 */


var trim = ''.trim ? function (s) {
  return s.trim();
} : function (s) {
  return s.replace(/(^\s*|\s*$)/g, '');
};
/**
 * Serialize the given `obj`.
 *
 * @param {Object} obj
 * @return {String}
 * @api private
 */

function serialize(obj) {
  if (!isObject(obj)) return obj;
  var pairs = [];

  for (var key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) pushEncodedKeyValuePair(pairs, key, obj[key]);
  }

  return pairs.join('&');
}
/**
 * Helps 'serialize' with serializing arrays.
 * Mutates the pairs array.
 *
 * @param {Array} pairs
 * @param {String} key
 * @param {Mixed} val
 */


function pushEncodedKeyValuePair(pairs, key, val) {
  if (val === undefined) return;

  if (val === null) {
    pairs.push(encodeURI(key));
    return;
  }

  if (Array.isArray(val)) {
    val.forEach(function (v) {
      pushEncodedKeyValuePair(pairs, key, v);
    });
  } else if (isObject(val)) {
    for (var subkey in val) {
      if (Object.prototype.hasOwnProperty.call(val, subkey)) pushEncodedKeyValuePair(pairs, "".concat(key, "[").concat(subkey, "]"), val[subkey]);
    }
  } else {
    pairs.push(encodeURI(key) + '=' + encodeURIComponent(val));
  }
}
/**
 * Expose serialization method.
 */


request.serializeObject = serialize;
/**
 * Parse the given x-www-form-urlencoded `str`.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */

function parseString(str) {
  var obj = {};
  var pairs = str.split('&');
  var pair;
  var pos;

  for (var i = 0, len = pairs.length; i < len; ++i) {
    pair = pairs[i];
    pos = pair.indexOf('=');

    if (pos === -1) {
      obj[decodeURIComponent(pair)] = '';
    } else {
      obj[decodeURIComponent(pair.slice(0, pos))] = decodeURIComponent(pair.slice(pos + 1));
    }
  }

  return obj;
}
/**
 * Expose parser.
 */


request.parseString = parseString;
/**
 * Default MIME type map.
 *
 *     superagent.types.xml = 'application/xml';
 *
 */

request.types = {
  html: 'text/html',
  json: 'application/json',
  xml: 'text/xml',
  urlencoded: 'application/x-www-form-urlencoded',
  form: 'application/x-www-form-urlencoded',
  'form-data': 'application/x-www-form-urlencoded'
};
/**
 * Default serialization map.
 *
 *     superagent.serialize['application/xml'] = function(obj){
 *       return 'generated xml here';
 *     };
 *
 */

request.serialize = {
  'application/x-www-form-urlencoded': qs.stringify,
  'application/json': safeStringify
};
/**
 * Default parsers.
 *
 *     superagent.parse['application/xml'] = function(str){
 *       return { object parsed from str };
 *     };
 *
 */

request.parse = {
  'application/x-www-form-urlencoded': parseString,
  'application/json': JSON.parse
};
/**
 * Parse the given header `str` into
 * an object containing the mapped fields.
 *
 * @param {String} str
 * @return {Object}
 * @api private
 */

function parseHeader(str) {
  var lines = str.split(/\r?\n/);
  var fields = {};
  var index;
  var line;
  var field;
  var val;

  for (var i = 0, len = lines.length; i < len; ++i) {
    line = lines[i];
    index = line.indexOf(':');

    if (index === -1) {
      // could be empty line, just skip it
      continue;
    }

    field = line.slice(0, index).toLowerCase();
    val = trim(line.slice(index + 1));
    fields[field] = val;
  }

  return fields;
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
 * Initialize a new `Response` with the given `xhr`.
 *
 *  - set flags (.ok, .error, etc)
 *  - parse header
 *
 * Examples:
 *
 *  Aliasing `superagent` as `request` is nice:
 *
 *      request = superagent;
 *
 *  We can use the promise-like API, or pass callbacks:
 *
 *      request.get('/').end(function(res){});
 *      request.get('/', function(res){});
 *
 *  Sending data can be chained:
 *
 *      request
 *        .post('/user')
 *        .send({ name: 'tj' })
 *        .end(function(res){});
 *
 *  Or passed to `.send()`:
 *
 *      request
 *        .post('/user')
 *        .send({ name: 'tj' }, function(res){});
 *
 *  Or passed to `.post()`:
 *
 *      request
 *        .post('/user', { name: 'tj' })
 *        .end(function(res){});
 *
 * Or further reduced to a single call for simple cases:
 *
 *      request
 *        .post('/user', { name: 'tj' }, function(res){});
 *
 * @param {XMLHTTPRequest} xhr
 * @param {Object} options
 * @api private
 */


function Response(req) {
  this.req = req;
  this.xhr = this.req.xhr; // responseText is accessible only if responseType is '' or 'text' and on older browsers

  this.text = this.req.method !== 'HEAD' && (this.xhr.responseType === '' || this.xhr.responseType === 'text') || typeof this.xhr.responseType === 'undefined' ? this.xhr.responseText : null;
  this.statusText = this.req.xhr.statusText;
  var status = this.xhr.status; // handle IE9 bug: http://stackoverflow.com/questions/10046972/msie-returns-status-code-of-1223-for-ajax-request

  if (status === 1223) {
    status = 204;
  }

  this._setStatusProperties(status);

  this.headers = parseHeader(this.xhr.getAllResponseHeaders());
  this.header = this.headers; // getAllResponseHeaders sometimes falsely returns "" for CORS requests, but
  // getResponseHeader still works. so we get content-type even if getting
  // other headers fails.

  this.header['content-type'] = this.xhr.getResponseHeader('content-type');

  this._setHeaderProperties(this.header);

  if (this.text === null && req._responseType) {
    this.body = this.xhr.response;
  } else {
    this.body = this.req.method === 'HEAD' ? null : this._parseBody(this.text ? this.text : this.xhr.response);
  }
} // eslint-disable-next-line new-cap


ResponseBase(Response.prototype);
/**
 * Parse the given body `str`.
 *
 * Used for auto-parsing of bodies. Parsers
 * are defined on the `superagent.parse` object.
 *
 * @param {String} str
 * @return {Mixed}
 * @api private
 */

Response.prototype._parseBody = function (str) {
  var parse = request.parse[this.type];

  if (this.req._parser) {
    return this.req._parser(this, str);
  }

  if (!parse && isJSON(this.type)) {
    parse = request.parse['application/json'];
  }

  return parse && str && (str.length > 0 || str instanceof Object) ? parse(str) : null;
};
/**
 * Return an `Error` representative of this response.
 *
 * @return {Error}
 * @api public
 */


Response.prototype.toError = function () {
  var req = this.req;
  var method = req.method;
  var url = req.url;
  var msg = "cannot ".concat(method, " ").concat(url, " (").concat(this.status, ")");
  var err = new Error(msg);
  err.status = this.status;
  err.method = method;
  err.url = url;
  return err;
};
/**
 * Expose `Response`.
 */


request.Response = Response;
/**
 * Initialize a new `Request` with the given `method` and `url`.
 *
 * @param {String} method
 * @param {String} url
 * @api public
 */

function Request(method, url) {
  var self = this;
  this._query = this._query || [];
  this.method = method;
  this.url = url;
  this.header = {}; // preserves header name case

  this._header = {}; // coerces header names to lowercase

  this.on('end', function () {
    var err = null;
    var res = null;

    try {
      res = new Response(self);
    } catch (err_) {
      err = new Error('Parser is unable to parse the response');
      err.parse = true;
      err.original = err_; // issue #675: return the raw response if the response parsing fails

      if (self.xhr) {
        // ie9 doesn't have 'response' property
        err.rawResponse = typeof self.xhr.responseType === 'undefined' ? self.xhr.responseText : self.xhr.response; // issue #876: return the http status code if the response parsing fails

        err.status = self.xhr.status ? self.xhr.status : null;
        err.statusCode = err.status; // backwards-compat only
      } else {
        err.rawResponse = null;
        err.status = null;
      }

      return self.callback(err);
    }

    self.emit('response', res);
    var new_err;

    try {
      if (!self._isResponseOK(res)) {
        new_err = new Error(res.statusText || res.text || 'Unsuccessful HTTP response');
      }
    } catch (err_) {
      new_err = err_; // ok() callback can throw
    } // #1000 don't catch errors from the callback to avoid double calling it


    if (new_err) {
      new_err.original = err;
      new_err.response = res;
      new_err.status = res.status;
      self.callback(new_err, res);
    } else {
      self.callback(null, res);
    }
  });
}
/**
 * Mixin `Emitter` and `RequestBase`.
 */
// eslint-disable-next-line new-cap


Emitter(Request.prototype); // eslint-disable-next-line new-cap

RequestBase(Request.prototype);
/**
 * Set Content-Type to `type`, mapping values from `request.types`.
 *
 * Examples:
 *
 *      superagent.types.xml = 'application/xml';
 *
 *      request.post('/')
 *        .type('xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 *      request.post('/')
 *        .type('application/xml')
 *        .send(xmlstring)
 *        .end(callback);
 *
 * @param {String} type
 * @return {Request} for chaining
 * @api public
 */

Request.prototype.type = function (type) {
  this.set('Content-Type', request.types[type] || type);
  return this;
};
/**
 * Set Accept to `type`, mapping values from `request.types`.
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
  this.set('Accept', request.types[type] || type);
  return this;
};
/**
 * Set Authorization field value with `user` and `pass`.
 *
 * @param {String} user
 * @param {String} [pass] optional in case of using 'bearer' as type
 * @param {Object} options with 'type' property 'auto', 'basic' or 'bearer' (default 'basic')
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
      type: typeof btoa === 'function' ? 'basic' : 'auto'
    };
  }

  var encoder = function encoder(string) {
    if (typeof btoa === 'function') {
      return btoa(string);
    }

    throw new Error('Cannot use basic auth, btoa is not a function');
  };

  return this._auth(user, pass, options, encoder);
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
  if (typeof val !== 'string') val = serialize(val);
  if (val) this._query.push(val);
  return this;
};
/**
 * Queue the given `file` as an attachment to the specified `field`,
 * with optional `options` (or filename).
 *
 * ``` js
 * request.post('/upload')
 *   .attach('content', new Blob(['<a id="a"><b id="b">hey!</b></a>'], { type: "text/html"}))
 *   .end(callback);
 * ```
 *
 * @param {String} field
 * @param {Blob|File} file
 * @param {String|Object} options
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.attach = function (field, file, options) {
  if (file) {
    if (this._data) {
      throw new Error("superagent can't mix .send() and .attach()");
    }

    this._getFormData().append(field, file, options || file.name);
  }

  return this;
};

Request.prototype._getFormData = function () {
  if (!this._formData) {
    this._formData = new root.FormData();
  }

  return this._formData;
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
  }

  var fn = this._callback;
  this.clearTimeout();

  if (err) {
    if (this._maxRetries) err.retries = this._retries - 1;
    this.emit('error', err);
  }

  fn(err, res);
};
/**
 * Invoke callback with x-domain error.
 *
 * @api private
 */


Request.prototype.crossDomainError = function () {
  var err = new Error('Request has been terminated\nPossible causes: the network is offline, Origin is not allowed by Access-Control-Allow-Origin, the page is being unloaded, etc.');
  err.crossDomain = true;
  err.status = this.status;
  err.method = this.method;
  err.url = this.url;
  this.callback(err);
}; // This only warns, because the request is still likely to work


Request.prototype.agent = function () {
  console.warn('This is not supported in browser version of superagent');
  return this;
};

Request.prototype.ca = Request.prototype.agent;
Request.prototype.buffer = Request.prototype.ca; // This throws, because it can't send/receive data as expected

Request.prototype.write = function () {
  throw new Error('Streaming is not supported in browser version of superagent');
};

Request.prototype.pipe = Request.prototype.write;
/**
 * Check if `obj` is a host object,
 * we don't want to serialize these :)
 *
 * @param {Object} obj host object
 * @return {Boolean} is a host object
 * @api private
 */

Request.prototype._isHost = function (obj) {
  // Native objects stringify to [object File], [object Blob], [object FormData], etc.
  return obj && _typeof(obj) === 'object' && !Array.isArray(obj) && Object.prototype.toString.call(obj) !== '[object Object]';
};
/**
 * Initiate request, invoking callback `fn(res)`
 * with an instanceof `Response`.
 *
 * @param {Function} fn
 * @return {Request} for chaining
 * @api public
 */


Request.prototype.end = function (fn) {
  if (this._endCalled) {
    console.warn('Warning: .end() was called twice. This is not supported in superagent');
  }

  this._endCalled = true; // store callback

  this._callback = fn || noop; // querystring

  this._finalizeQueryString();

  this._end();
};

Request.prototype._setUploadTimeout = function () {
  var self = this; // upload timeout it's wokrs only if deadline timeout is off

  if (this._uploadTimeout && !this._uploadTimeoutTimer) {
    this._uploadTimeoutTimer = setTimeout(function () {
      self._timeoutError('Upload timeout of ', self._uploadTimeout, 'ETIMEDOUT');
    }, this._uploadTimeout);
  }
}; // eslint-disable-next-line complexity


Request.prototype._end = function () {
  if (this._aborted) return this.callback(new Error('The request has been aborted even before .end() was called'));
  var self = this;
  this.xhr = request.getXHR();
  var xhr = this.xhr;
  var data = this._formData || this._data;

  this._setTimeouts(); // state change


  xhr.onreadystatechange = function () {
    var readyState = xhr.readyState;

    if (readyState >= 2 && self._responseTimeoutTimer) {
      clearTimeout(self._responseTimeoutTimer);
    }

    if (readyState !== 4) {
      return;
    } // In IE9, reads to any property (e.g. status) off of an aborted XHR will
    // result in the error "Could not complete the operation due to error c00c023f"


    var status;

    try {
      status = xhr.status;
    } catch (_unused5) {
      status = 0;
    }

    if (!status) {
      if (self.timedout || self._aborted) return;
      return self.crossDomainError();
    }

    self.emit('end');
  }; // progress


  var handleProgress = function handleProgress(direction, e) {
    if (e.total > 0) {
      e.percent = e.loaded / e.total * 100;

      if (e.percent === 100) {
        clearTimeout(self._uploadTimeoutTimer);
      }
    }

    e.direction = direction;
    self.emit('progress', e);
  };

  if (this.hasListeners('progress')) {
    try {
      xhr.addEventListener('progress', handleProgress.bind(null, 'download'));

      if (xhr.upload) {
        xhr.upload.addEventListener('progress', handleProgress.bind(null, 'upload'));
      }
    } catch (_unused6) {// Accessing xhr.upload fails in IE from a web worker, so just pretend it doesn't exist.
      // Reported here:
      // https://connect.microsoft.com/IE/feedback/details/837245/xmlhttprequest-upload-throws-invalid-argument-when-used-from-web-worker-context
    }
  }

  if (xhr.upload) {
    this._setUploadTimeout();
  } // initiate request


  try {
    if (this.username && this.password) {
      xhr.open(this.method, this.url, true, this.username, this.password);
    } else {
      xhr.open(this.method, this.url, true);
    }
  } catch (err) {
    // see #1149
    return this.callback(err);
  } // CORS


  if (this._withCredentials) xhr.withCredentials = true; // body

  if (!this._formData && this.method !== 'GET' && this.method !== 'HEAD' && typeof data !== 'string' && !this._isHost(data)) {
    // serialize stuff
    var contentType = this._header['content-type'];

    var _serialize = this._serializer || request.serialize[contentType ? contentType.split(';')[0] : ''];

    if (!_serialize && isJSON(contentType)) {
      _serialize = request.serialize['application/json'];
    }

    if (_serialize) data = _serialize(data);
  } // set header fields


  for (var field in this.header) {
    if (this.header[field] === null) continue;
    if (Object.prototype.hasOwnProperty.call(this.header, field)) xhr.setRequestHeader(field, this.header[field]);
  }

  if (this._responseType) {
    xhr.responseType = this._responseType;
  } // send stuff


  this.emit('request', this); // IE11 xhr.send(undefined) sends 'undefined' string as POST payload (instead of nothing)
  // We need null here if data is undefined

  xhr.send(typeof data === 'undefined' ? null : data);
};

request.agent = function () {
  return new Agent();
};

['GET', 'POST', 'OPTIONS', 'PATCH', 'PUT', 'DELETE'].forEach(function (method) {
  Agent.prototype[method.toLowerCase()] = function (url, fn) {
    var req = new request.Request(method, url);

    this._setDefaults(req);

    if (fn) {
      req.end(fn);
    }

    return req;
  };
});
Agent.prototype.del = Agent.prototype.delete;
/**
 * GET `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */

request.get = function (url, data, fn) {
  var req = request('GET', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.query(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * HEAD `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.head = function (url, data, fn) {
  var req = request('HEAD', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.query(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * OPTIONS query to `url` with optional callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.options = function (url, data, fn) {
  var req = request('OPTIONS', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * DELETE `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} [data]
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


function del(url, data, fn) {
  var req = request('DELETE', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
}

request.del = del;
request.delete = del;
/**
 * PATCH `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} [data]
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */

request.patch = function (url, data, fn) {
  var req = request('PATCH', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * POST `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed} [data]
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.post = function (url, data, fn) {
  var req = request('POST', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
/**
 * PUT `url` with optional `data` and callback `fn(res)`.
 *
 * @param {String} url
 * @param {Mixed|Function} [data] or fn
 * @param {Function} [fn]
 * @return {Request}
 * @api public
 */


request.put = function (url, data, fn) {
  var req = request('PUT', url);

  if (typeof data === 'function') {
    fn = data;
    data = null;
  }

  if (data) req.send(data);
  if (fn) req.end(fn);
  return req;
};
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIi4uL3NyYy9jbGllbnQuanMiXSwibmFtZXMiOlsicm9vdCIsIndpbmRvdyIsInNlbGYiLCJjb25zb2xlIiwid2FybiIsIkVtaXR0ZXIiLCJyZXF1aXJlIiwic2FmZVN0cmluZ2lmeSIsInFzIiwiUmVxdWVzdEJhc2UiLCJpc09iamVjdCIsIlJlc3BvbnNlQmFzZSIsIkFnZW50Iiwibm9vcCIsIm1vZHVsZSIsImV4cG9ydHMiLCJtZXRob2QiLCJ1cmwiLCJSZXF1ZXN0IiwiZW5kIiwiYXJndW1lbnRzIiwibGVuZ3RoIiwicmVxdWVzdCIsImdldFhIUiIsIlhNTEh0dHBSZXF1ZXN0IiwibG9jYXRpb24iLCJwcm90b2NvbCIsIkFjdGl2ZVhPYmplY3QiLCJFcnJvciIsInRyaW0iLCJzIiwicmVwbGFjZSIsInNlcmlhbGl6ZSIsIm9iaiIsInBhaXJzIiwia2V5IiwiT2JqZWN0IiwicHJvdG90eXBlIiwiaGFzT3duUHJvcGVydHkiLCJjYWxsIiwicHVzaEVuY29kZWRLZXlWYWx1ZVBhaXIiLCJqb2luIiwidmFsIiwidW5kZWZpbmVkIiwicHVzaCIsImVuY29kZVVSSSIsIkFycmF5IiwiaXNBcnJheSIsImZvckVhY2giLCJ2Iiwic3Via2V5IiwiZW5jb2RlVVJJQ29tcG9uZW50Iiwic2VyaWFsaXplT2JqZWN0IiwicGFyc2VTdHJpbmciLCJzdHIiLCJzcGxpdCIsInBhaXIiLCJwb3MiLCJpIiwibGVuIiwiaW5kZXhPZiIsImRlY29kZVVSSUNvbXBvbmVudCIsInNsaWNlIiwidHlwZXMiLCJodG1sIiwianNvbiIsInhtbCIsInVybGVuY29kZWQiLCJmb3JtIiwic3RyaW5naWZ5IiwicGFyc2UiLCJKU09OIiwicGFyc2VIZWFkZXIiLCJsaW5lcyIsImZpZWxkcyIsImluZGV4IiwibGluZSIsImZpZWxkIiwidG9Mb3dlckNhc2UiLCJpc0pTT04iLCJtaW1lIiwidGVzdCIsIlJlc3BvbnNlIiwicmVxIiwieGhyIiwidGV4dCIsInJlc3BvbnNlVHlwZSIsInJlc3BvbnNlVGV4dCIsInN0YXR1c1RleHQiLCJzdGF0dXMiLCJfc2V0U3RhdHVzUHJvcGVydGllcyIsImhlYWRlcnMiLCJnZXRBbGxSZXNwb25zZUhlYWRlcnMiLCJoZWFkZXIiLCJnZXRSZXNwb25zZUhlYWRlciIsIl9zZXRIZWFkZXJQcm9wZXJ0aWVzIiwiX3Jlc3BvbnNlVHlwZSIsImJvZHkiLCJyZXNwb25zZSIsIl9wYXJzZUJvZHkiLCJ0eXBlIiwiX3BhcnNlciIsInRvRXJyb3IiLCJtc2ciLCJlcnIiLCJfcXVlcnkiLCJfaGVhZGVyIiwib24iLCJyZXMiLCJlcnJfIiwib3JpZ2luYWwiLCJyYXdSZXNwb25zZSIsInN0YXR1c0NvZGUiLCJjYWxsYmFjayIsImVtaXQiLCJuZXdfZXJyIiwiX2lzUmVzcG9uc2VPSyIsInNldCIsImFjY2VwdCIsImF1dGgiLCJ1c2VyIiwicGFzcyIsIm9wdGlvbnMiLCJidG9hIiwiZW5jb2RlciIsInN0cmluZyIsIl9hdXRoIiwicXVlcnkiLCJhdHRhY2giLCJmaWxlIiwiX2RhdGEiLCJfZ2V0Rm9ybURhdGEiLCJhcHBlbmQiLCJuYW1lIiwiX2Zvcm1EYXRhIiwiRm9ybURhdGEiLCJfc2hvdWxkUmV0cnkiLCJfcmV0cnkiLCJmbiIsIl9jYWxsYmFjayIsImNsZWFyVGltZW91dCIsIl9tYXhSZXRyaWVzIiwicmV0cmllcyIsIl9yZXRyaWVzIiwiY3Jvc3NEb21haW5FcnJvciIsImNyb3NzRG9tYWluIiwiYWdlbnQiLCJjYSIsImJ1ZmZlciIsIndyaXRlIiwicGlwZSIsIl9pc0hvc3QiLCJ0b1N0cmluZyIsIl9lbmRDYWxsZWQiLCJfZmluYWxpemVRdWVyeVN0cmluZyIsIl9lbmQiLCJfc2V0VXBsb2FkVGltZW91dCIsIl91cGxvYWRUaW1lb3V0IiwiX3VwbG9hZFRpbWVvdXRUaW1lciIsInNldFRpbWVvdXQiLCJfdGltZW91dEVycm9yIiwiX2Fib3J0ZWQiLCJkYXRhIiwiX3NldFRpbWVvdXRzIiwib25yZWFkeXN0YXRlY2hhbmdlIiwicmVhZHlTdGF0ZSIsIl9yZXNwb25zZVRpbWVvdXRUaW1lciIsInRpbWVkb3V0IiwiaGFuZGxlUHJvZ3Jlc3MiLCJkaXJlY3Rpb24iLCJlIiwidG90YWwiLCJwZXJjZW50IiwibG9hZGVkIiwiaGFzTGlzdGVuZXJzIiwiYWRkRXZlbnRMaXN0ZW5lciIsImJpbmQiLCJ1cGxvYWQiLCJ1c2VybmFtZSIsInBhc3N3b3JkIiwib3BlbiIsIl93aXRoQ3JlZGVudGlhbHMiLCJ3aXRoQ3JlZGVudGlhbHMiLCJjb250ZW50VHlwZSIsIl9zZXJpYWxpemVyIiwic2V0UmVxdWVzdEhlYWRlciIsInNlbmQiLCJfc2V0RGVmYXVsdHMiLCJkZWwiLCJkZWxldGUiLCJnZXQiLCJoZWFkIiwicGF0Y2giLCJwb3N0IiwicHV0Il0sIm1hcHBpbmdzIjoiOzs7O0FBQUE7QUFDQTtBQUNBO0FBRUEsSUFBSUEsSUFBSjs7QUFDQSxJQUFJLE9BQU9DLE1BQVAsS0FBa0IsV0FBdEIsRUFBbUM7QUFDakM7QUFDQUQsRUFBQUEsSUFBSSxHQUFHQyxNQUFQO0FBQ0QsQ0FIRCxNQUdPLElBQUksT0FBT0MsSUFBUCxLQUFnQixXQUFwQixFQUFpQztBQUN0QztBQUNBQyxFQUFBQSxPQUFPLENBQUNDLElBQVIsQ0FDRSxxRUFERjtBQUdBSixFQUFBQSxJQUFJLFNBQUo7QUFDRCxDQU5NLE1BTUE7QUFDTDtBQUNBQSxFQUFBQSxJQUFJLEdBQUdFLElBQVA7QUFDRDs7QUFFRCxJQUFNRyxPQUFPLEdBQUdDLE9BQU8sQ0FBQyxtQkFBRCxDQUF2Qjs7QUFDQSxJQUFNQyxhQUFhLEdBQUdELE9BQU8sQ0FBQyxxQkFBRCxDQUE3Qjs7QUFDQSxJQUFNRSxFQUFFLEdBQUdGLE9BQU8sQ0FBQyxJQUFELENBQWxCOztBQUNBLElBQU1HLFdBQVcsR0FBR0gsT0FBTyxDQUFDLGdCQUFELENBQTNCOztBQUNBLElBQU1JLFFBQVEsR0FBR0osT0FBTyxDQUFDLGFBQUQsQ0FBeEI7O0FBQ0EsSUFBTUssWUFBWSxHQUFHTCxPQUFPLENBQUMsaUJBQUQsQ0FBNUI7O0FBQ0EsSUFBTU0sS0FBSyxHQUFHTixP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QixFQUFaLEVBQW1CO0FBQy9CLE1BQU12RCxHQUFHLEdBQUc3RCxPQUFPLENBQUMsS0FBRCxFQUFRTCxHQUFSLENBQW5COztBQUNBLE1BQUksT0FBT2lKLElBQVAsS0FBZ0IsVUFBcEIsRUFBZ0M7QUFDOUJ4QixJQUFBQSxFQUFFLEdBQUd3QixJQUFMO0FBQ0FBLElBQUFBLElBQUksR0FBRyxJQUFQO0FBQ0Q7O0FBRUQsTUFBSUEsSUFBSixFQUFVL0UsR0FBRyxDQUFDdUcsSUFBSixDQUFTeEIsSUFBVDtBQUNWLE1BQUl4QixFQUFKLEVBQVF2RCxHQUFHLENBQUNoRSxHQUFKLENBQVF1SCxFQUFSO0FBQ1IsU0FBT3ZELEdBQVA7QUFDRCxDQVZEIiwic291cmNlc0NvbnRlbnQiOlsiLyoqXG4gKiBSb290IHJlZmVyZW5jZSBmb3IgaWZyYW1lcy5cbiAqL1xuXG5sZXQgcm9vdDtcbmlmICh0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJykge1xuICAvLyBCcm93c2VyIHdpbmRvd1xuICByb290ID0gd2luZG93O1xufSBlbHNlIGlmICh0eXBlb2Ygc2VsZiA9PT0gJ3VuZGVmaW5lZCcpIHtcbiAgLy8gT3RoZXIgZW52aXJvbm1lbnRzXG4gIGNvbnNvbGUud2FybihcbiAgICAnVXNpbmcgYnJvd3Nlci1vbmx5IHZlcnNpb24gb2Ygc3VwZXJhZ2VudCBpbiBub24tYnJvd3NlciBlbnZpcm9ubWVudCdcbiAgKTtcbiAgcm9vdCA9IHRoaXM7XG59IGVsc2Uge1xuICAvLyBXZWIgV29ya2VyXG4gIHJvb3QgPSBzZWxmO1xufVxuXG5jb25zdCBFbWl0dGVyID0gcmVxdWlyZSgnY29tcG9uZW50LWVtaXR0ZXInKTtcbmNvbnN0IHNhZmVTdHJpbmdpZnkgPSByZXF1aXJlKCdmYXN0LXNhZmUtc3RyaW5naWZ5Jyk7XG5jb25zdCBxcyA9IHJlcXVpcmUoJ3FzJyk7XG5jb25zdCBSZXF1ZXN0QmFzZSA9IHJlcXVpcmUoJy4vcmVxdWVzdC1iYXNlJyk7XG5jb25zdCBpc09iamVjdCA9IHJlcXVpcmUoJy4vaXMtb2JqZWN0Jyk7XG5jb25zdCBSZXNwb25zZUJhc2UgPSByZXF1aXJlKCcuL3Jlc3BvbnNlLWJhc2UnKTtcbmNvbnN0IEFnZW50ID0gcmVxdWlyZSgnLi9hZ2VudC1iYXNlJyk7XG5cbi8qKlxuICogTm9vcC5cbiAqL1xuXG5mdW5jdGlvbiBub29wKCkge31cblxuLyoqXG4gKiBFeHBvc2UgYHJlcXVlc3RgLlxuICovXG5cbm1vZHVsZS5leHBvcnRzID0gZnVuY3Rpb24gKG1ldGhvZCwgdXJsKSB7XG4gIC8vIGNhbGxiYWNrXG4gIGlmICh0eXBlb2YgdXJsID09PSAnZnVuY3Rpb24nKSB7XG4gICAgcmV0dXJuIG5ldyBleHBvcnRzLlJlcXVlc3QoJ0dFVCcsIG1ldGhvZCkuZW5kKHVybCk7XG4gIH1cblxuICAvLyB1cmwgZmlyc3RcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDEpIHtcbiAgICByZXR1cm4gbmV3IGV4cG9ydHMuUmVxdWVzdCgnR0VUJywgbWV0aG9kKTtcbiAgfVxuXG4gIHJldHVybiBuZXcgZXhwb3J0cy5SZXF1ZXN0KG1ldGhvZCwgdXJsKTtcbn07XG5cbmV4cG9ydHMgPSBtb2R1bGUuZXhwb3J0cztcblxuY29uc3QgcmVxdWVzdCA9IGV4cG9ydHM7XG5cbmV4cG9ydHMuUmVxdWVzdCA9IFJlcXVlc3Q7XG5cbi8qKlxuICogRGV0ZXJtaW5lIFhIUi5cbiAqL1xuXG5yZXF1ZXN0LmdldFhIUiA9ICgpID0+IHtcbiAgaWYgKFxuICAgIHJvb3QuWE1MSHR0cFJlcXVlc3QgJiZcbiAgICAoIXJvb3QubG9jYXRpb24gfHxcbiAgICAgIHJvb3QubG9jYXRpb24ucHJvdG9jb2wgIT09ICdmaWxlOicgfHxcbiAgICAgICFyb290LkFjdGl2ZVhPYmplY3QpXG4gICkge1xuICAgIHJldHVybiBuZXcgWE1MSHR0cFJlcXVlc3QoKTtcbiAgfVxuXG4gIHRyeSB7XG4gICAgcmV0dXJuIG5ldyBBY3RpdmVYT2JqZWN0KCdNaWNyb3NvZnQuWE1MSFRUUCcpO1xuICB9IGNhdGNoIHt9XG5cbiAgdHJ5IHtcbiAgICByZXR1cm4gbmV3IEFjdGl2ZVhPYmplY3QoJ01zeG1sMi5YTUxIVFRQLjYuMCcpO1xuICB9IGNhdGNoIHt9XG5cbiAgdHJ5IHtcbiAgICByZXR1cm4gbmV3IEFjdGl2ZVhPYmplY3QoJ01zeG1sMi5YTUxIVFRQLjMuMCcpO1xuICB9IGNhdGNoIHt9XG5cbiAgdHJ5IHtcbiAgICByZXR1cm4gbmV3IEFjdGl2ZVhPYmplY3QoJ01zeG1sMi5YTUxIVFRQJyk7XG4gIH0gY2F0Y2gge31cblxuICB0aHJvdyBuZXcgRXJyb3IoJ0Jyb3dzZXItb25seSB2ZXJzaW9uIG9mIHN1cGVyYWdlbnQgY291bGQgbm90IGZpbmQgWEhSJyk7XG59O1xuXG4vKipcbiAqIFJlbW92ZXMgbGVhZGluZyBhbmQgdHJhaWxpbmcgd2hpdGVzcGFjZSwgYWRkZWQgdG8gc3VwcG9ydCBJRS5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gc1xuICogQHJldHVybiB7U3RyaW5nfVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuY29uc3QgdHJpbSA9ICcnLnRyaW0gPyAocykgPT4gcy50cmltKCkgOiAocykgPT4gcy5yZXBsYWNlKC8oXlxccyp8XFxzKiQpL2csICcnKTtcblxuLyoqXG4gKiBTZXJpYWxpemUgdGhlIGdpdmVuIGBvYmpgLlxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fSBvYmpcbiAqIEByZXR1cm4ge1N0cmluZ31cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIHNlcmlhbGl6ZShvYmopIHtcbiAgaWYgKCFpc09iamVjdChvYmopKSByZXR1cm4gb2JqO1xuICBjb25zdCBwYWlycyA9IFtdO1xuICBmb3IgKGNvbnN0IGtleSBpbiBvYmopIHtcbiAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKG9iaiwga2V5KSlcbiAgICAgIHB1c2hFbmNvZGVkS2V5VmFsdWVQYWlyKHBhaXJzLCBrZXksIG9ialtrZXldKTtcbiAgfVxuXG4gIHJldHVybiBwYWlycy5qb2luKCcmJyk7XG59XG5cbi8qKlxuICogSGVscHMgJ3NlcmlhbGl6ZScgd2l0aCBzZXJpYWxpemluZyBhcnJheXMuXG4gKiBNdXRhdGVzIHRoZSBwYWlycyBhcnJheS5cbiAqXG4gKiBAcGFyYW0ge0FycmF5fSBwYWlyc1xuICogQHBhcmFtIHtTdHJpbmd9IGtleVxuICogQHBhcmFtIHtNaXhlZH0gdmFsXG4gKi9cblxuZnVuY3Rpb24gcHVzaEVuY29kZWRLZXlWYWx1ZVBhaXIocGFpcnMsIGtleSwgdmFsKSB7XG4gIGlmICh2YWwgPT09IHVuZGVmaW5lZCkgcmV0dXJuO1xuICBpZiAodmFsID09PSBudWxsKSB7XG4gICAgcGFpcnMucHVzaChlbmNvZGVVUkkoa2V5KSk7XG4gICAgcmV0dXJuO1xuICB9XG5cbiAgaWYgKEFycmF5LmlzQXJyYXkodmFsKSkge1xuICAgIHZhbC5mb3JFYWNoKCh2KSA9PiB7XG4gICAgICBwdXNoRW5jb2RlZEtleVZhbHVlUGFpcihwYWlycywga2V5LCB2KTtcbiAgICB9KTtcbiAgfSBlbHNlIGlmIChpc09iamVjdCh2YWwpKSB7XG4gICAgZm9yIChjb25zdCBzdWJrZXkgaW4gdmFsKSB7XG4gICAgICBpZiAoT2JqZWN0LnByb3RvdHlwZS5oYXNPd25Qcm9wZXJ0eS5jYWxsKHZhbCwgc3Via2V5KSlcbiAgICAgICAgcHVzaEVuY29kZWRLZXlWYWx1ZVBhaXIocGFpcnMsIGAke2tleX1bJHtzdWJrZXl9XWAsIHZhbFtzdWJrZXldKTtcbiAgICB9XG4gIH0gZWxzZSB7XG4gICAgcGFpcnMucHVzaChlbmNvZGVVUkkoa2V5KSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh2YWwpKTtcbiAgfVxufVxuXG4vKipcbiAqIEV4cG9zZSBzZXJpYWxpemF0aW9uIG1ldGhvZC5cbiAqL1xuXG5yZXF1ZXN0LnNlcmlhbGl6ZU9iamVjdCA9IHNlcmlhbGl6ZTtcblxuLyoqXG4gKiBQYXJzZSB0aGUgZ2l2ZW4geC13d3ctZm9ybS11cmxlbmNvZGVkIGBzdHJgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBzdHJcbiAqIEByZXR1cm4ge09iamVjdH1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIHBhcnNlU3RyaW5nKHN0cikge1xuICBjb25zdCBvYmogPSB7fTtcbiAgY29uc3QgcGFpcnMgPSBzdHIuc3BsaXQoJyYnKTtcbiAgbGV0IHBhaXI7XG4gIGxldCBwb3M7XG5cbiAgZm9yIChsZXQgaSA9IDAsIGxlbiA9IHBhaXJzLmxlbmd0aDsgaSA8IGxlbjsgKytpKSB7XG4gICAgcGFpciA9IHBhaXJzW2ldO1xuICAgIHBvcyA9IHBhaXIuaW5kZXhPZignPScpO1xuICAgIGlmIChwb3MgPT09IC0xKSB7XG4gICAgICBvYmpbZGVjb2RlVVJJQ29tcG9uZW50KHBhaXIpXSA9ICcnO1xuICAgIH0gZWxzZSB7XG4gICAgICBvYmpbZGVjb2RlVVJJQ29tcG9uZW50KHBhaXIuc2xpY2UoMCwgcG9zKSldID0gZGVjb2RlVVJJQ29tcG9uZW50KFxuICAgICAgICBwYWlyLnNsaWNlKHBvcyArIDEpXG4gICAgICApO1xuICAgIH1cbiAgfVxuXG4gIHJldHVybiBvYmo7XG59XG5cbi8qKlxuICogRXhwb3NlIHBhcnNlci5cbiAqL1xuXG5yZXF1ZXN0LnBhcnNlU3RyaW5nID0gcGFyc2VTdHJpbmc7XG5cbi8qKlxuICogRGVmYXVsdCBNSU1FIHR5cGUgbWFwLlxuICpcbiAqICAgICBzdXBlcmFnZW50LnR5cGVzLnhtbCA9ICdhcHBsaWNhdGlvbi94bWwnO1xuICpcbiAqL1xuXG5yZXF1ZXN0LnR5cGVzID0ge1xuICBodG1sOiAndGV4dC9odG1sJyxcbiAganNvbjogJ2FwcGxpY2F0aW9uL2pzb24nLFxuICB4bWw6ICd0ZXh0L3htbCcsXG4gIHVybGVuY29kZWQ6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnLFxuICBmb3JtOiAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJyxcbiAgJ2Zvcm0tZGF0YSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXG59O1xuXG4vKipcbiAqIERlZmF1bHQgc2VyaWFsaXphdGlvbiBtYXAuXG4gKlxuICogICAgIHN1cGVyYWdlbnQuc2VyaWFsaXplWydhcHBsaWNhdGlvbi94bWwnXSA9IGZ1bmN0aW9uKG9iail7XG4gKiAgICAgICByZXR1cm4gJ2dlbmVyYXRlZCB4bWwgaGVyZSc7XG4gKiAgICAgfTtcbiAqXG4gKi9cblxucmVxdWVzdC5zZXJpYWxpemUgPSB7XG4gICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnOiBxcy5zdHJpbmdpZnksXG4gICdhcHBsaWNhdGlvbi9qc29uJzogc2FmZVN0cmluZ2lmeVxufTtcblxuLyoqXG4gKiBEZWZhdWx0IHBhcnNlcnMuXG4gKlxuICogICAgIHN1cGVyYWdlbnQucGFyc2VbJ2FwcGxpY2F0aW9uL3htbCddID0gZnVuY3Rpb24oc3RyKXtcbiAqICAgICAgIHJldHVybiB7IG9iamVjdCBwYXJzZWQgZnJvbSBzdHIgfTtcbiAqICAgICB9O1xuICpcbiAqL1xuXG5yZXF1ZXN0LnBhcnNlID0ge1xuICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJzogcGFyc2VTdHJpbmcsXG4gICdhcHBsaWNhdGlvbi9qc29uJzogSlNPTi5wYXJzZVxufTtcblxuLyoqXG4gKiBQYXJzZSB0aGUgZ2l2ZW4gaGVhZGVyIGBzdHJgIGludG9cbiAqIGFuIG9iamVjdCBjb250YWluaW5nIHRoZSBtYXBwZWQgZmllbGRzLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBzdHJcbiAqIEByZXR1cm4ge09iamVjdH1cbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIHBhcnNlSGVhZGVyKHN0cikge1xuICBjb25zdCBsaW5lcyA9IHN0ci5zcGxpdCgvXFxyP1xcbi8pO1xuICBjb25zdCBmaWVsZHMgPSB7fTtcbiAgbGV0IGluZGV4O1xuICBsZXQgbGluZTtcbiAgbGV0IGZpZWxkO1xuICBsZXQgdmFsO1xuXG4gIGZvciAobGV0IGkgPSAwLCBsZW4gPSBsaW5lcy5sZW5ndGg7IGkgPCBsZW47ICsraSkge1xuICAgIGxpbmUgPSBsaW5lc1tpXTtcbiAgICBpbmRleCA9IGxpbmUuaW5kZXhPZignOicpO1xuICAgIGlmIChpbmRleCA9PT0gLTEpIHtcbiAgICAgIC8vIGNvdWxkIGJlIGVtcHR5IGxpbmUsIGp1c3Qgc2tpcCBpdFxuICAgICAgY29udGludWU7XG4gICAgfVxuXG4gICAgZmllbGQgPSBsaW5lLnNsaWNlKDAsIGluZGV4KS50b0xvd2VyQ2FzZSgpO1xuICAgIHZhbCA9IHRyaW0obGluZS5zbGljZShpbmRleCArIDEpKTtcbiAgICBmaWVsZHNbZmllbGRdID0gdmFsO1xuICB9XG5cbiAgcmV0dXJuIGZpZWxkcztcbn1cblxuLyoqXG4gKiBDaGVjayBpZiBgbWltZWAgaXMganNvbiBvciBoYXMgK2pzb24gc3RydWN0dXJlZCBzeW50YXggc3VmZml4LlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBtaW1lXG4gKiBAcmV0dXJuIHtCb29sZWFufVxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuZnVuY3Rpb24gaXNKU09OKG1pbWUpIHtcbiAgLy8gc2hvdWxkIG1hdGNoIC9qc29uIG9yICtqc29uXG4gIC8vIGJ1dCBub3QgL2pzb24tc2VxXG4gIHJldHVybiAvWy8rXWpzb24oJHxbXi1cXHddKS9pLnRlc3QobWltZSk7XG59XG5cbi8qKlxuICogSW5pdGlhbGl6ZSBhIG5ldyBgUmVzcG9uc2VgIHdpdGggdGhlIGdpdmVuIGB4aHJgLlxuICpcbiAqICAtIHNldCBmbGFncyAoLm9rLCAuZXJyb3IsIGV0YylcbiAqICAtIHBhcnNlIGhlYWRlclxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICBBbGlhc2luZyBgc3VwZXJhZ2VudGAgYXMgYHJlcXVlc3RgIGlzIG5pY2U6XG4gKlxuICogICAgICByZXF1ZXN0ID0gc3VwZXJhZ2VudDtcbiAqXG4gKiAgV2UgY2FuIHVzZSB0aGUgcHJvbWlzZS1saWtlIEFQSSwgb3IgcGFzcyBjYWxsYmFja3M6XG4gKlxuICogICAgICByZXF1ZXN0LmdldCgnLycpLmVuZChmdW5jdGlvbihyZXMpe30pO1xuICogICAgICByZXF1ZXN0LmdldCgnLycsIGZ1bmN0aW9uKHJlcyl7fSk7XG4gKlxuICogIFNlbmRpbmcgZGF0YSBjYW4gYmUgY2hhaW5lZDpcbiAqXG4gKiAgICAgIHJlcXVlc3RcbiAqICAgICAgICAucG9zdCgnL3VzZXInKVxuICogICAgICAgIC5zZW5kKHsgbmFtZTogJ3RqJyB9KVxuICogICAgICAgIC5lbmQoZnVuY3Rpb24ocmVzKXt9KTtcbiAqXG4gKiAgT3IgcGFzc2VkIHRvIGAuc2VuZCgpYDpcbiAqXG4gKiAgICAgIHJlcXVlc3RcbiAqICAgICAgICAucG9zdCgnL3VzZXInKVxuICogICAgICAgIC5zZW5kKHsgbmFtZTogJ3RqJyB9LCBmdW5jdGlvbihyZXMpe30pO1xuICpcbiAqICBPciBwYXNzZWQgdG8gYC5wb3N0KClgOlxuICpcbiAqICAgICAgcmVxdWVzdFxuICogICAgICAgIC5wb3N0KCcvdXNlcicsIHsgbmFtZTogJ3RqJyB9KVxuICogICAgICAgIC5lbmQoZnVuY3Rpb24ocmVzKXt9KTtcbiAqXG4gKiBPciBmdXJ0aGVyIHJlZHVjZWQgdG8gYSBzaW5nbGUgY2FsbCBmb3Igc2ltcGxlIGNhc2VzOlxuICpcbiAqICAgICAgcmVxdWVzdFxuICogICAgICAgIC5wb3N0KCcvdXNlcicsIHsgbmFtZTogJ3RqJyB9LCBmdW5jdGlvbihyZXMpe30pO1xuICpcbiAqIEBwYXJhbSB7WE1MSFRUUFJlcXVlc3R9IHhoclxuICogQHBhcmFtIHtPYmplY3R9IG9wdGlvbnNcbiAqIEBhcGkgcHJpdmF0ZVxuICovXG5cbmZ1bmN0aW9uIFJlc3BvbnNlKHJlcSkge1xuICB0aGlzLnJlcSA9IHJlcTtcbiAgdGhpcy54aHIgPSB0aGlzLnJlcS54aHI7XG4gIC8vIHJlc3BvbnNlVGV4dCBpcyBhY2Nlc3NpYmxlIG9ubHkgaWYgcmVzcG9uc2VUeXBlIGlzICcnIG9yICd0ZXh0JyBhbmQgb24gb2xkZXIgYnJvd3NlcnNcbiAgdGhpcy50ZXh0ID1cbiAgICAodGhpcy5yZXEubWV0aG9kICE9PSAnSEVBRCcgJiZcbiAgICAgICh0aGlzLnhoci5yZXNwb25zZVR5cGUgPT09ICcnIHx8IHRoaXMueGhyLnJlc3BvbnNlVHlwZSA9PT0gJ3RleHQnKSkgfHxcbiAgICB0eXBlb2YgdGhpcy54aHIucmVzcG9uc2VUeXBlID09PSAndW5kZWZpbmVkJ1xuICAgICAgPyB0aGlzLnhoci5yZXNwb25zZVRleHRcbiAgICAgIDogbnVsbDtcbiAgdGhpcy5zdGF0dXNUZXh0ID0gdGhpcy5yZXEueGhyLnN0YXR1c1RleHQ7XG4gIGxldCB7IHN0YXR1cyB9ID0gdGhpcy54aHI7XG4gIC8vIGhhbmRsZSBJRTkgYnVnOiBodHRwOi8vc3RhY2tvdmVyZmxvdy5jb20vcXVlc3Rpb25zLzEwMDQ2OTcyL21zaWUtcmV0dXJucy1zdGF0dXMtY29kZS1vZi0xMjIzLWZvci1hamF4LXJlcXVlc3RcbiAgaWYgKHN0YXR1cyA9PT0gMTIyMykge1xuICAgIHN0YXR1cyA9IDIwNDtcbiAgfVxuXG4gIHRoaXMuX3NldFN0YXR1c1Byb3BlcnRpZXMoc3RhdHVzKTtcbiAgdGhpcy5oZWFkZXJzID0gcGFyc2VIZWFkZXIodGhpcy54aHIuZ2V0QWxsUmVzcG9uc2VIZWFkZXJzKCkpO1xuICB0aGlzLmhlYWRlciA9IHRoaXMuaGVhZGVycztcbiAgLy8gZ2V0QWxsUmVzcG9uc2VIZWFkZXJzIHNvbWV0aW1lcyBmYWxzZWx5IHJldHVybnMgXCJcIiBmb3IgQ09SUyByZXF1ZXN0cywgYnV0XG4gIC8vIGdldFJlc3BvbnNlSGVhZGVyIHN0aWxsIHdvcmtzLiBzbyB3ZSBnZXQgY29udGVudC10eXBlIGV2ZW4gaWYgZ2V0dGluZ1xuICAvLyBvdGhlciBoZWFkZXJzIGZhaWxzLlxuICB0aGlzLmhlYWRlclsnY29udGVudC10eXBlJ10gPSB0aGlzLnhoci5nZXRSZXNwb25zZUhlYWRlcignY29udGVudC10eXBlJyk7XG4gIHRoaXMuX3NldEhlYWRlclByb3BlcnRpZXModGhpcy5oZWFkZXIpO1xuXG4gIGlmICh0aGlzLnRleHQgPT09IG51bGwgJiYgcmVxLl9yZXNwb25zZVR5cGUpIHtcbiAgICB0aGlzLmJvZHkgPSB0aGlzLnhoci5yZXNwb25zZTtcbiAgfSBlbHNlIHtcbiAgICB0aGlzLmJvZHkgPVxuICAgICAgdGhpcy5yZXEubWV0aG9kID09PSAnSEVBRCdcbiAgICAgICAgPyBudWxsXG4gICAgICAgIDogdGhpcy5fcGFyc2VCb2R5KHRoaXMudGV4dCA/IHRoaXMudGV4dCA6IHRoaXMueGhyLnJlc3BvbnNlKTtcbiAgfVxufVxuXG4vLyBlc2xpbnQtZGlzYWJsZS1uZXh0LWxpbmUgbmV3LWNhcFxuUmVzcG9uc2VCYXNlKFJlc3BvbnNlLnByb3RvdHlwZSk7XG5cbi8qKlxuICogUGFyc2UgdGhlIGdpdmVuIGJvZHkgYHN0cmAuXG4gKlxuICogVXNlZCBmb3IgYXV0by1wYXJzaW5nIG9mIGJvZGllcy4gUGFyc2Vyc1xuICogYXJlIGRlZmluZWQgb24gdGhlIGBzdXBlcmFnZW50LnBhcnNlYCBvYmplY3QuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHN0clxuICogQHJldHVybiB7TWl4ZWR9XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXNwb25zZS5wcm90b3R5cGUuX3BhcnNlQm9keSA9IGZ1bmN0aW9uIChzdHIpIHtcbiAgbGV0IHBhcnNlID0gcmVxdWVzdC5wYXJzZVt0aGlzLnR5cGVdO1xuICBpZiAodGhpcy5yZXEuX3BhcnNlcikge1xuICAgIHJldHVybiB0aGlzLnJlcS5fcGFyc2VyKHRoaXMsIHN0cik7XG4gIH1cblxuICBpZiAoIXBhcnNlICYmIGlzSlNPTih0aGlzLnR5cGUpKSB7XG4gICAgcGFyc2UgPSByZXF1ZXN0LnBhcnNlWydhcHBsaWNhdGlvbi9qc29uJ107XG4gIH1cblxuICByZXR1cm4gcGFyc2UgJiYgc3RyICYmIChzdHIubGVuZ3RoID4gMCB8fCBzdHIgaW5zdGFuY2VvZiBPYmplY3QpXG4gICAgPyBwYXJzZShzdHIpXG4gICAgOiBudWxsO1xufTtcblxuLyoqXG4gKiBSZXR1cm4gYW4gYEVycm9yYCByZXByZXNlbnRhdGl2ZSBvZiB0aGlzIHJlc3BvbnNlLlxuICpcbiAqIEByZXR1cm4ge0Vycm9yfVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXNwb25zZS5wcm90b3R5cGUudG9FcnJvciA9IGZ1bmN0aW9uICgpIHtcbiAgY29uc3QgeyByZXEgfSA9IHRoaXM7XG4gIGNvbnN0IHsgbWV0aG9kIH0gPSByZXE7XG4gIGNvbnN0IHsgdXJsIH0gPSByZXE7XG5cbiAgY29uc3QgbXNnID0gYGNhbm5vdCAke21ldGhvZH0gJHt1cmx9ICgke3RoaXMuc3RhdHVzfSlgO1xuICBjb25zdCBlcnIgPSBuZXcgRXJyb3IobXNnKTtcbiAgZXJyLnN0YXR1cyA9IHRoaXMuc3RhdHVzO1xuICBlcnIubWV0aG9kID0gbWV0aG9kO1xuICBlcnIudXJsID0gdXJsO1xuXG4gIHJldHVybiBlcnI7XG59O1xuXG4vKipcbiAqIEV4cG9zZSBgUmVzcG9uc2VgLlxuICovXG5cbnJlcXVlc3QuUmVzcG9uc2UgPSBSZXNwb25zZTtcblxuLyoqXG4gKiBJbml0aWFsaXplIGEgbmV3IGBSZXF1ZXN0YCB3aXRoIHRoZSBnaXZlbiBgbWV0aG9kYCBhbmQgYHVybGAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IG1ldGhvZFxuICogQHBhcmFtIHtTdHJpbmd9IHVybFxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5mdW5jdGlvbiBSZXF1ZXN0KG1ldGhvZCwgdXJsKSB7XG4gIGNvbnN0IHNlbGYgPSB0aGlzO1xuICB0aGlzLl9xdWVyeSA9IHRoaXMuX3F1ZXJ5IHx8IFtdO1xuICB0aGlzLm1ldGhvZCA9IG1ldGhvZDtcbiAgdGhpcy51cmwgPSB1cmw7XG4gIHRoaXMuaGVhZGVyID0ge307IC8vIHByZXNlcnZlcyBoZWFkZXIgbmFtZSBjYXNlXG4gIHRoaXMuX2hlYWRlciA9IHt9OyAvLyBjb2VyY2VzIGhlYWRlciBuYW1lcyB0byBsb3dlcmNhc2VcbiAgdGhpcy5vbignZW5kJywgKCkgPT4ge1xuICAgIGxldCBlcnIgPSBudWxsO1xuICAgIGxldCByZXMgPSBudWxsO1xuXG4gICAgdHJ5IHtcbiAgICAgIHJlcyA9IG5ldyBSZXNwb25zZShzZWxmKTtcbiAgICB9IGNhdGNoIChlcnJfKSB7XG4gICAgICBlcnIgPSBuZXcgRXJyb3IoJ1BhcnNlciBpcyB1bmFibGUgdG8gcGFyc2UgdGhlIHJlc3BvbnNlJyk7XG4gICAgICBlcnIucGFyc2UgPSB0cnVlO1xuICAgICAgZXJyLm9yaWdpbmFsID0gZXJyXztcbiAgICAgIC8vIGlzc3VlICM2NzU6IHJldHVybiB0aGUgcmF3IHJlc3BvbnNlIGlmIHRoZSByZXNwb25zZSBwYXJzaW5nIGZhaWxzXG4gICAgICBpZiAoc2VsZi54aHIpIHtcbiAgICAgICAgLy8gaWU5IGRvZXNuJ3QgaGF2ZSAncmVzcG9uc2UnIHByb3BlcnR5XG4gICAgICAgIGVyci5yYXdSZXNwb25zZSA9XG4gICAgICAgICAgdHlwZW9mIHNlbGYueGhyLnJlc3BvbnNlVHlwZSA9PT0gJ3VuZGVmaW5lZCdcbiAgICAgICAgICAgID8gc2VsZi54aHIucmVzcG9uc2VUZXh0XG4gICAgICAgICAgICA6IHNlbGYueGhyLnJlc3BvbnNlO1xuICAgICAgICAvLyBpc3N1ZSAjODc2OiByZXR1cm4gdGhlIGh0dHAgc3RhdHVzIGNvZGUgaWYgdGhlIHJlc3BvbnNlIHBhcnNpbmcgZmFpbHNcbiAgICAgICAgZXJyLnN0YXR1cyA9IHNlbGYueGhyLnN0YXR1cyA/IHNlbGYueGhyLnN0YXR1cyA6IG51bGw7XG4gICAgICAgIGVyci5zdGF0dXNDb2RlID0gZXJyLnN0YXR1czsgLy8gYmFja3dhcmRzLWNvbXBhdCBvbmx5XG4gICAgICB9IGVsc2Uge1xuICAgICAgICBlcnIucmF3UmVzcG9uc2UgPSBudWxsO1xuICAgICAgICBlcnIuc3RhdHVzID0gbnVsbDtcbiAgICAgIH1cblxuICAgICAgcmV0dXJuIHNlbGYuY2FsbGJhY2soZXJyKTtcbiAgICB9XG5cbiAgICBzZWxmLmVtaXQoJ3Jlc3BvbnNlJywgcmVzKTtcblxuICAgIGxldCBuZXdfZXJyO1xuICAgIHRyeSB7XG4gICAgICBpZiAoIXNlbGYuX2lzUmVzcG9uc2VPSyhyZXMpKSB7XG4gICAgICAgIG5ld19lcnIgPSBuZXcgRXJyb3IoXG4gICAgICAgICAgcmVzLnN0YXR1c1RleHQgfHwgcmVzLnRleHQgfHwgJ1Vuc3VjY2Vzc2Z1bCBIVFRQIHJlc3BvbnNlJ1xuICAgICAgICApO1xuICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycl8pIHtcbiAgICAgIG5ld19lcnIgPSBlcnJfOyAvLyBvaygpIGNhbGxiYWNrIGNhbiB0aHJvd1xuICAgIH1cblxuICAgIC8vICMxMDAwIGRvbid0IGNhdGNoIGVycm9ycyBmcm9tIHRoZSBjYWxsYmFjayB0byBhdm9pZCBkb3VibGUgY2FsbGluZyBpdFxuICAgIGlmIChuZXdfZXJyKSB7XG4gICAgICBuZXdfZXJyLm9yaWdpbmFsID0gZXJyO1xuICAgICAgbmV3X2Vyci5yZXNwb25zZSA9IHJlcztcbiAgICAgIG5ld19lcnIuc3RhdHVzID0gcmVzLnN0YXR1cztcbiAgICAgIHNlbGYuY2FsbGJhY2sobmV3X2VyciwgcmVzKTtcbiAgICB9IGVsc2Uge1xuICAgICAgc2VsZi5jYWxsYmFjayhudWxsLCByZXMpO1xuICAgIH1cbiAgfSk7XG59XG5cbi8qKlxuICogTWl4aW4gYEVtaXR0ZXJgIGFuZCBgUmVxdWVzdEJhc2VgLlxuICovXG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuZXctY2FwXG5FbWl0dGVyKFJlcXVlc3QucHJvdG90eXBlKTtcbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBuZXctY2FwXG5SZXF1ZXN0QmFzZShSZXF1ZXN0LnByb3RvdHlwZSk7XG5cbi8qKlxuICogU2V0IENvbnRlbnQtVHlwZSB0byBgdHlwZWAsIG1hcHBpbmcgdmFsdWVzIGZyb20gYHJlcXVlc3QudHlwZXNgLlxuICpcbiAqIEV4YW1wbGVzOlxuICpcbiAqICAgICAgc3VwZXJhZ2VudC50eXBlcy54bWwgPSAnYXBwbGljYXRpb24veG1sJztcbiAqXG4gKiAgICAgIHJlcXVlc3QucG9zdCgnLycpXG4gKiAgICAgICAgLnR5cGUoJ3htbCcpXG4gKiAgICAgICAgLnNlbmQoeG1sc3RyaW5nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqICAgICAgcmVxdWVzdC5wb3N0KCcvJylcbiAqICAgICAgICAudHlwZSgnYXBwbGljYXRpb24veG1sJylcbiAqICAgICAgICAuc2VuZCh4bWxzdHJpbmcpXG4gKiAgICAgICAgLmVuZChjYWxsYmFjayk7XG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHR5cGVcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS50eXBlID0gZnVuY3Rpb24gKHR5cGUpIHtcbiAgdGhpcy5zZXQoJ0NvbnRlbnQtVHlwZScsIHJlcXVlc3QudHlwZXNbdHlwZV0gfHwgdHlwZSk7XG4gIHJldHVybiB0aGlzO1xufTtcblxuLyoqXG4gKiBTZXQgQWNjZXB0IHRvIGB0eXBlYCwgbWFwcGluZyB2YWx1ZXMgZnJvbSBgcmVxdWVzdC50eXBlc2AuXG4gKlxuICogRXhhbXBsZXM6XG4gKlxuICogICAgICBzdXBlcmFnZW50LnR5cGVzLmpzb24gPSAnYXBwbGljYXRpb24vanNvbic7XG4gKlxuICogICAgICByZXF1ZXN0LmdldCgnL2FnZW50JylcbiAqICAgICAgICAuYWNjZXB0KCdqc29uJylcbiAqICAgICAgICAuZW5kKGNhbGxiYWNrKTtcbiAqXG4gKiAgICAgIHJlcXVlc3QuZ2V0KCcvYWdlbnQnKVxuICogICAgICAgIC5hY2NlcHQoJ2FwcGxpY2F0aW9uL2pzb24nKVxuICogICAgICAgIC5lbmQoY2FsbGJhY2spO1xuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBhY2NlcHRcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hY2NlcHQgPSBmdW5jdGlvbiAodHlwZSkge1xuICB0aGlzLnNldCgnQWNjZXB0JywgcmVxdWVzdC50eXBlc1t0eXBlXSB8fCB0eXBlKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFNldCBBdXRob3JpemF0aW9uIGZpZWxkIHZhbHVlIHdpdGggYHVzZXJgIGFuZCBgcGFzc2AuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVzZXJcbiAqIEBwYXJhbSB7U3RyaW5nfSBbcGFzc10gb3B0aW9uYWwgaW4gY2FzZSBvZiB1c2luZyAnYmVhcmVyJyBhcyB0eXBlXG4gKiBAcGFyYW0ge09iamVjdH0gb3B0aW9ucyB3aXRoICd0eXBlJyBwcm9wZXJ0eSAnYXV0bycsICdiYXNpYycgb3IgJ2JlYXJlcicgKGRlZmF1bHQgJ2Jhc2ljJylcbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5hdXRoID0gZnVuY3Rpb24gKHVzZXIsIHBhc3MsIG9wdGlvbnMpIHtcbiAgaWYgKGFyZ3VtZW50cy5sZW5ndGggPT09IDEpIHBhc3MgPSAnJztcbiAgaWYgKHR5cGVvZiBwYXNzID09PSAnb2JqZWN0JyAmJiBwYXNzICE9PSBudWxsKSB7XG4gICAgLy8gcGFzcyBpcyBvcHRpb25hbCBhbmQgY2FuIGJlIHJlcGxhY2VkIHdpdGggb3B0aW9uc1xuICAgIG9wdGlvbnMgPSBwYXNzO1xuICAgIHBhc3MgPSAnJztcbiAgfVxuXG4gIGlmICghb3B0aW9ucykge1xuICAgIG9wdGlvbnMgPSB7XG4gICAgICB0eXBlOiB0eXBlb2YgYnRvYSA9PT0gJ2Z1bmN0aW9uJyA/ICdiYXNpYycgOiAnYXV0bydcbiAgICB9O1xuICB9XG5cbiAgY29uc3QgZW5jb2RlciA9IChzdHJpbmcpID0+IHtcbiAgICBpZiAodHlwZW9mIGJ0b2EgPT09ICdmdW5jdGlvbicpIHtcbiAgICAgIHJldHVybiBidG9hKHN0cmluZyk7XG4gICAgfVxuXG4gICAgdGhyb3cgbmV3IEVycm9yKCdDYW5ub3QgdXNlIGJhc2ljIGF1dGgsIGJ0b2EgaXMgbm90IGEgZnVuY3Rpb24nKTtcbiAgfTtcblxuICByZXR1cm4gdGhpcy5fYXV0aCh1c2VyLCBwYXNzLCBvcHRpb25zLCBlbmNvZGVyKTtcbn07XG5cbi8qKlxuICogQWRkIHF1ZXJ5LXN0cmluZyBgdmFsYC5cbiAqXG4gKiBFeGFtcGxlczpcbiAqXG4gKiAgIHJlcXVlc3QuZ2V0KCcvc2hvZXMnKVxuICogICAgIC5xdWVyeSgnc2l6ZT0xMCcpXG4gKiAgICAgLnF1ZXJ5KHsgY29sb3I6ICdibHVlJyB9KVxuICpcbiAqIEBwYXJhbSB7T2JqZWN0fFN0cmluZ30gdmFsXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fSBmb3IgY2hhaW5pbmdcbiAqIEBhcGkgcHVibGljXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUucXVlcnkgPSBmdW5jdGlvbiAodmFsKSB7XG4gIGlmICh0eXBlb2YgdmFsICE9PSAnc3RyaW5nJykgdmFsID0gc2VyaWFsaXplKHZhbCk7XG4gIGlmICh2YWwpIHRoaXMuX3F1ZXJ5LnB1c2godmFsKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG4vKipcbiAqIFF1ZXVlIHRoZSBnaXZlbiBgZmlsZWAgYXMgYW4gYXR0YWNobWVudCB0byB0aGUgc3BlY2lmaWVkIGBmaWVsZGAsXG4gKiB3aXRoIG9wdGlvbmFsIGBvcHRpb25zYCAob3IgZmlsZW5hbWUpLlxuICpcbiAqIGBgYCBqc1xuICogcmVxdWVzdC5wb3N0KCcvdXBsb2FkJylcbiAqICAgLmF0dGFjaCgnY29udGVudCcsIG5ldyBCbG9iKFsnPGEgaWQ9XCJhXCI+PGIgaWQ9XCJiXCI+aGV5ITwvYj48L2E+J10sIHsgdHlwZTogXCJ0ZXh0L2h0bWxcIn0pKVxuICogICAuZW5kKGNhbGxiYWNrKTtcbiAqIGBgYFxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSBmaWVsZFxuICogQHBhcmFtIHtCbG9ifEZpbGV9IGZpbGVcbiAqIEBwYXJhbSB7U3RyaW5nfE9iamVjdH0gb3B0aW9uc1xuICogQHJldHVybiB7UmVxdWVzdH0gZm9yIGNoYWluaW5nXG4gKiBAYXBpIHB1YmxpY1xuICovXG5cblJlcXVlc3QucHJvdG90eXBlLmF0dGFjaCA9IGZ1bmN0aW9uIChmaWVsZCwgZmlsZSwgb3B0aW9ucykge1xuICBpZiAoZmlsZSkge1xuICAgIGlmICh0aGlzLl9kYXRhKSB7XG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXCJzdXBlcmFnZW50IGNhbid0IG1peCAuc2VuZCgpIGFuZCAuYXR0YWNoKClcIik7XG4gICAgfVxuXG4gICAgdGhpcy5fZ2V0Rm9ybURhdGEoKS5hcHBlbmQoZmllbGQsIGZpbGUsIG9wdGlvbnMgfHwgZmlsZS5uYW1lKTtcbiAgfVxuXG4gIHJldHVybiB0aGlzO1xufTtcblxuUmVxdWVzdC5wcm90b3R5cGUuX2dldEZvcm1EYXRhID0gZnVuY3Rpb24gKCkge1xuICBpZiAoIXRoaXMuX2Zvcm1EYXRhKSB7XG4gICAgdGhpcy5fZm9ybURhdGEgPSBuZXcgcm9vdC5Gb3JtRGF0YSgpO1xuICB9XG5cbiAgcmV0dXJuIHRoaXMuX2Zvcm1EYXRhO1xufTtcblxuLyoqXG4gKiBJbnZva2UgdGhlIGNhbGxiYWNrIHdpdGggYGVycmAgYW5kIGByZXNgXG4gKiBhbmQgaGFuZGxlIGFyaXR5IGNoZWNrLlxuICpcbiAqIEBwYXJhbSB7RXJyb3J9IGVyclxuICogQHBhcmFtIHtSZXNwb25zZX0gcmVzXG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYWxsYmFjayA9IGZ1bmN0aW9uIChlcnIsIHJlcykge1xuICBpZiAodGhpcy5fc2hvdWxkUmV0cnkoZXJyLCByZXMpKSB7XG4gICAgcmV0dXJuIHRoaXMuX3JldHJ5KCk7XG4gIH1cblxuICBjb25zdCBmbiA9IHRoaXMuX2NhbGxiYWNrO1xuICB0aGlzLmNsZWFyVGltZW91dCgpO1xuXG4gIGlmIChlcnIpIHtcbiAgICBpZiAodGhpcy5fbWF4UmV0cmllcykgZXJyLnJldHJpZXMgPSB0aGlzLl9yZXRyaWVzIC0gMTtcbiAgICB0aGlzLmVtaXQoJ2Vycm9yJywgZXJyKTtcbiAgfVxuXG4gIGZuKGVyciwgcmVzKTtcbn07XG5cbi8qKlxuICogSW52b2tlIGNhbGxiYWNrIHdpdGggeC1kb21haW4gZXJyb3IuXG4gKlxuICogQGFwaSBwcml2YXRlXG4gKi9cblxuUmVxdWVzdC5wcm90b3R5cGUuY3Jvc3NEb21haW5FcnJvciA9IGZ1bmN0aW9uICgpIHtcbiAgY29uc3QgZXJyID0gbmV3IEVycm9yKFxuICAgICdSZXF1ZXN0IGhhcyBiZWVuIHRlcm1pbmF0ZWRcXG5Qb3NzaWJsZSBjYXVzZXM6IHRoZSBuZXR3b3JrIGlzIG9mZmxpbmUsIE9yaWdpbiBpcyBub3QgYWxsb3dlZCBieSBBY2Nlc3MtQ29udHJvbC1BbGxvdy1PcmlnaW4sIHRoZSBwYWdlIGlzIGJlaW5nIHVubG9hZGVkLCBldGMuJ1xuICApO1xuICBlcnIuY3Jvc3NEb21haW4gPSB0cnVlO1xuXG4gIGVyci5zdGF0dXMgPSB0aGlzLnN0YXR1cztcbiAgZXJyLm1ldGhvZCA9IHRoaXMubWV0aG9kO1xuICBlcnIudXJsID0gdGhpcy51cmw7XG5cbiAgdGhpcy5jYWxsYmFjayhlcnIpO1xufTtcblxuLy8gVGhpcyBvbmx5IHdhcm5zLCBiZWNhdXNlIHRoZSByZXF1ZXN0IGlzIHN0aWxsIGxpa2VseSB0byB3b3JrXG5SZXF1ZXN0LnByb3RvdHlwZS5hZ2VudCA9IGZ1bmN0aW9uICgpIHtcbiAgY29uc29sZS53YXJuKCdUaGlzIGlzIG5vdCBzdXBwb3J0ZWQgaW4gYnJvd3NlciB2ZXJzaW9uIG9mIHN1cGVyYWdlbnQnKTtcbiAgcmV0dXJuIHRoaXM7XG59O1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5jYSA9IFJlcXVlc3QucHJvdG90eXBlLmFnZW50O1xuUmVxdWVzdC5wcm90b3R5cGUuYnVmZmVyID0gUmVxdWVzdC5wcm90b3R5cGUuY2E7XG5cbi8vIFRoaXMgdGhyb3dzLCBiZWNhdXNlIGl0IGNhbid0IHNlbmQvcmVjZWl2ZSBkYXRhIGFzIGV4cGVjdGVkXG5SZXF1ZXN0LnByb3RvdHlwZS53cml0ZSA9ICgpID0+IHtcbiAgdGhyb3cgbmV3IEVycm9yKFxuICAgICdTdHJlYW1pbmcgaXMgbm90IHN1cHBvcnRlZCBpbiBicm93c2VyIHZlcnNpb24gb2Ygc3VwZXJhZ2VudCdcbiAgKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLnBpcGUgPSBSZXF1ZXN0LnByb3RvdHlwZS53cml0ZTtcblxuLyoqXG4gKiBDaGVjayBpZiBgb2JqYCBpcyBhIGhvc3Qgb2JqZWN0LFxuICogd2UgZG9uJ3Qgd2FudCB0byBzZXJpYWxpemUgdGhlc2UgOilcbiAqXG4gKiBAcGFyYW0ge09iamVjdH0gb2JqIGhvc3Qgb2JqZWN0XG4gKiBAcmV0dXJuIHtCb29sZWFufSBpcyBhIGhvc3Qgb2JqZWN0XG4gKiBAYXBpIHByaXZhdGVcbiAqL1xuUmVxdWVzdC5wcm90b3R5cGUuX2lzSG9zdCA9IGZ1bmN0aW9uIChvYmopIHtcbiAgLy8gTmF0aXZlIG9iamVjdHMgc3RyaW5naWZ5IHRvIFtvYmplY3QgRmlsZV0sIFtvYmplY3QgQmxvYl0sIFtvYmplY3QgRm9ybURhdGFdLCBldGMuXG4gIHJldHVybiAoXG4gICAgb2JqICYmXG4gICAgdHlwZW9mIG9iaiA9PT0gJ29iamVjdCcgJiZcbiAgICAhQXJyYXkuaXNBcnJheShvYmopICYmXG4gICAgT2JqZWN0LnByb3RvdHlwZS50b1N0cmluZy5jYWxsKG9iaikgIT09ICdbb2JqZWN0IE9iamVjdF0nXG4gICk7XG59O1xuXG4vKipcbiAqIEluaXRpYXRlIHJlcXVlc3QsIGludm9raW5nIGNhbGxiYWNrIGBmbihyZXMpYFxuICogd2l0aCBhbiBpbnN0YW5jZW9mIGBSZXNwb25zZWAuXG4gKlxuICogQHBhcmFtIHtGdW5jdGlvbn0gZm5cbiAqIEByZXR1cm4ge1JlcXVlc3R9IGZvciBjaGFpbmluZ1xuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5SZXF1ZXN0LnByb3RvdHlwZS5lbmQgPSBmdW5jdGlvbiAoZm4pIHtcbiAgaWYgKHRoaXMuX2VuZENhbGxlZCkge1xuICAgIGNvbnNvbGUud2FybihcbiAgICAgICdXYXJuaW5nOiAuZW5kKCkgd2FzIGNhbGxlZCB0d2ljZS4gVGhpcyBpcyBub3Qgc3VwcG9ydGVkIGluIHN1cGVyYWdlbnQnXG4gICAgKTtcbiAgfVxuXG4gIHRoaXMuX2VuZENhbGxlZCA9IHRydWU7XG5cbiAgLy8gc3RvcmUgY2FsbGJhY2tcbiAgdGhpcy5fY2FsbGJhY2sgPSBmbiB8fCBub29wO1xuXG4gIC8vIHF1ZXJ5c3RyaW5nXG4gIHRoaXMuX2ZpbmFsaXplUXVlcnlTdHJpbmcoKTtcblxuICB0aGlzLl9lbmQoKTtcbn07XG5cblJlcXVlc3QucHJvdG90eXBlLl9zZXRVcGxvYWRUaW1lb3V0ID0gZnVuY3Rpb24gKCkge1xuICBjb25zdCBzZWxmID0gdGhpcztcblxuICAvLyB1cGxvYWQgdGltZW91dCBpdCdzIHdva3JzIG9ubHkgaWYgZGVhZGxpbmUgdGltZW91dCBpcyBvZmZcbiAgaWYgKHRoaXMuX3VwbG9hZFRpbWVvdXQgJiYgIXRoaXMuX3VwbG9hZFRpbWVvdXRUaW1lcikge1xuICAgIHRoaXMuX3VwbG9hZFRpbWVvdXRUaW1lciA9IHNldFRpbWVvdXQoKCkgPT4ge1xuICAgICAgc2VsZi5fdGltZW91dEVycm9yKFxuICAgICAgICAnVXBsb2FkIHRpbWVvdXQgb2YgJyxcbiAgICAgICAgc2VsZi5fdXBsb2FkVGltZW91dCxcbiAgICAgICAgJ0VUSU1FRE9VVCdcbiAgICAgICk7XG4gICAgfSwgdGhpcy5fdXBsb2FkVGltZW91dCk7XG4gIH1cbn07XG5cbi8vIGVzbGludC1kaXNhYmxlLW5leHQtbGluZSBjb21wbGV4aXR5XG5SZXF1ZXN0LnByb3RvdHlwZS5fZW5kID0gZnVuY3Rpb24gKCkge1xuICBpZiAodGhpcy5fYWJvcnRlZClcbiAgICByZXR1cm4gdGhpcy5jYWxsYmFjayhcbiAgICAgIG5ldyBFcnJvcignVGhlIHJlcXVlc3QgaGFzIGJlZW4gYWJvcnRlZCBldmVuIGJlZm9yZSAuZW5kKCkgd2FzIGNhbGxlZCcpXG4gICAgKTtcblxuICBjb25zdCBzZWxmID0gdGhpcztcbiAgdGhpcy54aHIgPSByZXF1ZXN0LmdldFhIUigpO1xuICBjb25zdCB7IHhociB9ID0gdGhpcztcbiAgbGV0IGRhdGEgPSB0aGlzLl9mb3JtRGF0YSB8fCB0aGlzLl9kYXRhO1xuXG4gIHRoaXMuX3NldFRpbWVvdXRzKCk7XG5cbiAgLy8gc3RhdGUgY2hhbmdlXG4gIHhoci5vbnJlYWR5c3RhdGVjaGFuZ2UgPSAoKSA9PiB7XG4gICAgY29uc3QgeyByZWFkeVN0YXRlIH0gPSB4aHI7XG4gICAgaWYgKHJlYWR5U3RhdGUgPj0gMiAmJiBzZWxmLl9yZXNwb25zZVRpbWVvdXRUaW1lcikge1xuICAgICAgY2xlYXJUaW1lb3V0KHNlbGYuX3Jlc3BvbnNlVGltZW91dFRpbWVyKTtcbiAgICB9XG5cbiAgICBpZiAocmVhZHlTdGF0ZSAhPT0gNCkge1xuICAgICAgcmV0dXJuO1xuICAgIH1cblxuICAgIC8vIEluIElFOSwgcmVhZHMgdG8gYW55IHByb3BlcnR5IChlLmcuIHN0YXR1cykgb2ZmIG9mIGFuIGFib3J0ZWQgWEhSIHdpbGxcbiAgICAvLyByZXN1bHQgaW4gdGhlIGVycm9yIFwiQ291bGQgbm90IGNvbXBsZXRlIHRoZSBvcGVyYXRpb24gZHVlIHRvIGVycm9yIGMwMGMwMjNmXCJcbiAgICBsZXQgc3RhdHVzO1xuICAgIHRyeSB7XG4gICAgICBzdGF0dXMgPSB4aHIuc3RhdHVzO1xuICAgIH0gY2F0Y2gge1xuICAgICAgc3RhdHVzID0gMDtcbiAgICB9XG5cbiAgICBpZiAoIXN0YXR1cykge1xuICAgICAgaWYgKHNlbGYudGltZWRvdXQgfHwgc2VsZi5fYWJvcnRlZCkgcmV0dXJuO1xuICAgICAgcmV0dXJuIHNlbGYuY3Jvc3NEb21haW5FcnJvcigpO1xuICAgIH1cblxuICAgIHNlbGYuZW1pdCgnZW5kJyk7XG4gIH07XG5cbiAgLy8gcHJvZ3Jlc3NcbiAgY29uc3QgaGFuZGxlUHJvZ3Jlc3MgPSAoZGlyZWN0aW9uLCBlKSA9PiB7XG4gICAgaWYgKGUudG90YWwgPiAwKSB7XG4gICAgICBlLnBlcmNlbnQgPSAoZS5sb2FkZWQgLyBlLnRvdGFsKSAqIDEwMDtcblxuICAgICAgaWYgKGUucGVyY2VudCA9PT0gMTAwKSB7XG4gICAgICAgIGNsZWFyVGltZW91dChzZWxmLl91cGxvYWRUaW1lb3V0VGltZXIpO1xuICAgICAgfVxuICAgIH1cblxuICAgIGUuZGlyZWN0aW9uID0gZGlyZWN0aW9uO1xuICAgIHNlbGYuZW1pdCgncHJvZ3Jlc3MnLCBlKTtcbiAgfTtcblxuICBpZiAodGhpcy5oYXNMaXN0ZW5lcnMoJ3Byb2dyZXNzJykpIHtcbiAgICB0cnkge1xuICAgICAgeGhyLmFkZEV2ZW50TGlzdGVuZXIoJ3Byb2dyZXNzJywgaGFuZGxlUHJvZ3Jlc3MuYmluZChudWxsLCAnZG93bmxvYWQnKSk7XG4gICAgICBpZiAoeGhyLnVwbG9hZCkge1xuICAgICAgICB4aHIudXBsb2FkLmFkZEV2ZW50TGlzdGVuZXIoXG4gICAgICAgICAgJ3Byb2dyZXNzJyxcbiAgICAgICAgICBoYW5kbGVQcm9ncmVzcy5iaW5kKG51bGwsICd1cGxvYWQnKVxuICAgICAgICApO1xuICAgICAgfVxuICAgIH0gY2F0Y2gge1xuICAgICAgLy8gQWNjZXNzaW5nIHhoci51cGxvYWQgZmFpbHMgaW4gSUUgZnJvbSBhIHdlYiB3b3JrZXIsIHNvIGp1c3QgcHJldGVuZCBpdCBkb2Vzbid0IGV4aXN0LlxuICAgICAgLy8gUmVwb3J0ZWQgaGVyZTpcbiAgICAgIC8vIGh0dHBzOi8vY29ubmVjdC5taWNyb3NvZnQuY29tL0lFL2ZlZWRiYWNrL2RldGFpbHMvODM3MjQ1L3htbGh0dHByZXF1ZXN0LXVwbG9hZC10aHJvd3MtaW52YWxpZC1hcmd1bWVudC13aGVuLXVzZWQtZnJvbS13ZWItd29ya2VyLWNvbnRleHRcbiAgICB9XG4gIH1cblxuICBpZiAoeGhyLnVwbG9hZCkge1xuICAgIHRoaXMuX3NldFVwbG9hZFRpbWVvdXQoKTtcbiAgfVxuXG4gIC8vIGluaXRpYXRlIHJlcXVlc3RcbiAgdHJ5IHtcbiAgICBpZiAodGhpcy51c2VybmFtZSAmJiB0aGlzLnBhc3N3b3JkKSB7XG4gICAgICB4aHIub3Blbih0aGlzLm1ldGhvZCwgdGhpcy51cmwsIHRydWUsIHRoaXMudXNlcm5hbWUsIHRoaXMucGFzc3dvcmQpO1xuICAgIH0gZWxzZSB7XG4gICAgICB4aHIub3Blbih0aGlzLm1ldGhvZCwgdGhpcy51cmwsIHRydWUpO1xuICAgIH1cbiAgfSBjYXRjaCAoZXJyKSB7XG4gICAgLy8gc2VlICMxMTQ5XG4gICAgcmV0dXJuIHRoaXMuY2FsbGJhY2soZXJyKTtcbiAgfVxuXG4gIC8vIENPUlNcbiAgaWYgKHRoaXMuX3dpdGhDcmVkZW50aWFscykgeGhyLndpdGhDcmVkZW50aWFscyA9IHRydWU7XG5cbiAgLy8gYm9keVxuICBpZiAoXG4gICAgIXRoaXMuX2Zvcm1EYXRhICYmXG4gICAgdGhpcy5tZXRob2QgIT09ICdHRVQnICYmXG4gICAgdGhpcy5tZXRob2QgIT09ICdIRUFEJyAmJlxuICAgIHR5cGVvZiBkYXRhICE9PSAnc3RyaW5nJyAmJlxuICAgICF0aGlzLl9pc0hvc3QoZGF0YSlcbiAgKSB7XG4gICAgLy8gc2VyaWFsaXplIHN0dWZmXG4gICAgY29uc3QgY29udGVudFR5cGUgPSB0aGlzLl9oZWFkZXJbJ2NvbnRlbnQtdHlwZSddO1xuICAgIGxldCBzZXJpYWxpemUgPVxuICAgICAgdGhpcy5fc2VyaWFsaXplciB8fFxuICAgICAgcmVxdWVzdC5zZXJpYWxpemVbY29udGVudFR5cGUgPyBjb250ZW50VHlwZS5zcGxpdCgnOycpWzBdIDogJyddO1xuICAgIGlmICghc2VyaWFsaXplICYmIGlzSlNPTihjb250ZW50VHlwZSkpIHtcbiAgICAgIHNlcmlhbGl6ZSA9IHJlcXVlc3Quc2VyaWFsaXplWydhcHBsaWNhdGlvbi9qc29uJ107XG4gICAgfVxuXG4gICAgaWYgKHNlcmlhbGl6ZSkgZGF0YSA9IHNlcmlhbGl6ZShkYXRhKTtcbiAgfVxuXG4gIC8vIHNldCBoZWFkZXIgZmllbGRzXG4gIGZvciAoY29uc3QgZmllbGQgaW4gdGhpcy5oZWFkZXIpIHtcbiAgICBpZiAodGhpcy5oZWFkZXJbZmllbGRdID09PSBudWxsKSBjb250aW51ZTtcblxuICAgIGlmIChPYmplY3QucHJvdG90eXBlLmhhc093blByb3BlcnR5LmNhbGwodGhpcy5oZWFkZXIsIGZpZWxkKSlcbiAgICAgIHhoci5zZXRSZXF1ZXN0SGVhZGVyKGZpZWxkLCB0aGlzLmhlYWRlcltmaWVsZF0pO1xuICB9XG5cbiAgaWYgKHRoaXMuX3Jlc3BvbnNlVHlwZSkge1xuICAgIHhoci5yZXNwb25zZVR5cGUgPSB0aGlzLl9yZXNwb25zZVR5cGU7XG4gIH1cblxuICAvLyBzZW5kIHN0dWZmXG4gIHRoaXMuZW1pdCgncmVxdWVzdCcsIHRoaXMpO1xuXG4gIC8vIElFMTEgeGhyLnNlbmQodW5kZWZpbmVkKSBzZW5kcyAndW5kZWZpbmVkJyBzdHJpbmcgYXMgUE9TVCBwYXlsb2FkIChpbnN0ZWFkIG9mIG5vdGhpbmcpXG4gIC8vIFdlIG5lZWQgbnVsbCBoZXJlIGlmIGRhdGEgaXMgdW5kZWZpbmVkXG4gIHhoci5zZW5kKHR5cGVvZiBkYXRhID09PSAndW5kZWZpbmVkJyA/IG51bGwgOiBkYXRhKTtcbn07XG5cbnJlcXVlc3QuYWdlbnQgPSAoKSA9PiBuZXcgQWdlbnQoKTtcblxuWydHRVQnLCAnUE9TVCcsICdPUFRJT05TJywgJ1BBVENIJywgJ1BVVCcsICdERUxFVEUnXS5mb3JFYWNoKChtZXRob2QpID0+IHtcbiAgQWdlbnQucHJvdG90eXBlW21ldGhvZC50b0xvd2VyQ2FzZSgpXSA9IGZ1bmN0aW9uICh1cmwsIGZuKSB7XG4gICAgY29uc3QgcmVxID0gbmV3IHJlcXVlc3QuUmVxdWVzdChtZXRob2QsIHVybCk7XG4gICAgdGhpcy5fc2V0RGVmYXVsdHMocmVxKTtcbiAgICBpZiAoZm4pIHtcbiAgICAgIHJlcS5lbmQoZm4pO1xuICAgIH1cblxuICAgIHJldHVybiByZXE7XG4gIH07XG59KTtcblxuQWdlbnQucHJvdG90eXBlLmRlbCA9IEFnZW50LnByb3RvdHlwZS5kZWxldGU7XG5cbi8qKlxuICogR0VUIGB1cmxgIHdpdGggb3B0aW9uYWwgY2FsbGJhY2sgYGZuKHJlcylgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB1cmxcbiAqIEBwYXJhbSB7TWl4ZWR8RnVuY3Rpb259IFtkYXRhXSBvciBmblxuICogQHBhcmFtIHtGdW5jdGlvbn0gW2ZuXVxuICogQHJldHVybiB7UmVxdWVzdH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxucmVxdWVzdC5nZXQgPSAodXJsLCBkYXRhLCBmbikgPT4ge1xuICBjb25zdCByZXEgPSByZXF1ZXN0KCdHRVQnLCB1cmwpO1xuICBpZiAodHlwZW9mIGRhdGEgPT09ICdmdW5jdGlvbicpIHtcbiAgICBmbiA9IGRhdGE7XG4gICAgZGF0YSA9IG51bGw7XG4gIH1cblxuICBpZiAoZGF0YSkgcmVxLnF1ZXJ5KGRhdGEpO1xuICBpZiAoZm4pIHJlcS5lbmQoZm4pO1xuICByZXR1cm4gcmVxO1xufTtcblxuLyoqXG4gKiBIRUFEIGB1cmxgIHdpdGggb3B0aW9uYWwgY2FsbGJhY2sgYGZuKHJlcylgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB1cmxcbiAqIEBwYXJhbSB7TWl4ZWR8RnVuY3Rpb259IFtkYXRhXSBvciBmblxuICogQHBhcmFtIHtGdW5jdGlvbn0gW2ZuXVxuICogQHJldHVybiB7UmVxdWVzdH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxucmVxdWVzdC5oZWFkID0gKHVybCwgZGF0YSwgZm4pID0+IHtcbiAgY29uc3QgcmVxID0gcmVxdWVzdCgnSEVBRCcsIHVybCk7XG4gIGlmICh0eXBlb2YgZGF0YSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIGZuID0gZGF0YTtcbiAgICBkYXRhID0gbnVsbDtcbiAgfVxuXG4gIGlmIChkYXRhKSByZXEucXVlcnkoZGF0YSk7XG4gIGlmIChmbikgcmVxLmVuZChmbik7XG4gIHJldHVybiByZXE7XG59O1xuXG4vKipcbiAqIE9QVElPTlMgcXVlcnkgdG8gYHVybGAgd2l0aCBvcHRpb25hbCBjYWxsYmFjayBgZm4ocmVzKWAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVybFxuICogQHBhcmFtIHtNaXhlZHxGdW5jdGlvbn0gW2RhdGFdIG9yIGZuXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBbZm5dXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5yZXF1ZXN0Lm9wdGlvbnMgPSAodXJsLCBkYXRhLCBmbikgPT4ge1xuICBjb25zdCByZXEgPSByZXF1ZXN0KCdPUFRJT05TJywgdXJsKTtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgZm4gPSBkYXRhO1xuICAgIGRhdGEgPSBudWxsO1xuICB9XG5cbiAgaWYgKGRhdGEpIHJlcS5zZW5kKGRhdGEpO1xuICBpZiAoZm4pIHJlcS5lbmQoZm4pO1xuICByZXR1cm4gcmVxO1xufTtcblxuLyoqXG4gKiBERUxFVEUgYHVybGAgd2l0aCBvcHRpb25hbCBgZGF0YWAgYW5kIGNhbGxiYWNrIGBmbihyZXMpYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdXJsXG4gKiBAcGFyYW0ge01peGVkfSBbZGF0YV1cbiAqIEBwYXJhbSB7RnVuY3Rpb259IFtmbl1cbiAqIEByZXR1cm4ge1JlcXVlc3R9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbmZ1bmN0aW9uIGRlbCh1cmwsIGRhdGEsIGZuKSB7XG4gIGNvbnN0IHJlcSA9IHJlcXVlc3QoJ0RFTEVURScsIHVybCk7XG4gIGlmICh0eXBlb2YgZGF0YSA9PT0gJ2Z1bmN0aW9uJykge1xuICAgIGZuID0gZGF0YTtcbiAgICBkYXRhID0gbnVsbDtcbiAgfVxuXG4gIGlmIChkYXRhKSByZXEuc2VuZChkYXRhKTtcbiAgaWYgKGZuKSByZXEuZW5kKGZuKTtcbiAgcmV0dXJuIHJlcTtcbn1cblxucmVxdWVzdC5kZWwgPSBkZWw7XG5yZXF1ZXN0LmRlbGV0ZSA9IGRlbDtcblxuLyoqXG4gKiBQQVRDSCBgdXJsYCB3aXRoIG9wdGlvbmFsIGBkYXRhYCBhbmQgY2FsbGJhY2sgYGZuKHJlcylgLlxuICpcbiAqIEBwYXJhbSB7U3RyaW5nfSB1cmxcbiAqIEBwYXJhbSB7TWl4ZWR9IFtkYXRhXVxuICogQHBhcmFtIHtGdW5jdGlvbn0gW2ZuXVxuICogQHJldHVybiB7UmVxdWVzdH1cbiAqIEBhcGkgcHVibGljXG4gKi9cblxucmVxdWVzdC5wYXRjaCA9ICh1cmwsIGRhdGEsIGZuKSA9PiB7XG4gIGNvbnN0IHJlcSA9IHJlcXVlc3QoJ1BBVENIJywgdXJsKTtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgZm4gPSBkYXRhO1xuICAgIGRhdGEgPSBudWxsO1xuICB9XG5cbiAgaWYgKGRhdGEpIHJlcS5zZW5kKGRhdGEpO1xuICBpZiAoZm4pIHJlcS5lbmQoZm4pO1xuICByZXR1cm4gcmVxO1xufTtcblxuLyoqXG4gKiBQT1NUIGB1cmxgIHdpdGggb3B0aW9uYWwgYGRhdGFgIGFuZCBjYWxsYmFjayBgZm4ocmVzKWAuXG4gKlxuICogQHBhcmFtIHtTdHJpbmd9IHVybFxuICogQHBhcmFtIHtNaXhlZH0gW2RhdGFdXG4gKiBAcGFyYW0ge0Z1bmN0aW9ufSBbZm5dXG4gKiBAcmV0dXJuIHtSZXF1ZXN0fVxuICogQGFwaSBwdWJsaWNcbiAqL1xuXG5yZXF1ZXN0LnBvc3QgPSAodXJsLCBkYXRhLCBmbikgPT4ge1xuICBjb25zdCByZXEgPSByZXF1ZXN0KCdQT1NUJywgdXJsKTtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgZm4gPSBkYXRhO1xuICAgIGRhdGEgPSBudWxsO1xuICB9XG5cbiAgaWYgKGRhdGEpIHJlcS5zZW5kKGRhdGEpO1xuICBpZiAoZm4pIHJlcS5lbmQoZm4pO1xuICByZXR1cm4gcmVxO1xufTtcblxuLyoqXG4gKiBQVVQgYHVybGAgd2l0aCBvcHRpb25hbCBgZGF0YWAgYW5kIGNhbGxiYWNrIGBmbihyZXMpYC5cbiAqXG4gKiBAcGFyYW0ge1N0cmluZ30gdXJsXG4gKiBAcGFyYW0ge01peGVkfEZ1bmN0aW9ufSBbZGF0YV0gb3IgZm5cbiAqIEBwYXJhbSB7RnVuY3Rpb259IFtmbl1cbiAqIEByZXR1cm4ge1JlcXVlc3R9XG4gKiBAYXBpIHB1YmxpY1xuICovXG5cbnJlcXVlc3QucHV0ID0gKHVybCwgZGF0YSwgZm4pID0+IHtcbiAgY29uc3QgcmVxID0gcmVxdWVzdCgnUFVUJywgdXJsKTtcbiAgaWYgKHR5cGVvZiBkYXRhID09PSAnZnVuY3Rpb24nKSB7XG4gICAgZm4gPSBkYXRhO1xuICAgIGRhdGEgPSBudWxsO1xuICB9XG5cbiAgaWYgKGRhdGEpIHJlcS5zZW5kKGRhdGEpO1xuICBpZiAoZm4pIHJlcS5lbmQoZm4pO1xuICByZXR1cm4gcmVxO1xufTtcbiJdfQ==