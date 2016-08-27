var _ = require('lodash'),
  async = require('async'),
  debug = require('debug')('express-request-proxy:proxy'),
  zlib = require('zlib'),
  request = require('request'),
  requestOptions = require('./request-options'),
  is = require('type-is');

require('simple-errors');

var discardApiResponseHeaders = ['content-length'];

var headersToPreserveInCache = ['content-type'];

/* eslint-disable consistent-return */
module.exports = function(options) {
  options = _.defaults(options || {}, {
    ensureAuthenticated: false,
    cache: null,
    spoofHost: null,
    cacheMaxAge: 0,
    userAgent: 'express-request-proxy',
    cacheHttpHeader: 'Express-Request-Proxy-Cache',
    cacheKeyFn: null,
    timeout: 5000,
    maxRedirects: 5,
    gzip: true,
    originalQuery: false
  });

  return function(req, res, next) {
    var method = req.method.toUpperCase();

    if (!options.cache) {
      options.cache = req.app.settings.cache;
    }

    if (!req.ext) {
      req.ext = {};
    }

    req.ext.requestHandler = 'express-request-proxy';

    if (options.ensureAuthenticated === true) {
      if (req.ext.isAuthenticated !== true) {
        debug('user is not authenticated');
        return next(Error.http(401, 'User must be authenticated to invoke this API endpoint'));
      }
    }

    if (method.toUpperCase() === 'GET' && options.cache && options.cacheMaxAge > 0) {
      if (!options.cache) return next(new Error('No cache provider configured'));

      return proxyViaCache(req, res, next);
    }

    makeApiCall(req, res, next);
  };

  function makeApiCall(req, res, next) {
    var apiRequestOptions;

    if (options.spoofCookies && req.headers['x-cookie']) {
      req.headers['cookie'] = req.headers['x-cookie']
      delete req.headers['x-cookie']
    }

    if (options.spoofHost) {
      if (typeof options.spoofHost === 'function') {
        req.headers['host'] = options.spoofHost(req)
      } else {
        req.headers['host'] = options.spoofHost
      }
    }

    try {
      apiRequestOptions = requestOptions(req, options);
    } catch (err) {
      debug('error building request options %s', err.stack);
      return next(Error.http(400, err.message));
    }

    debug('making %s call to %s', apiRequestOptions.method, apiRequestOptions.url);

    var apiRequest;
    if (is.hasBody(req)) {
      debug('piping req body to remote http endpoint');
      apiRequest = req.pipe(request(apiRequestOptions));
    } else {
      apiRequest = request(apiRequestOptions);
    }

    apiRequest.on('error', function(err) {
      unhandledApiError(err, next);
    });

    apiRequest.on('response', function(resp) {
      if (resp.statusCode >= 400) {
        debug('Received error %s from %s', resp.statusCode, apiRequestOptions.url);
        return apiRequest.pipe(res);
      }

      if (_.isArray(options.transforms)) {
        apiRequest = applyTransforms(apiRequest, options.transforms, resp.headers);
      }

      if (options.spoofCookies && resp.headers['set-cookie']) {
        resp.headers['x-set-cookie'] = resp.headers['set-cookie']
        discardApiResponseHeaders.push('set-cookie')
      }

      for (var key in resp.headers) {
        if (_.includes(discardApiResponseHeaders, key)) {
          delete resp.headers[key]
        }
      }

      apiRequest.pipe(res);
    });
  }

  function proxyViaCache(req, res, next) {
    var apiRequestOptions;
    try {
      apiRequestOptions = requestOptions(req, options);
    } catch (err) {
      debug('error building request options %s', err.stack);
      return next(Error.http(400, err.message));
    }

    var cacheKey;
    if (_.isFunction(options.cacheKeyFn)) {
      cacheKey = options.cacheKeyFn(req, apiRequestOptions);
    } else {
      cacheKey = apiRequestOptions.url;
    }

    debug('checking if key %s exists in cache', cacheKey);
    options.cache.exists(cacheKey, function(err, exists) {
      if (err) return next(err);

      debug('api response exists in cache=%s', exists);
      if (exists) {
        debug('api response exists in cache');
        return pipeToResponseFromCache(cacheKey, req, res, next);
      }

      debug('key %s not in cache', cacheKey);

      res.set('Cache-Control', 'max-age=' + options.cacheMaxAge);
      res.set(options.cacheHttpHeader, 'miss');

      debug('making %s request to %s', apiRequestOptions.method, apiRequestOptions.url);

      var apiRequest = request(apiRequestOptions);
      apiRequest.on('error', function(_err) {
        debug('error making api call');
        unhandledApiError(_err, next);
      });

      apiRequest.on('response', function(resp) {
        if (resp.statusCode !== 200) {
          return apiRequest.pipe(res);
        }

        if (resp.headers['content-encoding'] === 'gzip') {
          apiRequest = apiRequest.pipe(zlib.createGunzip());
        }

        var headersToKeep = _.pick(resp.headers, headersToPreserveInCache);

        if (_.isArray(options.transforms)) {
          apiRequest = applyTransforms(apiRequest, options.transforms, headersToKeep);
        }

        _.forOwn(headersToKeep, function(value, key) {
          debug('setting header %s to %s', key, value);
          res.set(key, value);
        });

        if (_.isEmpty(headersToKeep) === false) {
          debug('writing original headers to cache');
          options.cache.setex(cacheKey + '__headers',
            options.cacheMaxAge,
            JSON.stringify(headersToKeep));
        }

        debug('cache api response for %s seconds', options.cacheMaxAge);

        apiRequest.pipe(options.cache.writeThrough(cacheKey, options.cacheMaxAge))
          .pipe(res);
      });
    });
  }

  function setHeadersFromCache(cacheKey, res, callback) {
    async.parallel({
      ttl: function(cb) {
        options.cache.ttl(cacheKey, cb);
      },
      headers: function(cb) {
        options.cache.get(cacheKey + '__headers', function(err, value) {
          var headers = {};
          if (value) {
            try {
              headers = JSON.parse(value);
            } catch (jsonError) {
              debug('can\'t parse headers as json');
            }
          }
          cb(null, headers);
        });
      }
    }, function(err, results) {
      if (err) return callback(err);

      _.forOwn(results.headers, function(value, key) {
        res.set(key, value);
      });

      res.set(options.cacheHttpHeader, 'hit');

      debug('setting max-age to remaining TTL of %s', results.ttl);
      res.set('Cache-Control', 'max-age=' + results.ttl);
      callback();
    });
  }

  function pipeToResponseFromCache(cacheKey, req, res, next) {
    debug('getting TTL of cached api response');

    setHeadersFromCache(cacheKey, res, function(err) {
      if (err) return next(err);

      if (_.isFunction(options.cache.readStream)) {
        options.cache.readStream(cacheKey).pipe(res);
        return;
      }
      options.cache.get(cacheKey, function(_err, data) {
        if (_err) return next(_err);
        res.end(data);
      });
    });
  }

  function unhandledApiError(err, next) {
    debug('unhandled API error: %s', err.code);
    if (err.code === 'ETIMEDOUT' || err.code === 'ESOCKETTIMEDOUT') {
      return next(Error.http(408, 'API call timed out'));
    }
    return next(err);
  }

  function applyTransforms(stream, transforms, headers) {
    transforms.forEach(function(transform) {
      debug('applying transform %s', transform.name);
      if (transform.contentType) {
        headers['Content-Type'] = transform.contentType;
      }

      stream = stream.pipe(transform.transform());
    });

    return stream;
  }
};
