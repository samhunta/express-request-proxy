var parseUrl = require('url').parse;
var formatUrl = require('url').format;
var _ = require('lodash');
var querystring = require('querystring');
var pathToRegexp = require('path-to-regexp');

var BLOCK_HEADERS = ['host'];
var CACHE_HEADERS = ['if-none-match', 'if-modified-since'];

module.exports = function(req, options, limits) {
  var requestOptions = _.pick(options, 'method', 'timeout', 'maxRedirects', 'proxy');

  if (!requestOptions.method) {
    requestOptions.method = req.method;
  }
  
  requestOptions.rejectUnauthorized = ('rejectUnauthorized' in options) ?
    options.rejectUnauthorized :
    false;
    
  requestOptions.followRedirect = ('followRedirect' in options) ?
    options.followRedirect :
    false;

  if (options.spoofCookies) {
    BLOCK_HEADERS.push('cookie')
  }

  if (_.isObject(limits) === true) {
    if (_.isNumber(limits.timeout)) {
      if (_.isNumber(options.timeout) === false || options.timeout > limits.timeout) {
        requestOptions.timeout = limits.timeout;
      }
    }
    if (_.isNumber(limits.maxRedirects)) {
      if (_.isNumber(options.maxRedirects) === false ||
        options.maxRedirects > limits.maxRedirects) {
        requestOptions.maxRedirects = limits.maxRedirects;
      }
    }
  }

  if (_.isObject(options.query)) {
    _.extend(req.query, options.query);
  }

  var parsedUrl = parseUrl(options.url);

  var compiledPath = pathToRegexp.compile(parsedUrl.path);

  var pathname = decodeURIComponent(compiledPath(_.extend({}, req.params, options.params || {})));

  requestOptions.url = formatUrl(_.extend({
    protocol: parsedUrl.protocol,
    host: parsedUrl.host,
    pathname: pathname
  }, options.originalQuery ?
    {search: req.url.replace(/^.+\?/, '')} :
    {query: _.extend({}, querystring.parse(parsedUrl.query), req.query, options.query)}
  ));

  requestOptions.headers = {};

  _.each(req.headers, function(value, key) {
    if (shouldPassthroughHeader(key)) {
      requestOptions.headers[key] = value;
    }
  });

  if (req.ip) {
    requestOptions.headers['x-forwarded-for'] = req.ip;
  }

  if (req.headers && req.headers.host) {
    var hostSplit = req.headers.host.split(':');
    var host = hostSplit[0];
    var port = hostSplit[1];

    if (port) {
      requestOptions.headers['x-forwarded-port'] = port;
    }

    requestOptions.headers['x-forwarded-host'] = host;
  }

  requestOptions.headers['x-forwarded-proto'] = req.secure ? 'https' : 'http';

  if (!requestOptions.headers['accept-encoding']) {
    requestOptions.headers['accept-encoding'] = 'gzip';
  }

  if (_.isObject(options.headers)) {
    _.extend(requestOptions.headers, options.headers);
  }

  if (options.userAgent) {
    requestOptions.headers['user-agent'] = options.userAgent;
  }

  return requestOptions;

  function shouldPassthroughHeader(header) {
    if (_.includes(BLOCK_HEADERS, header) === true) return false;
    if (options.cache && _.includes(CACHE_HEADERS, header) === true) return false;

    return true;
  }
};
