var passport = require('passport-strategy');
var SkautIS =  require('node-skautis');

/**
 * Creates an instance of `Strategy`.
 *
 * Options:
 *
 *   - `applicationID`
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `useTestSkautis`
 *
 * @constructor
 * @api public
 */
function SkautISStrategy(options, verify) {
  if (typeof options == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) { throw new TypeError('SkautISStrategy requires a verify callback'); }
  if (!options.applicationID) { throw new TypeError('SkautISStrategy requires a applicationID option'); }
  if (!options.useTestSkautis) options.useTestSkautis = false;

  passport.Strategy.call(this);
  this.name = 'skautis';
  this._verify = verify;
  this._skautis = new SkautIS(options.applicationID, options.useTestSkautis);
}

util.inherits(OAuth2Strategy, passport.Strategy);

/**
 * Authenticate request.
 *
 * This function must be overridden by subclasses.  In abstract form, it always
 * throws an exception.
 *
 * @param {Object} req The request to authenticate.
 * @param {Object} [options] Strategy-specific options.
 * @api public
 */
Strategy.prototype.authenticate = function(req, options) {
  throw new Error('Strategy#authenticate must be overridden by subclass');
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
