var util =  require('util');
var moment =  require('moment');
var passport = require('passport-strategy');
var SkautIS =  require('node-skautis');

/**
 * Creates an instance of `Strategy`.
 *
 * Options:
 *
 *   - `applicationID`
 *   - `callbackURL`       URL to which the service provider will redirect the user after obtaining authorization
 *   - `useTestSkautIS`
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
  if (!options.applicationId) { throw new TypeError('SkautISStrategy requires a applicationId option'); }
  if (!options.useTestSkautIS) options.useTestSkautIS = false;

  passport.Strategy.call(this);
  this.name = 'skautis';
  this._verify = verify;
  this._skautis = new SkautIS(options.applicationId, options.useTestSkautIS);
}

util.inherits(SkautISStrategy, passport.Strategy);

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
SkautISStrategy.prototype.authenticate = function(req, options) {
  console.dir(req.body.skautIS_Token);
  console.dir(req.query);
  console.dir(req.body);

  var self = this;
  if (req.body && req.body.skautIS_Token) {
    this._skautis.setToken(req.body.skautIS_Token);
    this.getUserDetail(function(err, data) {
      if(err) {return self.error(err); }
      var profile = {};

      profile.id = data.ID;
      profile.idPerson = data.ID_Person;
      profile.token = req.body.skautIS_Token;
      profile.logoutTime = new Date(moment(req.body.skautIS_DateLogout, "DD. MM. YYYY HH:mm:ss"));

      function verified(err, user, info) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(info); }
        self.success(user, info);
      }

      self._verify(self._skautis, profile, verified);
    });
  }
  else {
    var location = self._skautis.getLoginURL();
    self.redirect(location);
  }
};

SkautISStrategy.prototype.getUserDetail = function(fn) {
  this._skautis.UserManagement.UserDetail(this._skautis.skautisToken, null, function(err, data) {
    if(err) {
      return  fn(err, null);
    }

    fn(null, data);
  });
}

/**
 * Expose `Strategy`.
 */
module.exports = SkautISStrategy;
