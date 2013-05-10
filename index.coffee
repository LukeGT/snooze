sha1          = require 'sha1'
fs            = require 'fs'
json_checker  = require 'json-checker'
coffeecup     = require 'coffeecup'


#
# Represents a RESTful api, which contains a heirarchy of endpoints.
#

class exports.RESTfulAPI

  constructor: (setup) ->

    # Default configuration
    @config =

      # The directory in which to look for RESTful endpoints
      directory: __dirname

      # Whether authentication will be used or not
      authentication: true

      # The name of the header for the authentication token
      tokenHeader: 'Snooze-Auth-Token'

      # The granularity of the token timestamp
      # A lower number gives more security, but less reliability
      tokenGranularity: 60000

      # A function which retrieves the password hash given the user id
      getPassword: (id, callback) -> callback sha1 id + 'budget_buddy'

      # An object whose properties will be made accessible as 'this.property' within every rest method
      scope: {}

    # Copy the setup information into our own object (which contains defaults)
    @config[k] = v for k, v of setup

    #
    # A nested set of objects which store information and methods of the API
    #
    # At any point along the heirarchy, an "authentication" property may be attached
    # to incidacte that this object and all its children should/shouldn't have
    # authentication applied on each request.
    #
    # Each object can have POST/GET/PUT/DELETE as properties to define an endpoint.
    # These must contain an object which contains a property "method",
    # which is called when the enpoint is reached.  You can't have any more HTTP methods
    # within here, but you can have an "authentication" property.
    #
    # Each object can also have an arbitrary name attached, which corresponds to
    # another level in the path.  E.g. the property "email" will represent the
    # endpoint at /api/users/email.  This object in turn can have HTTP methods attached to it.

    @api = {}

    # Read folders from the rest directory
    @recursiveRequire @api, @config.directory

    console.log @api


  #
  # Contructs and returns the middleware according to the setup information given
  # Note: uses synchronous file system methods - only use this method during server setup.
  #
  # returns:  A middleware function

  middleware: -> do (api = @) -> (req, res, next) ->

    console.log 'API CALL:', req.path
    console.log 'authentication?:', api.config.authentication

    # If no path was given, return the API Tester
    return api.apiTester req, res if req.path == '/'

    # Attach the enpoint object to the request
    req.endpoint = api.getEndpoint req

    return res.status(404).send() unless req.endpoint?

    api.checkAuth req, (success, error) ->

      console.log 'auth result', success, error
      return api.sendError res, error, 401 unless success

      errors = api.validate req

      console.log 'validation errors: ', errors
      return api.sendError res, errors if errors

      # TODO: Heaps legit dependency injection
      req.endpoint.scope ?= {}
      req.endpoint.scope[k] = v for k, v of api.config.scope

      # TODO: catch all exceptions and automatically email them. Also automatically send back a generic error
      req.endpoint.method.call req.endpoint.scope, req, res, next


  #
  # Retrieve an endpoint object given the parts of a path to follow
  #
  # parts:    a URI path split on '/'s (IS MUTATED)
  # obj:      the object to traverse at this point
  #
  # returns:  the endpoint pointed to by the path parts

  traversePath: (parts, obj) ->

    # Get the next part of the path
    next = parts.shift()

    # If there's any of the path left
    if next?

      # If this part of the path is defined
      if obj[next]?

        # Retrive the endpoint of the rest of the path
        end = @traversePath parts, obj[next]

        # Assign its authentication value if it isn't already set
        end?.authentication ?= obj.authentication

        return end

      # If this part of the path is not defined
      else

        # Check for a dynamic path parameter
        param = (p for p of obj when p.match /^_/)[0]

        if param?

          # Retrive the endpoint of the rest of the path
          end = @traversePath parts, obj[param]

          if end?

            # Store the parameter's value in the endpoint's scope
            end.scope ?= {}
            end.scope[ param[1..] ] = next

            # Assign its authentication value if it isn't already set
            end.authentication ?= obj.authentication

          return end

        # No dynamic parameter
        else return null

    # If there's none of the path left
    else return obj


  #
  # Get the object definition for an endpoint given a request object
  #
  # req:      The request object
  #
  # returns:  Endpoint

  getEndpoint: (req) ->

    # Construct a list of parts of the path
    parts = req.path.replace( /\/*$/, '' ).split('/')[1..]
    parts.push req.method

    # Find the endpoint
    endpoint = @traversePath parts, @api

    # Apply the authentication setting to the endpoint if need be
    endpoint?.authentication ?= @config.authentication

    return endpoint


  #
  # Check the authentication token of the request.
  #
  #
  # req:                      The request object
  # callback(success, error):
  #     success:              whether the authentication succeeded or not
  #     error:                if it failed, this will contain a string explaining the error
  #
  # returns:  true if it passed or an error message if it did not

  checkAuth: (req, callback) ->

    # If authentication is turned off, return true
    return callback true unless @config.authentication

    # If we don't need authentication for this route, return true
    return callback true unless req.endpoint.authentication

    # Ensure that an authentication token was supplied
    theirToken = req.get @config.tokenHeader
    console.log theirToken
    return callback false, 'Authentication token is missing' unless theirToken?

    # Split up the token into its component parts and ensure they're there
    [ userId, hash ] = theirToken.split ':'
    userId -= 0
    console.log 'hash', hash
    console.log 'userId', userId
    return callback false, 'Authentication token malformed: must look like "userId:hash"' unless userId and hash?

    req.endpoint.scope ?= {}
    req.endpoint.scope.userId = userId

    # Reduce the granularity of the time in order to improve authentication reliability
    time = Math.floor Date.now() / @config.tokenGranularity
    console.log @config.getPassword.toString()
    @config.getPassword userId, (password, error) ->

      return callback false, "Authentication failed: problem while checking password: #{error}" if error

      # Check if the hash matches the current time and password, or surrounding time or password
      if hash in [ time, time - 1, time + 1 ].map( (time) -> sha1 "#{ password }#{ time }" )
        return callback true

      callback false, 'Authentication failed: invalid token'


  #
  # Validate the body (or query string) of the request against the validation information.
  #
  # req:      the request
  #
  # returns:  a list of errors, or null if there were none

  validate: (req) ->

    return true unless req.endpoint.validation?

    errors = json_checker.verify req.endpoint.validation, if req.method == 'GET' then req.query else req.body

    return errors


  #
  # Send errors to the client
  #
  # res: the response object
  # errors: error(s) to send (string or array)
  # status: (optional) the status code to use

  sendError: (res, errors, status) ->

    unless errors instanceof Array
      errors = [ errors ]

    res.status(status ? 403).send errors: errors


  #
  # Render the API tester
  #
  # req: the request object
  # res: the response object

  apiTester: (req, res) ->

    res.send coffeecup.render require('./tester'),
      headername: @config.tokenHeader
      granularity: @config.tokenGranularity


  #
  # Walks a directory structure and turns it into an endpoint heriarchy.
  # Folders are path parts, and files are endpoints.
  #
  # directory: the directory to crawl

  recursiveRequire: (api, directory) ->

    resources = fs.readdirSync directory

    for resource in resources
      subdir = "#{ directory }/#{ resource }"
      stats = fs.statSync subdir

      if stats.isDirectory()
        api[resource] = {}
        @recursiveRequire api[resource], subdir

      else if stats.isFile()
        resource = resource.replace /\..*$/, ''
        api[resource] = require "#{ process.cwd() }/#{ directory }/#{ resource }"

    return null # otherwise the for loop is comprehended...

exports.api = (setup) -> new exports.RESTfulAPI(setup).middleware()