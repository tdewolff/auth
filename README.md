# Auth <a name="auth"></a>

Auth is a package that provides OAuth endpoints for social logins and issues a JWT to be used for subsequent API calls.

Supported:

* Google
* Facebook
* GitHub

## Security
*Client* - front-end web application, ie. the browser that the user controls
*Server* - our API server that requires authentications for its endpoints
*Provider* - the OAuth2 service that provides us with authorization to the user's data

### CSRF
In order to prevent CSRF, or at least mitigate it, a few measures have been implemented.

* Using proper CORS headers we prevent API requests from other websites using browsers (does not prevent native apps from making requests).
* By checking both the `Origin` header and the `Referrer` header, making sure it is the same as the server's host. This prevents users from being redirected into a POST action from another website.

## License
Released under the [MIT license](LICENSE.md).

[1]: http://golang.org/ "Go Language"
