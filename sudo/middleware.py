"""
sudo.middleware
~~~~~~~~~~~~~~~

:copyright: (c) 2014 by Matt Robenolt.
:license: BSD, see LICENSE for more details.
"""
from sudo.settings import (
    COOKIE_DOMAIN, COOKIE_HTTPONLY,
    COOKIE_PATH, COOKIE_SECURE, COOKIE_SALT,
)
from sudo.utils import has_sudo_privileges, cookie_name


class SudoMiddleware(object):
    """
    Middleware that contributes ``request.is_sudo()`` and sets the required
    cookie for sudo mode to work correctly.
    """
    def has_sudo_privileges(self, request, region=None):
        # Override me to alter behavior
        return has_sudo_privileges(request, region=region)

    def process_request(self, request):
        assert hasattr(request, 'session'), (
            "The Sudo middleware requires session middleware to be installed."
            "Edit your MIDDLEWARE_CLASSES setting to insert "
            "'django.contrib.sessions.middleware.SessionMiddleware' before "
            "'sudo.middleware.SudoMiddleware'."
        )
        def is_sudo(region=None):
            return self.has_sudo_privileges(request, region=region)

        request.is_sudo = is_sudo

    def process_response(self, request, response):
        is_sudo = getattr(request, '_sudo', None)

        if is_sudo is None:
            return response

        for region, sudo_enabled in is_sudo.iteritems():
            cookie = cookie_name(region)

            # We have explicitly had sudo revoked, so clean up cookie
            if sudo_enabled is False and cookie in request.COOKIES:
                response.delete_cookie(cookie)
                return response

            # Sudo mode has been granted,
            # and we have a token to send back to the user agent
            if sudo_enabled is True and hasattr(request, '_sudo_token') and region in request._sudo_token:
                token = request._sudo_token[region]
                max_age = request._sudo_max_age
                response.set_signed_cookie(
                    cookie, token,
                    salt=COOKIE_SALT,
                    max_age=max_age,  # If max_age is None, it's a session cookie
                    secure=request.is_secure() if COOKIE_SECURE is None else COOKIE_SECURE,
                    httponly=COOKIE_HTTPONLY,  # Not accessible by JavaScript
                    path=COOKIE_PATH,
                    domain=COOKIE_DOMAIN,
                )

        return response
