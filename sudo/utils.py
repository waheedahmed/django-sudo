"""
sudo.utils
~~~~~~~~~~

:copyright: (c) 2014 by Matt Robenolt.
:license: BSD, see LICENSE for more details.
"""
from collections import defaultdict
from django.core.signing import BadSignature
from django.utils.crypto import get_random_string

from sudo.settings import COOKIE_NAME, COOKIE_AGE, COOKIE_SALT


def cookie_name(region):
    if region is None:
        return COOKIE_NAME
    else:
        return str('%s-%s' % (COOKIE_NAME, region))

def setup_request(request):

    if not hasattr(request, '_sudo'):
        request._sudo = defaultdict(lambda: None)

    if not hasattr(request, '_sudo_token'):
        request._sudo_token = {}

def grant_sudo_privileges(request, max_age=COOKIE_AGE, region=None):
    """
    Assigns a random token to the user's session
    that allows them to have elevated permissions
    """
    user = getattr(request, 'user', None)

    # If there's not a user on the request, just noop
    if user is None:
        return

    if not user.is_authenticated():
        raise ValueError('User needs to be logged in to be elevated to sudo')

    # Token doesn't need to be unique,
    # just needs to be unpredictable and match the cookie and the session
    token = get_random_string()

    setup_request(request)
    request.session[cookie_name(region)] = token
    request._sudo[region] = True
    request._sudo_token[region] = token
    request._sudo_max_age = max_age
    return token


def revoke_sudo_privileges(request, region=None):
    """
    Revoke sudo privileges from a request explicitly
    """
    setup_request(request)

    request._sudo[region] = False
    if cookie_name(region) in request.session:
        del request.session[cookie_name(region)]


def has_sudo_privileges(request, region=None):
    """
    Check if a request is allowed to perform sudo actions
    """
    setup_request(request)

    if request._sudo[region] is None:
        try:
            token = request.get_signed_cookie(
                cookie_name(region),
                salt=COOKIE_SALT,
                max_age=COOKIE_AGE
            )
            request._sudo[region] = (
                request.user.is_authenticated() and
                token == request.session[cookie_name(region)]
            )
        except (KeyError, BadSignature):
            request._sudo[region] = False
    return request._sudo[region]

def new_sudo_token_on_activity(request, region=None):
    """
    Provide new sudo token content on activity and reset timeout.
    """

    token = get_random_string()

    setup_request(request)
    request.session[cookie_name(region)] = token
    request._sudo_token[region] = token
    request._sudo_max_age = COOKIE_AGE
