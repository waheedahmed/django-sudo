"""
sudo.decorators
~~~~~~~~~~~~~~~

:copyright: (c) 2014 by Matt Robenolt.
:license: BSD, see LICENSE for more details.
"""
from functools import wraps

from sudo.settings import RESET_TOKEN
from sudo.utils import new_sudo_token_on_activity
from sudo.views import redirect_to_sudo


def sudo_required(func_or_region):
    """
    Enforces a view to have elevated privileges.
    Should likely be paired with ``@login_required``.

    >>> @sudo_required
    >>> def secure_page(request):
    >>>     ...

    Can also specify a particular sudo region (to only
    allow access to that region).

    >>> @sudo_required('admin_page')
    >>> def secure_admin_page(request):
    >>>     ...
    """
    def wrapper(func):
        @wraps(func)
        def inner(request, *args, **kwargs):
            # N.B. region is captured from the enclosing sudo_required function
            if not request.is_sudo(region=region):
                return redirect_to_sudo(request.get_full_path(), region=region)

            if RESET_TOKEN is True:
                # Provide new sudo token content and reset timeout on activity
                new_sudo_token_on_activity(request, region=region)

            return func(request, *args, **kwargs)
        return inner

    if callable(func_or_region):
        region = None
        return wrapper(func_or_region)
    else:
        region = func_or_region
        return wrapper
