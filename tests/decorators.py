from .base import BaseTestCase

from django.http import HttpResponse
from sudo.decorators import sudo_required


@sudo_required
def foo(request):
    return HttpResponse()


@sudo_required('admin_pages')
def admin_foo(request):
    return HttpResponse()


class SudoRequiredTestCase(BaseTestCase):
    def test_is_sudo(self):
        self.request.is_sudo = lambda region: True
        response = foo(self.request)
        self.assertEqual(response.status_code, 200)

    def test_is_not_sudo(self):
        self.request.is_sudo = lambda region: False
        response = foo(self.request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/sudo/?next=/foo')

    def test_is_sudo_same_region(self):
        self.request.is_sudo = lambda region: region == 'admin_pages'
        response = admin_foo(self.request)
        self.assertEqual(response.status_code, 200)

    def test_is_sudo_different_region(self):
        self.request.is_sudo = lambda region: region != 'admin_pages'
        response = admin_foo(self.request)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response['Location'], '/sudo/?next=/foo&region=admin_pages')