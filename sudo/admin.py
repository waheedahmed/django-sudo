from django.contrib.admin.sites import AdminSite
from sudo.decorators import sudo_required

class SudoAdminSite(AdminSite):
    """
    An AdminSite that requires sudo-mode to be activated for any admin
    view.
    """
    def admin_view(self, view, cacheable=False):
        return sudo_required('django_admin')(view)
