from django.urls import path
from django.contrib.auth.decorators import user_passes_test
from django.conf.urls import url

from django.views.generic import TemplateView

from core.views import MasterKeyCreateView, KeyGenerateView

anonymous_only = user_passes_test(lambda u: u.is_anonymous, '/', redirect_field_name=None)

urlpatterns = [
    url(r'^master_keys$', MasterKeyCreateView.as_view(), name='master_keys_conf'),
    url(r'^master_keys_generate$', KeyGenerateView.as_view(), name='master_keys_generate'),
    url(r'^master_keys_not_admin$', TemplateView.as_view(template_name='master_keys/master_keys_not_admin.html'), name='master_keys_not_admin'),
]
