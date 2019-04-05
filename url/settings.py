from django.urls import path
from django.conf.urls import url

from django.views.generic import TemplateView

from core.views import KeyCreateView, KeyGenerateView

urlpatterns = [
    url(r'^create-key$', KeyCreateView.as_view(), name='master_keys_conf'),
    url(r'^create-key/generate', KeyGenerateView.as_view(), name='regular_keys_generate')
]
