from django.urls import path
from django.contrib.auth.decorators import user_passes_test
from django.conf.urls import url

from django.views.generic import TemplateView

import core.views as views

superuser_required = user_passes_test(lambda u: u.is_superuser, '/', redirect_field_name=None)

urlpatterns = [
    url(r'^$', superuser_required(views.ManageDashboardView.as_view()), name='manage_dashboard'),

    url(r'^create-user$', superuser_required(views.CreateUserView.as_view(success_url='/manage')), name='create_user'),
    url(r'^update-user-groups/(?P<pk>[^/]+)/$', superuser_required(views.UserGroupUpdateView.as_view(success_url='/manage')), name='edit_user'),
    url(r'^delete-user/(?P<pk>[^/]+)/$', superuser_required(views.DeleteUserView.as_view(success_url="/manage")), name='delete_user'),

    url(r'^delete-group/(?P<pk>[^/]+)/$', superuser_required(views.DeleteGroupView.as_view()), name='delete_group'),
    url(r'^create-group$', superuser_required(views.CreateGroupView.as_view(success_url='/manage')), name='create_group'),

    url(r'^create-document-type$', superuser_required(views.CreateDocumentTypeView.as_view(success_url='/manage')), name='create_document_type'),
    url(r'^update-document-type/(?P<pk>[^/]+)/$', superuser_required(views.DocumentTypeEditView.as_view(success_url='/manage')), name="edit_document_type"),
    url(r'^delete-document-type/(?P<pk>[^/]+)/$', superuser_required(views.DeleteDocumentTypeView.as_view()), name='delete_document_type'),

    url(r'^delete-document/(?P<pk>[^/]+)/$', views.DocumentDeleteView.as_view(), name='delete_document'),

    url(r'^websocket-testing$', TemplateView.as_view(template_name='websocket_test.html'), name='webscoket_test'),
]
