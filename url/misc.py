from django.conf.urls import url

from core.views import DocumentCreateView, DocumentDecryptView, download_handler, AllDocumentsView, check_key

urlpatterns = [
    url(r'^upload-document$', DocumentCreateView.as_view(), name='upload_document'),
    url(r'^decrypt/(?P<pk>[^/]+)/$', DocumentDecryptView.as_view(), name="decrypt"),
    url(r'^download$', download_handler),
    url(r'^documents$', AllDocumentsView.as_view(), name='all_documents'),
    url(r'^check-key$', check_key)
]
