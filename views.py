from django.conf import settings
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.models import User, Group
from django.contrib.auth.hashers import make_password, check_password
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import reverse, redirect
from django.urls import reverse_lazy
from django.views.generic import TemplateView, CreateView, DeleteView, UpdateView
from django.views.generic.detail import DetailView
from django.views.decorators.csrf import csrf_exempt

from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

from core.forms.pgp_keys import KeyCreateForm
from core.models import PGPKey, Document, DocumentType
from core.permissions import KeysNotSetMixin, KeyDataExistsMixin, MasterKeysGenerationMixin, SuperUserRequiredMixin, PrivateKeyCheckMixin

import random, string, uuid, magic

characters = string.ascii_lowercase + string.ascii_uppercase + string.digits + "!$&*"

@csrf_exempt
def gnupg_log_handler(request, uuid):
    if request.method == 'POST':
        if not request.POST.get('auth_token', None):
            return HttpResponse(status=401)
        if request.POST['auth_token'] != settings.GNUPG_LOG_AUTH_TOKEN:
            return HttpResponse(status=401)

        channel = uuid
        layer = get_channel_layer()

        async_to_sync(layer.group_send)(
            f"GPG_{channel}",
            {
                'type':'group.message',
                'message':{
                    'message_type':'gnupg_log',
                    'message': request.POST['message']
                }
            }
        )

        return HttpResponse(status=200)
    else:
        return HttpResponse(status=405)


class CheckKeysTemplateView(KeysNotSetMixin, TemplateView):
    pass


class MasterKeyCreateView(MasterKeysGenerationMixin, CreateView):
    model = PGPKey
    form_class = KeyCreateForm
    template_name = 'master_keys/master_keys.html'
    success_url = reverse_lazy('master_keys_generate')

    def form_valid(self, form):
        form.instance.created_by = self.request.user

        self.request.session['key_data'] = {
            'realname': form.cleaned_data['realname'],
            'email': form.cleaned_data['email'],
            'password': form.cleaned_data['password']
        }
        self.request.session['key_type'] = 'MASTER'
        self.request.session['proceed'] = True
        self.request.session['websocket_uuid'] = str(uuid.uuid4())

        return super().form_valid(form)

class KeyCreateView(KeyDataExistsMixin, CreateView):
    model = PGPKey
    form_class = KeyCreateForm
    template_name = 'keys/key_create.html'
    success_url = reverse_lazy('regular_keys_generate')

    def form_valid(self, form):
        form.instance.created_by = self.request.user

        self.request.session['key_data'] = {
            'realname': form.cleaned_data['realname'],
            'email': form.cleaned_data['email'],
            'password': form.cleaned_data['password']
        }
        self.request.session['key_type'] = 'NORMAL'
        self.request.session['proceed'] = True
        self.request.session['websocket_uuid'] = str(uuid.uuid4())

        return super().form_valid(form)


class KeyGenerateView(LoginRequiredMixin, TemplateView):
    template_name = 'keys/key_generate_view.html'


class ManageDashboardView(TemplateView):
    template_name = 'manage/dashboard.html'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)

        context['users'] = User.objects.all()
        context['groups'] = Group.objects.all()
        context['document_types'] = DocumentType.objects.all()
        context['orphaned_documents'] = Document.objects.filter(document_type=None)

        return context


class CreateUserView(CreateView):
    model = User
    fields = [
        'username',
        'email',
    ]

    def form_invalid(self, form):
        original_response = super().form_valid(form)

        return JsonResponse(form.errors, status=400)

    def form_valid(self, form):
        form.instance.password = make_password(
            ''.join([random.choice(characters) for i in range(0,32)]))

        original_response = super().form_valid(form)

        return JsonResponse({
            "status":"OK",
            "id": form.instance.id,
            "username":form.cleaned_data['username'],
            "email":form.cleaned_data['email']},
            status=200)


class UserGroupUpdateView(UpdateView):
    model = User
    fields = [
        "groups"
    ]

    def form_invalid(self, form):
        original_response = super().form_valid(form)

        return JsonResponse(form.errors, status=400)

    def form_valid(self, form):
        original_response = super().form_valid(form)

        return JsonResponse({"status":"OK"}, status=200)

class DeleteUserView(DeleteView):
    model = User

    def delete(self, request, *args, **kwrags):
        self.get_object().delete()
        return JsonResponse({"status":"OK"}, status=200)


class CreateGroupView(CreateView):
    model = Group
    fields = [
        'name',
    ]

    def form_invalid(self, form):
        original_response = super().form_valid(form)

        return JsonResponse(form.errors, status=400)

    def form_valid(self, form):
        original_response = super().form_valid(form)

        return JsonResponse({
            "status":"OK",
            "id": form.instance.id,
            "name":form.cleaned_data['name']},
            status=200)


class DeleteGroupView(DeleteView):
    model = Group

    def delete(self, request, *args, **kwrags):
        self.get_object().delete()
        return JsonResponse({"status":"OK"}, status=200)


class CreateDocumentTypeView(CreateView):
    model = DocumentType
    fields = [
        'name',
        'groups'
    ]

    def form_invalid(self, form):
        original_response = super().form_valid(form)

        return JsonResponse(form.errors, status=400)

    def form_valid(self, form):
        form.instance.created_by = self.request.user

        original_response = super().form_valid(form)

        return_data = {
            "status": "OK",
            "id": form.instance.id,
            "name": form.cleaned_data['name'],
            "groups": [group.id for group in form.instance.groups.all()]
        }

        return JsonResponse(return_data, status=200)


class DocumentTypeEditView(UpdateView):
    model = DocumentType
    fields = [
        'name',
        'groups'
    ]

    def form_invalid(self, form):
        original_response = super().form_valid(form)

        return JsonResponse(form.errors, status=400)

    def form_valid(self, form):
        original_response = super().form_valid(form)

        return_data = {
            "status": "OK",
            "name": form.cleaned_data['name'],
            "groups": [group.id for group in form.instance.groups.all()]
        }

        return JsonResponse(return_data, status=200)

class DeleteDocumentTypeView(DeleteView):
    model = DocumentType

    def delete(self, request, *args, **kwrags):
        self.get_object().delete()
        return JsonResponse({"status":"OK"}, status=200)


class DocumentCreateView(CreateView):
    model = Document
    fields = [
        'document',
        'document_type',
    ]

    def form_valid(self, form):
        form.instance.created_by = self.request.user
        form.instance.title = self.request.FILES['document'].name

        if form.is_valid():
            new_document = form.save()

        self.request.session['enc_websocket_uuid'] = str(uuid.uuid4())
        self.request.session['document_upload_id'] = str(new_document.id)

        return redirect('/')


class DocumentDeleteView(DeleteView):
    pass


class AllDocumentsView(LoginRequiredMixin, TemplateView):
    template_name = 'all_documents.html'

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)

        context['document_types'] = []

        for document_type in DocumentType.objects.all() :
            for group in document_type.groups.all():
                if group in self.request.user.groups.all():
                    if document_type not in context['document_types']:
                        context['document_types'].append(document_type)

        return context


class DocumentDecryptView(PrivateKeyCheckMixin, DetailView):
    template_name='decrypt.html'
    model = Document


class DashboardView(KeysNotSetMixin, TemplateView):

    def get_context_data(self, *args, **kwargs):
        context = super().get_context_data(*args, **kwargs)

        context['documents'] = Document.objects.filter(
            created_by=self.request.user).order_by('-created_date')

        context['pgp_keys'] = PGPKey.objects.filter(
            created_by=self.request.user).order_by('-created_date')

        context['document_types'] = []

        for document_type in DocumentType.objects.all() :
            for group in document_type.groups.all():
                if group in self.request.user.groups.all():
                    if document_type not in context['document_types']:
                        context['document_types'].append(document_type)

        return context


def download_handler(request):
    if request.method == 'GET':
        if 'file_download' in request.session:
            document_record = Document.objects.filter(pk=request.session['file_download']['document_id']).first()

            if document_record:
                mime = magic.Magic(mime=True)
                content_type = mime.from_file(request.session['file_download']['file'])

                with open(request.session['file_download']['file'], 'rb') as fh:
                    response = HttpResponse(fh, content_type=content_type) 
                    response["Content-disposition"] = f'attachment; filename={document_record.title}'

                    layer = get_channel_layer()
                    async_to_sync(layer.send)(
                        'secure-remove',
                        {
                            'type':'remove',
                            'file': request.session['file_download']['file'],
                        }
                    )

                    request.session.pop('file_download', None)

                return response
            else:
                return HttpResponse(status=204)
        else:
            return HttpResponse(status=204)
    else:
        return HttpResponse(status=405)


def check_key(request):
    if request.method == 'POST':
        password = request.POST.get('password', None)
        if password:
            key = PGPKey.objects.filter(created_by=request.user).first()
            if key:
                if check_password(password, key.password):
                    request.session['private_unlocked'] = True
                    return HttpResponse(status=200)
                else:
                    return HttpResponse(status=403)
            else:
                return HttpResponse(status=404)
        else:
            return HttpResponse(status=403)
    else:
        return HttpResponse(status=405)
