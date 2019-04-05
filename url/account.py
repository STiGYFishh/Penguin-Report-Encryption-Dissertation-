from django.urls import path
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import user_passes_test
from django.conf.urls import url

anonymous_only = user_passes_test(lambda u: u.is_anonymous, '/', redirect_field_name=None)

urlpatterns = [
    path('forgotten',
         anonymous_only(auth_views.PasswordResetView.as_view(
             template_name='account/forgotten.html',
             subject_template_name='account/password_reset_email_subject.txt',
             email_template_name='account/password_reset_email_body.html',
         )),
         name="forgotten_login"),
    path('forgotten/done', anonymous_only(
        auth_views.PasswordResetDoneView.as_view(template_name='account/reset_sent.html')), name="password_reset_done"),
    url(r'^reset/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        auth_views.PasswordResetConfirmView.as_view(template_name="account/reset_password.html"),
        name='password_reset_confirm'),
    path('reset/done', auth_views.PasswordResetCompleteView.as_view(template_name="account/reset_complete.html"),
         name='password_reset_complete'),
]