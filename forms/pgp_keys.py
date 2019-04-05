from django import forms

from core.models import PGPKey
from core.validators import name_validators

from datetime import datetime, timedelta


class KeyCreateForm(forms.ModelForm):
    password = forms.CharField(min_length=12, widget=forms.PasswordInput)
    password_confirm = forms.CharField(min_length=12, widget=forms.PasswordInput)
    expire_date = forms.IntegerField(min_value=0, max_value=365)

    class Meta:
        model = PGPKey
        fields = [
            'realname',
            'email',
            'password',
            'expire_date',
        ]

    def clean(self):
        cleaned_data = super().clean()

        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')

        if password and password_confirm:
            if password != password_confirm:
                raise forms.ValidationError('Passwords do not match.')

        return cleaned_data

    def clean_expire_date(self):
        days = self.cleaned_data.get('expire_date')

        return datetime.now() + timedelta(days=days)

    def clean_realname(self):
        realname = self.cleaned_data.get('realname')
        realname = name_validators.string_validate(realname)

        return realname
