from django import forms
from django.contrib.auth.models import User
from .models import Document

class DocumentUploadForm(forms.Form):
    title = forms.CharField(max_length=255, required=False, label='Document Title')
    signee_address = forms.RegexField(
        label="Signee Wallet Address",
        regex=r'^0x[a-fA-F0-9]{40}$',
        max_length=42,
        min_length=42,
        required=False,
        error_messages={'invalid': 'Enter a valid Ethereum wallet address (0x...).'}
    )
    file = forms.FileField(required=True, label='Upload Document')

    def __init__(self, *args, **kwargs):
        use_title_and_signee = kwargs.pop('use_title_and_signee', True)
        super().__init__(*args, **kwargs)
        if not use_title_and_signee:
            del self.fields['title']
            del self.fields['signee_address']
