from django import forms
from django.contrib.auth.models import User
from .models import Document

class DocumentUploadForm(forms.Form):
    title = forms.CharField(max_length=255, required=True, label='Document Title')
    signee_address = forms.RegexField(
        label="Signee Wallet Address",
        regex=r'^0x[a-fA-F0-9]{40}$',
        max_length=42,
        min_length=42,
        required=True,
        error_messages={'invalid': 'Enter a valid Ethereum wallet address (0x...).'}
    )
    file = forms.FileField(required=True, label='Upload Document')
