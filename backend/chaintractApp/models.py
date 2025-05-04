from django.db import models
from django.contrib.auth.models import User
from storages.backends.s3boto3 import S3Boto3Storage

class Document(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending Signature'),
        ('signed', 'Signed'),
        ('rejected', 'Rejected'),
    ]

    owner = models.ForeignKey(User, related_name='owned_documents', on_delete=models.CASCADE)
    signee_address = models.CharField(max_length=42, null=True, blank=True)
    title = models.CharField(max_length=255)
    file = models.FileField(upload_to='uploads/', storage=S3Boto3Storage(), null=True, blank=True)
    file_hash = models.CharField(max_length=64, blank=True, null=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.title} (Owner: {self.owner.username}, Signee Addr: {self.signee_address})"


class Signature(models.Model):
    document = models.OneToOneField(Document, on_delete=models.CASCADE, related_name='signature')
    signer_address = models.CharField(max_length=42, null=True, blank=True)
    blockchain_tx_hash = models.CharField(max_length=66, blank=True, null=True)
    signed_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Signature for {self.document.title} by {self.signer_address}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    eth_address = models.CharField(max_length=42, unique=True, null=True, blank=True)

    def __str__(self):
        return f"Profile for {self.user.username} ({self.eth_address})"

