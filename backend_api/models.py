from django.db import models
import uuid
from django.utils.timezone import now

class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255) 
    account_created = models.DateTimeField(auto_now_add=True)
    account_updated = models.DateTimeField(auto_now=True)
    is_verified = models.BooleanField(default=False)

    def __str__(self):
        return self.email
    

class Image(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False, unique=True)
    file_name = models.CharField(max_length=255)
    url = models.URLField()
    upload_date = models.DateTimeField(auto_now_add=True)
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='images')


class SentEmail(models.Model):
    user = models.ForeignKey(
        'User',
        on_delete=models.CASCADE,
        related_name='sent_emails',
        to_field='email',
        null=True
    )
    token = models.CharField(max_length=255, unique=True, null=True)
    expiration_time = models.DateTimeField()
    sent_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"Email to {self.user.email} sent at {self.sent_at}"
