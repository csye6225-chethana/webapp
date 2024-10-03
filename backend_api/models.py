from django.db import models
import uuid

class User(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=255) 
    account_created = models.DateTimeField(auto_now_add=True)
    account_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.email
