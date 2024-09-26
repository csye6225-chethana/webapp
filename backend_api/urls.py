from django.urls import path
from . import views

urlpatterns = [
    path('healthz', views.health_check, name='health_check'),
    path('healthz/', views.health_check, name='health_check'),
]
