from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('backend_api.urls')), 
]

handler404 = 'backend_api.views.custom_404_view'
