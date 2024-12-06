from django.urls import path
from . import views

urlpatterns = [
    path('cicd', views.health_check, name='health_check'),
    path('cicd/', views.health_check, name='health_check'),

    path('v1/user', views.create_user, name='create_user'),
    path('v1/user/', views.create_user, name='create_user'),

    path('v1/user/self', views.user_detail, name='user_detail'),
    path('v1/user/self/', views.user_detail, name='user_detail'),

    path('v1/user/self/pic', views.profile_pic, name='profile_pic'),
    path('v1/user/self/pic/', views.profile_pic, name='profile_pic'),

    path('verify/', views.verify_user, name='verify_user'),
]
