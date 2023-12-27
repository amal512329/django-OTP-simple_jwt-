

from django.urls import path
from .views import success_page,CustomUserRegistrationView,CustomTokenObtainPairView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,)

urlpatterns = [

    path('success-page/', success_page, name='success-page'),
    path("user/register",CustomUserRegistrationView.as_view()),
    path("user/login",TokenObtainPairView.as_view(),)
]