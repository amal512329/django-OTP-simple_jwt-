"""core_project URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""



from django.contrib import admin
from django.urls import path,include

from django.contrib.auth.models import User

from django_otp.admin import OTPAdminSite
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_otp.plugins.otp_totp.admin import TOTPDeviceAdmin
from allauth.account.views import ConfirmEmailView
from django.urls import path
from user.views import OTPLoginView
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from user.views import CustomTokenObtainPairView,CustomUserRegistrationView,TOTPRegistrationView
from django.urls import path, re_path
from user.views import CustomEmailConfirmView,CustomLoginView,qrcode_page,FinishAndRedirectView



class OTPAdmin(OTPAdminSite):
   pass

admin_site = OTPAdmin(name='OTPAdmin')
admin_site.register(User)
admin_site.register(TOTPDevice, TOTPDeviceAdmin)



urlpatterns = [
   
   
    path('admin/', admin.site.urls),
    path('dj-rest-auth/', include('dj_rest_auth.urls')),
    path('', include('dj_rest_auth.urls')),
    path('otp/login/', OTPLoginView.as_view(), name='rest_login'),
    path("dj-rest-auth/registration/", include("dj_rest_auth.registration.urls")),
    path("dj-rest-auth/", include("dj_rest_auth.urls")),
    path('custom-login/', CustomLoginView.as_view(), name='custom-login'),
    re_path(
        r'^account-confirm-email/(?P<key>[-:\w]+)/$',
        CustomEmailConfirmView.as_view(),
        name='account_confirm_email',
    ),
    path('',include('user.urls')),
    path('api/token/',CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/v1/',include('user.urls')),
    path('api/totp/register/<int:device_id>/', TOTPRegistrationView.as_view(), name='totp-registration'),
    path('qrcode/', qrcode_page, name='qrcode-page'),
    path('finish_and_redirect/<int:user_id>/<str:username>/', FinishAndRedirectView.as_view(), name='finish_and_redirect'),
  
    
    

  
]
