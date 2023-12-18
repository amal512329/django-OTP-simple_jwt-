from dj_rest_auth.views import LoginView as DjRestAuthLoginView
from .serializers import OTPLoginSerializer
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import render
from django.contrib.auth import login as django_login
from rest_framework.authtoken.models import Token
from django.http import HttpResponseRedirect,HttpResponse
from django.urls import reverse
from django.shortcuts import redirect
from django_otp.plugins.otp_totp.models import TOTPDevice
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.response import Response
from rest_framework import status
from .serializers import CustomTokenObtainPairSerializer

class OTPLoginView(DjRestAuthLoginView):
    
    serializer_class = OTPLoginSerializer

    def login_user(self, user):
        # Perform the login using Django's authentication
        django_login(self.request, user)

        print("Login User:", user.username, "Authenticated:", self.request.user.is_authenticated)

        # Generate or retrieve the authentication token

        print("Token generated")

        
      

    def get_response_data(self, user):
    # Custom logic to get response data
    # Adjust this according to your requirements
    
       password = self.request.data.get('password', '********')  # Mask the password in the response
       print(password)
       return {
        'user_id': user.id,
        'username': user.username,
        'email': user.email,
        'password': password,
        'otp_code': self.request.data.get('otp_code'),  # Assuming 'otp_code' is in the request data
        # Include any additional user-related data you want in the response
    }

       

    

    def login(self):
        
        print("starting the serializer")
        serializer = self.get_serializer(data=self.request.data)
        print(serializer)
        is_valid = serializer.is_valid(raise_exception=True)
        print(is_valid)
        print("Hey serializer")

        token_key = serializer.validated_data.get('token_key')

        print(token_key)

        
       
        print("serialized")
     

        print("Login Started ")

        # Log in the user
        user = serializer.validated_data['user']
        self.login_user(user)

        print('Login Succesful',self.request,self.request.user)

        print('User authenticated:', self.request.user.is_authenticated)

        
        

        


def success_page(request, token):
    return render(request, 'user/success_page.html', {'token': token})

class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer