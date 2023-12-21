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
from .serializers import CustomTokenObtainPairSerializer,UserRegistrationSerializer
from django.core.mail import send_mail
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework.response import Response
from rest_framework.permissions import AllowAny
from django.shortcuts import get_object_or_404
from django.urls import reverse
import qrcode
from io import BytesIO
from dj_rest_auth.registration.views import RegisterView

from allauth.account.models import EmailConfirmation
from django.shortcuts import redirect
import requests






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




class CustomUserRegistrationView(RegisterView):
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)

        # Your TOTP logic here
        self.create_totp_device(user)

        return Response({'detail': 'Registration successful. An email has been sent for verification.'}, status=status.HTTP_201_CREATED)

    def create_totp_device(self, user):
        # Generate and store TOTP secret for the user
        totp_device = TOTPDevice.objects.create(user=user, confirmed=True)
        totp_device.save()

        email_confirmation_url = self.request.build_absolute_uri(email_confirmation_url)

        # Build the URL for TOTP registration
        totp_registration_url = reverse('totp-registration', kwargs={'device_id': totp_device.id})
        registration_url = self.request.build_absolute_uri(totp_registration_url)
        print(registration_url)

        # Send registration email
        subject = 'Welcome to My Website'
        message = f'Thank you for registering! Click the following link to complete TOTP registration: <a href="{registration_url}" style="color: blue;">{registration_url}</a>'
        from_email = 'amaldq333@gmail.com'
        recipient_list = [user.email]
        send_mail(subject, message, from_email, recipient_list, html_message=message)

    def perform_create(self, serializer):
        user = serializer.save(self.request)
        return user


class TOTPRegistrationView(APIView):
    def get(self, request, device_id, *args, **kwargs):
        totp_device = get_object_or_404(TOTPDevice, id=device_id)
        totp_device.confirmed = True
        totp_device.save()

        # Generate QR code
        totp_url = totp_device.config_url
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_url)
        qr.make(fit=True)

        print("QR code generated")

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer)
        qr_code_image = buffer.getvalue()

        response = HttpResponse(qr_code_image, content_type="image/png")
        response['Content-Disposition'] = 'attachment; filename="qrcode.png"'
        return response
    


class CustomEmailConfirmView(APIView):
    def get(self, request, key):
        verify_email_url = 'http://localhost:8000/dj-rest-auth/registration/verify-email/'

        # Make a POST request to the verify-email endpoint with the key
        response = requests.post(verify_email_url, {'key': key})

        if response.status_code == 200:
            # Redirect to the login URL
            login_url = reverse('token_obtain_pair')  # assuming 'token_obtain_pair' is the name of the login endpoint
            return redirect(login_url)
        else:
            return Response({'message': 'Email verification failed'}, status=status.HTTP_400_BAD_REQUEST)