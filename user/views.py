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
from django.shortcuts import redirect
import requests
from allauth.account.utils import send_email_confirmation
from allauth.account.models import EmailAddress
from dj_rest_auth.views import LoginView
from PIL import Image
import base64
from dj_rest_auth.views import LoginView as RestAuthLoginView
from base64 import b64encode
from rest_framework_simplejwt.tokens import AccessToken
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes






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


class CustomUserRegistrationView(RegisterView):
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer)

        # No need to call create_totp_device here
        # The signal will automatically add the user to the TOTP device

        # Check if EmailAddress already exists
        email_address, created = EmailAddress.objects.get_or_create(
            user=user,
            email=user.email,
            defaults={'primary': False}
        )

        if not created:
            # If the EmailAddress already exists, update the primary field
            email_address.primary = False
            email_address.save()

        # Send email confirmation
        send_email_confirmation(request, user)

        return Response({'detail': 'Registration successful. An email has been sent for verification.'}, status=status.HTTP_201_CREATED)

    def perform_create(self, serializer):
        user = serializer.save(self.request)
        return user



class CustomTokenObtainPairView(TokenObtainPairView):
    
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            # If the serializer is valid, return the token data
            return Response(serializer.validated_data, status=status.HTTP_200_OK)
        else:
            # If the serializer is not valid, return the validation errors
            return Response(serializer.errors, status=status.HTTP_402_PAYMENT_REQUIRED)





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
    

class CustomLoginView(RestAuthLoginView):
   
    def post(self, request, *args, **kwargs):
        print("test 1: ", request.data)
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']


     
        
        # Generate or retrieve the authentication token
        token, created = Token.objects.get_or_create(user=user)

        # Get the user's TOTP device
        totp_device = TOTPDevice.objects.filter(user=user).first()

        if totp_device:
            # Generate QR code
            qr_code_img = qrcode.make(totp_device.config_url)
            buffer = BytesIO()
            qr_code_img.save(buffer)
            buffer.seek(0)
            encoded_img = b64encode(buffer.read()).decode()
            qr_code_data = f'data:image/png;base64,{encoded_img}'
            access_token_data = {
                "qr": qr_code_data,
                "username": user.username,
                'user_id': user.id,
            }
            access_token = AccessToken.for_user(user)
            access_token.payload.update(access_token_data)

            # Return the JWT access token
            return Response({'access_token': str(access_token)}, status=status.HTTP_200_OK)
            # return render(request, 'qrcode.html', {'qr_code_data': qr_code_data,'username': user.username, 'user_id': user.id})
        else:
            return Response({'message': 'User has no TOTP device'}, status=status.HTTP_400_BAD_REQUEST)

    def generate_qr_code(self, totp_url):
        
        
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(totp_url)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer)
        # qr_code_image = base64.b64encode(buffer.getvalue()).decode()



        encoded_img = b64encode(buffer.read()).decode()
        qr_code_data = f'data:image/png;base64,{encoded_img}'

        print("QR CODE is printing")

        print(qr_code_data)

        return qr_code_data
        
    
    





class CustomEmailConfirmView(APIView):

    
    def get(self, request, key):
        
        

        verify_email_url = 'http://localhost:8000/dj-rest-auth/registration/verify-email/'

        # Make a POST request to the verify-email endpoint with the key
        response = requests.post(verify_email_url, {'key': key})

        if response.status_code == 200:
            # Redirect to the login URL
            redirect_url = reverse('custom-login')  # Assuming 'custom-login' is the name of your custom login URL
            return HttpResponseRedirect(redirect_url)
        else:
            return Response({'message': 'Email verification failed'}, status=status.HTTP_400_BAD_REQUEST)
        


def qrcode_page(request):
    key = request.GET.get('key', '')
    user_id = request.GET.get('user_id', '')
    username = request.GET.get('username', '')
    qr_code_image = request.GET.get('qr_code_data', '')
   

    return render(request, 'qrcode.html', {
        'key': key,
        'user_id': user_id,
        'username': username,
        'qr_code_image': qr_code_image,
    })



from django.views import View
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth import get_user_model
from django.http import HttpResponseNotFound
from django.views.decorators.csrf import csrf_exempt

UserModel = get_user_model()



# @method_decorator(csrf_exempt, name='dispatch')
# @permission_classes([IsAuthenticated])
class FinishAndRedirectView(APIView):
    print("first")
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        # Get user ID and username from the POST data
        # user_id = request.POST.get('user_id')
        # username = request.POST.get('username')

        # # Check if the user exists
        # try:
        #     user = UserModel.objects.get(id=user_id, username=username)
        # except UserModel.DoesNotExist:
        #     return HttpResponseNotFound("User not found")
        print("user: : : ", request.user)
        # Check if the user has a TOTP device
        totp_device = TOTPDevice.objects.filter(user=request.user).first()

        if totp_device:
            # Confirm the TOTP device
            totp_device.confirmed = True
            totp_device.save()

            # Redirect to API token endpoint or any other desired URL
            # Update with your actual URL pattern name
            return Response({'message': 'OTP SUCCESS'}, status=status.HTTP_200_OK)
        else:
            return render(request, 'no_totp_device.html')

    