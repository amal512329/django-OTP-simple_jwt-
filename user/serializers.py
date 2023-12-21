from rest_framework import serializers
from dj_rest_auth.serializers import LoginSerializer
from django.contrib.auth import authenticate
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from django.contrib.auth import login
from django.shortcuts import redirect
from django.urls import reverse
from django.http import HttpResponseRedirect
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer





class SuccessSerializer(serializers.Serializer):
    key = serializers.CharField()

class OTPLoginSerializer(LoginSerializer):

    otp_code = serializers.CharField(required=True)

    def validate_otp_code(self, value):
        # Your validation logic for the OTP code
        if not value:
            raise serializers.ValidationError("OTP code is required.")

        return value

    def validate(self, attrs):
        attrs = super().validate(attrs)

        user = attrs['user']
        otp_code = attrs.get('otp_code')

        # Get the TOTPDevice for the user
        totp_device = TOTPDevice.objects.filter(user=user, confirmed=True).first()

        print("Hello")
        print(totp_device)

        if not totp_device:
            raise serializers.ValidationError("No TOTP device found for the user.")
              
       


        print(f"otp_code: {otp_code}")
        print(f"User: {user}")
        print(f"TOTP Device User: {totp_device.user}")
        # print(f"Before verify_token: {totp_device.verify_token(otp_code)}")
        # Check the OTP code against the TOTP device

        # print(f"Before Condition: {otp_code and totp_device.verify_token(otp_code)}")
        # verification_result = totp_device.verify_token(otp_code)
        # print(f"Inside if condition: {verification_result}")
        
     
        if otp_code and totp_device.verify_token(otp_code):


            # Perform the login, authentication, and token generation here
            print("Success Login")
            token, created = Token.objects.get_or_create(user=user)
            print(f"Authentication Token Key: {token.key}")
           
           
            attrs['token_key'] = token.key  
        
       
        print("Returnin the attrs")
        return attrs
        
          



class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    otp_code = serializers.CharField(write_only=True, required=False)

    def validate(self, attrs):
        otp_code = attrs.get('otp_code', None)

        # Call the base class's validate method to get the token data
        data = super().validate(attrs)

        # If there's an OTP code, validate it
        if otp_code:
            user = self.user

            # Check if the user has an active TOTP device
            totp_device = TOTPDevice.objects.filter(user=user, confirmed=True).first()

            if totp_device and totp_device.verify_token(otp_code):
                # Valid OTP code, return the token data
                return data
            else:
                raise serializers.ValidationError({'otp_code': 'Invalid OTP code'})
        else:
            # No OTP code provided, raise an error
            raise serializers.ValidationError({'otp_code': 'This field is required when using TOTP'})



class UserRegistrationSerializer(serializers.ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('username', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}, 'email': {'required': True}}
