from rest_auth.serializers import LoginSerializer
from rest_framework import serializers

class OTPLoginSerializer(LoginSerializer):
    otp_code = serializers.CharField(required=False)