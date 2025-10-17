from rest_framework import serializers
from django.contrib.auth import authenticate
from .models import UserModel

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = UserModel
        fields = ['email', 'full_name', 'password']
    def create(self, validated_data):
        user = UserModel.objects.create_user(
            email = validated_data['email'],
            full_name = validated_data['full_name'],
            password = validated_data['password'],
        )
        print(f" OTP for {user.email}:{user.otp}") #OTP print in Terminal
        return user
    
class VerifyOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length = 6)

class ResendOtpSerializer(serializers.Serializer):
    email = serializers.EmailField()

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get('email')
        password = data.get('password')
        user = authenticate(email=email, password=password)
        if user and user.is_active:
            data['user'] = user
            return data
        raise serializers.ValidationError('Invalid credentials')
    
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ChangePasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)




