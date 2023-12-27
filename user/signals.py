from django.db.models.signals import post_save
from django.dispatch import receiver
from django_otp.plugins.otp_totp.models import TOTPDevice
from django.contrib.auth import get_user_model
from allauth.account.models import EmailAddress
from allauth.account.models import EmailAddress, EmailConfirmation


@receiver(post_save, sender=get_user_model())
def add_user_to_totp_device(sender, instance, created, **kwargs):
    if created:
        print("User created")
        
        # Add the user to the TOTP device regardless of email verification status
        totp_device = TOTPDevice.objects.create(user=instance, confirmed=False)
        totp_device.save()

        

        print("User added to TOTP device")
    else:
        print("User not Found")
   

