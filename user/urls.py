
from django.urls import path
from .views import success_page


urlpatterns = [

    path('success-page/', success_page, name='success-page'),
]