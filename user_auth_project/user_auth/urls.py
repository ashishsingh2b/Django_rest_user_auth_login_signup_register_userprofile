from django.urls import path
from . import views

urlpatterns = [
    # API URLs
    path('api/register/', views.RegisterUser.as_view(), name='register'),
    path('api/login/', views.LoginUser.as_view(), name='login'),
    path('api/profile/', views.UserProfile.as_view(), name='profile'),

 

]
