from django.urls import path
from . import views

urlpatterns = [
    path('login/', views.login_view, name='login'),
    path('okta/login/', views.okta_login_view, name='okta_login'),
    path('okta/callback/', views.oauth_callback, name='okta_callback'),
    path('logout/', views.logout_view, name='logout'),
    path('refresh-token/', views.refresh_token_view, name='refresh_token'),
    path('api/login/', views.api_login, name='api_login'),
]