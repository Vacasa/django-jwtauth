from django.urls import include, path
from django.conf import settings

from . import views

urlpatterns = [
    path('login', views.LoginView.as_view(), name="login"),
    path('callback', views.CallbackView.as_view(), name="callback"),
    path('logout', views.LogoutView.as_view(), name="logout")
]

if settings.DEBUG:
    """
    The following routes are only added in DEBUG mode. They should never
    be used in production.
    """
    urlpatterns += [
        path('authorize', views.AuthorizeView.as_view(), name="authorize"),
        path('token', views.TokenView.as_view(), name="token")
    ]
