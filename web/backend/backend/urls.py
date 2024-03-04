"""backend URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path
from .views import upload_file
from .views import type_scan
from .views import analyze_file
from .views import hello_world
from .views import test_qiling

urlpatterns = [
    path('',hello_world, name='hello_world'),
    path('api/upload/', upload_file, name='upload_file'),
    path('api/type_scan/',type_scan,name ='type_scan'),
    path('api/analyze/',analyze_file,name = 'analyze_file'),
    path('test', test_qiling , name='test_qiling')
]