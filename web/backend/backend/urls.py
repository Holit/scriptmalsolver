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
from backend import views

urlpatterns = [
    #path('',views.hello_world, name='hello_world'),
    #path('api/upload/', views.upload_file, name='upload_file'),
    #path('api/type_scan/',views.type_scan,name ='type_scan'),
    #path('api/analyze/',views.analyze_file,name = 'analyze_file'),
    #path('test', views.test_qiling , name='test_qiling'),
    path('',views.index),
    path('index/',views.index,name='index'),
    path('login/',views.login,name='login'),
    path('submit/',views.submit,name='submit'),
    path('submit_multiple/',views.submit_multiple,name='submit_multiple'),
    path('report/',views.report,name='report'),
    path('analyze/',views.analyze,name='analyze'),
]