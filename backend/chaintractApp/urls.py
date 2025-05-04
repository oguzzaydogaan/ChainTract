from django.urls import path
from django.views.generic import TemplateView
from . import views

app_name = 'chaintractApp'

urlpatterns = [
    path("", views.index, name="index"),
    path("upload/", views.upload_document, name="upload_document"),
    path("documents/owned/", views.document_list_owned, name="document_list_owned"),
    path("documents/to_sign/", views.document_list_to_sign, name="document_list_to_sign"),
    path('login/', TemplateView.as_view(template_name="chaintractApp/login.html"), name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('ajax/get_message/', views.get_message_to_sign, name='get_message'),
    path('ajax/login_signature/', views.login_with_signature, name='login_signature'),
    path('document/<int:document_id>/sign/', views.sign_document, name='sign_document'),
]
