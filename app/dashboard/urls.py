from django.urls import path

from web import views

urlpatterns = [
    path("", views.overview, name="overview"),
    path("clusters/", views.cluster_list, name="clusters"),
    path("clusters/<str:cid>/", views.cluster_detail, name="cluster"),
    path("attack/", views.attack_matrix, name="attack"),
]
