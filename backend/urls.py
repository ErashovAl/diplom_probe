from django.urls import path
from django_rest_passwordreset.views import reset_password_request_token, \
    reset_password_confirm
from rest_framework.routers import DefaultRouter

from .views import PartnerViewSet, UserViewSet, AddressViewSet
from .views import CategoryView, ShopView, ProductInfoView, BasketView, \
    OrderView

router = DefaultRouter()
router.register(r'partner', PartnerViewSet, basename='partner')
router.register(r'user', UserViewSet)
router.register(r'user/addresses', AddressViewSet, basename='user-address')

urlpatterns = [
    path('user/password_reset/', reset_password_request_token, name='password-reset'),
    path('user/password_reset/confirm/', reset_password_confirm, name='password-reset-confirm'),

    path('categories/', CategoryView.as_view(), name='categories'),
    path('shops/', ShopView.as_view(), name='shops'),
    path('products/', ProductInfoView.as_view(), name='products'),
    path('basket/', BasketView.as_view(), name='basket'),
    path('order/', OrderView.as_view(), name='order'),
] + router.urls
