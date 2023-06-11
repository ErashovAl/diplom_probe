from rest_framework.permissions import BasePermission


class IsShop(BasePermission):
    """
    Проверка, является ли пользователь поставщиком.
    """

    def has_permission(self, request, view):
        return request.user.type == 'shop'
