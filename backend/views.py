from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.http import JsonResponse
from rest_framework import viewsets, status, fields, parsers
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status, fields
from rest_framework.generics import ListAPIView
from rest_framework.views import APIView
from django.conf import settings
from django.db import IntegrityError
from django.db.models import Sum, F, Q

import datetime
from distutils.util import strtobool


from .models import User, ConfirmEmailToken, ProductInfo, Shop, Address, Order,\
                    OrderItem, Delivery, Category
from .permissions import IsShop
from .serializers import (UserSerializer, PartnerSerializer, ShopSerializer, 
                          OrderItemSerializer, PartnerOrderSerializer, 
                          OrderSerializer, ProductInfoSerializer,
                          DeliverySerializer, AddressSerializer,
                          CategorySerializer, ShopOrderSerializer,
                          UserWithPasswordSerializer)
from .tasks import send_email_task


class UserViewSet(viewsets.GenericViewSet):
    """
    Viewset для работы с покупателями
    """
    queryset = User.objects.filter(type='buyer')
    serializer_class = UserSerializer
    permission_classes = []


    @action(methods=['post'], detail=False, permission_classes=[])
    def register(self, request, *args, **kwargs):
        """
        Регистрация покупателей
        """
        print(request.data)
        # проверяем обязательные аргументы
        required_fields = {'first_name', 'last_name',
                           'email', 'password',
                           'company', 'position',
                           'phone'}
        absent_required_fields = required_fields.difference(request.data)
        if absent_required_fields:
            print('********33*************')
            return JsonResponse(
                {'Status': False,
                 'Errors': f"Не указаны необходимые аргументы: "
                           f"{', '.join(absent_required_fields)}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        print('*********************')
        # проверяем пароль на сложность
        try:
            validate_password(request.data['password'])
        except Exception as password_error:
            return JsonResponse(
                {'Status': False,
                 'Errors': {'password': list(password_error)}},
                status=status.HTTP_400_BAD_REQUEST
            )
        else:
            # проверяем данные для уникальности имени пользователя
            user_serializer = self.get_serializer(data=request.data)
            if user_serializer.is_valid():
                # сохраняем пользователя
                user = user_serializer.save()
                user.set_password(request.data['password'])
                user.save()
                # отправляем письмо с подтверждением почты
                token, _ = ConfirmEmailToken.objects.get_or_create(
                    user_id=user.id
                )
                title = f"Password Reset Token for {token.user.email}"
                message = token.key
                addressee_list = [token.user.email]
                send_email_task(title, message, addressee_list)
                return JsonResponse({'Status': True},
                                    status=status.HTTP_201_CREATED)
            else:
                return JsonResponse(
                    {'Status': False, 'Errors': user_serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

    
    @action(methods=['post'], detail=False, url_path='register/confirm')
    def register_confirm(self, request, *args, **kwargs):
        """
        Подтверждение почтового адреса
        """
        print('*******start', request)
        # проверяем обязательные аргументы
        if not {'email', 'token'}.issubset(request.data):
            print('***********request.data: ', request.data)
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Не указаны все необходимые аргументы'},
                status=status.HTTP_400_BAD_REQUEST
            )

        token = ConfirmEmailToken.objects.filter(
            user__email=request.data['email'],
            key=request.data['token']
        ).first()
        if token:
            token.user.is_active = True
            token.user.save()
            token.delete()
            return JsonResponse({'Status': True})
        else:
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Неправильно указан токен или email'},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(methods=['post'], detail=False)
    def login(self, request, *args, **kwargs):
        """
        Авторизация пользователей
        """

        if not {'email', 'password'}.issubset(request.data):
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Не указаны все необходимые аргументы'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(request, username=request.data['email'],
                            password=request.data['password'])

        if user is not None:
            if user.is_active:
                token, _ = Token.objects.get_or_create(user=user)

                return JsonResponse({'Status': True, 'Token': token.key})

        return JsonResponse(
            {'Status': False, 'Errors': 'Не удалось авторизовать'},
            status=status.HTTP_400_BAD_REQUEST
        )


    @action(methods=['get', 'post'], detail=False, url_path='details',
            permission_classes=[IsAuthenticated])
    def account_details(self, request, *args, **kwargs):
        """
        Получение и изменение данных пользователя
        """
        if request.method == 'GET':
            serializer = self.get_serializer(request.user)
            return Response(serializer.data)
        else:
            if 'password' in request.data:
                errors = {}
                # проверяем пароль на сложность
                try:
                    validate_password(request.data['password'])
                except Exception as password_error:
                    return JsonResponse(
                        {'Status': False,
                         'Errors': {'password': list(password_error)}},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    request.user.set_password(request.data['password'])

            # проверяем остальные данные
            user_serializer = self.get_serializer(request.user,
                                                  data=request.data,
                                                  partial=True)
            if user_serializer.is_valid():
                user_serializer.save()
                return JsonResponse({'Status': True})
            else:
                return JsonResponse(
                    {'Status': False, 'Errors': user_serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )


class AddressViewSet(viewsets.ModelViewSet):
    """
    Viewset для работы с адресами покупателя
    """
    serializer_class = AddressSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return self.request.user.addresses.all()

    def get_serializer(self, *args, **kwargs):
        serializer_class = self.get_serializer_class()
        kwargs.setdefault('context', self.get_serializer_context())
        return serializer_class(*args, user_id=self.request.user.id, **kwargs)



class CategoryView(ListAPIView):
    """
    Класс для просмотра категорий
    """
    queryset = Category.objects.all()
    serializer_class = CategorySerializer


class ShopView(ListAPIView):
    """
    Класс для просмотра списка магазинов
    """
    queryset = Shop.objects.filter(state=True)
    serializer_class = ShopSerializer


class ProductInfoView(APIView):
    """
    Класс для поиска товаров
    """
    queryset = ProductInfo.objects.none()
    serializer_class = ProductInfoSerializer

    def get(self, request, *args, **kwargs):

        query = Q(shop__state=True)
        shop_id = request.query_params.get('shop_id')
        category_id = request.query_params.get('category_id')

        if shop_id:
            query = query & Q(shop_id=shop_id)

        if category_id:
            query = query & Q(product__category_id=category_id)

        # фильтруем дубликаты
        queryset = ProductInfo.objects.filter(
            query
        ).select_related(
            'shop', 'product__category'
        ).prefetch_related(
            'product_parameters__parameter'
        ).distinct()

        serializer = ProductInfoSerializer(queryset, many=True)

        return Response(serializer.data)


class BasketView(APIView):
    """
    Класс для работы с корзиной пользователя
    """
    queryset = Order.objects.none()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Получить корзину
        """

        basket = Order.objects.filter(
            user_id=request.user.id, state='basket'
        ).prefetch_related(
            'ordered_items__product_info__shop',
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).annotate(
            total_sum=Sum(F('ordered_items__quantity') *
                          F('ordered_items__product_info__price'))
        ).distinct()

        serializer = OrderSerializer(basket, many=True)
        return Response(serializer.data)

   
    def post(self, request, *args, **kwargs):
        """
        Добавить позиции в корзину
        """

        items_list = request.data.get('items')
        if not items_list:
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Указаны не все необходимые аргументы'},
                status=status.HTTP_400_BAD_REQUEST
            )

        basket, _ = Order.objects.get_or_create(
            user_id=request.user.id, state='basket'
        )
        objects_created = 0
        for order_item in items_list:
            order_item.update({'order': basket.id})
            serializer = OrderItemSerializer(data=order_item)
            if serializer.is_valid():
                try:
                    serializer.save()
                except IntegrityError as error:
                    return JsonResponse(
                        {'Status': False, 'Errors': str(error)},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                else:
                    objects_created += 1
            else:
                return JsonResponse(
                    {'Status': False, 'Errors': serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

        return JsonResponse(
            {'Status': True, 'Создано объектов': objects_created}
        )

 
    def put(self, request, *args, **kwargs):
        """
        Изменить в корзине количество у указанных позиций.
        Если новое количество равно 0, то позиция будет удалена из корзины.
        """

        items_list = request.data.get('items')
        if not items_list:
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Указаны не все необходимые аргументы'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            basket = Order.objects.get(user_id=request.user.id, state='basket')
        except Order.DoesNotExist:
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Нет заказа со статусом корзины'},
                status=status.HTTP_400_BAD_REQUEST
            )

        objects_updated, deleted_count = 0, 0
        query = Q()
        has_objects_to_delete = False

        for order_item in items_list:
            item_id, qty = order_item.get('id'), order_item.get('quantity')

            if type(item_id) == int and type(qty) == int:
                if qty == 0:
                    query = query | Q(order_id=basket.id, id=item_id)
                    has_objects_to_delete = True
                else:
                    objects_updated += OrderItem.objects.filter(
                        order_id=basket.id, id=item_id
                    ).update(
                        quantity=qty
                    )

        if has_objects_to_delete:
            deleted_count, _ = OrderItem.objects.filter(query).delete()

        if objects_updated or deleted_count:
            return JsonResponse(
                {'Status': True, 'Обновлено объектов': objects_updated,
                 'Удалено объектов': deleted_count}
            )
        else:
            return JsonResponse(
                {'Status': False, 'Errors': 'Нет таких позиций в корзине'},
                status=status.HTTP_400_BAD_REQUEST
            )


class OrderView(APIView):
    """
    Класс для получения и размещения заказов пользователями
    """
    queryset = Order.objects.none()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        """
        Получить мои заказы
        """

        order = Order.objects.filter(
            user_id=request.user.id
        ).exclude(
            state='basket'
        ).prefetch_related(
            'ordered_items__product_info__shop',
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related(
            'address'
        ).annotate(
            total_sum=Sum(F('ordered_items__quantity')
                          * F('ordered_items__product_info__price'))
        ).distinct()

        serializer = OrderSerializer(order, many=True)
        return Response(serializer.data)

    
    def post(self, request, *args, **kwargs):
        """
        Разместить заказ из корзины с указанным адресом доставки.
        Затем отправить почту администратору о новом заказе
        и клиенту об изменении статуса заказа.
        """

        try:
            basket = Order.objects.get(user_id=request.user.id, state='basket')
        except Order.DoesNotExist:
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Нет заказа со статусом корзины'},
                status=status.HTTP_400_BAD_REQUEST
            )

        invalid_deliveries = []
        shops = Shop.objects.filter(
            product_infos__ordered_items__order=basket.id
        ).prefetch_related(
            'product_infos__product__category',
            'product_infos__product_parameters__parameter'

        ).annotate(
            shop_sum=Sum(F('product_infos__ordered_items__quantity')
                         * F('product_infos__price'))
        ).distinct()
        for shop in shops:
            shop_data = ShopOrderSerializer(shop, order_id=basket.id).data
            shop_deliveries = Delivery.objects.filter(shop=shop)
            if not shop_deliveries:
                invalid_deliveries.append(f"{shop_data['name']}: "
                                          f"стоимость доставки недоступна.")
            else:
                shop_delivery = shop_deliveries.filter(
                    min_sum__lte=shop_data['shop_sum']
                ).order_by('-min_sum').first()
                if shop_delivery is None:
                    invalid_deliveries.append(
                        f"{shop_data['name']}: сумма заказа меньше минимальной"
                    )
        if invalid_deliveries:
            return JsonResponse(
                {'Status': False, 'Errors': invalid_deliveries},
                status=status.HTTP_400_BAD_REQUEST
            )

        address_id = request.data.get('address_id')
        if not address_id:
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Не указаны все необходимые аргументы'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if type(address_id) != int:
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Неправильно указаны аргументы'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            basket.address_id = address_id
            basket.state = 'new'
            basket.save()
        except IntegrityError:
            return JsonResponse(
                {'Status': False, 'Errors': 'Адрес не найден'},
                status=status.HTTP_400_BAD_REQUEST
            )
        else:
            # отправляем письмо пользователю об изменении статуса заказа
            title = f"Обновление статуса заказа {basket.id}"
            message = f'Заказ {basket.id} получил статус Новый.'
            addressee_list = [basket.user.email]
            send_email_task(title, message, addressee_list)

            # отправляем письмо администратору о новом заказе
            title = f"Новый заказ от {basket.user}"
            message = (f'Пользователем {basket.user} оформлен '
                       f'новый заказ {basket.id}.')
            addressee_list = [settings.ADMIN_EMAIL]
            send_email_task(title, message, addressee_list)

            return JsonResponse({'Status': True})



class PartnerViewSet(viewsets.GenericViewSet):
    """
    Viewset для работы с поставщиками
    """
    queryset = User.objects.filter(type='shop')
    serializer_class = PartnerSerializer
    permission_classes = [IsAuthenticated, IsShop]

    
    @action(methods=['post'], detail=False, permission_classes=[])
    def register(self, request):
        """
        Регистрация поставщика.
        Отправка письма администратору о регистрации нового поставщика.
        После регистрации администратору необходимо активировать поставщика
        для начала работы.
        """

        # проверка обязательных аргументов
        if not {'email', 'password', 'company'}.issubset(request.data):
            return JsonResponse(
                {'Status': False,
                 'Errors': 'Указаны не все необходимые аргументы'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # проверка пароля на сложность
        try:
            validate_password(request.data['password'])
        except Exception as password_error:
            return JsonResponse(
                {'Status': False,
                 'Errors': {'password': str(password_error)}},
                status=status.HTTP_400_BAD_REQUEST
            )
        else:
            # проверяем данные для уникальности имени пользователя
            partner_serializer = self.get_serializer(data=request.data)
            if partner_serializer.is_valid():
                # сохраняем пользователя
                user = partner_serializer.save()
                user.set_password(request.data['password'])
                user.save()

                # # отправляем письмо с подтверждением почты
                token, _ = ConfirmEmailToken.objects.get_or_create(
                    user_id=user.id
                )
                title = f"Password Reset Token for {token.user.email}"
                message = token.key
                addressee_list = [token.user.email]
                send_email_task(title, message, addressee_list)

                # отправляем письмо администратору
                title = f"Новый поставщик: {user}"
                message = (f"Зарегистрировался новый поставщик: {user}. "
                           f"Для начала работы необходимо его активировать.")
                addressee_list = [settings.ADMIN_EMAIL]
                send_email_task(title, message, addressee_list)

                return JsonResponse({'Status': True},
                                    status=status.HTTP_201_CREATED)
            else:
                return JsonResponse(
                    {'Status': False, 'Errors': partner_serializer.errors},
                    status=status.HTTP_400_BAD_REQUEST
                )

    @action(methods=['post'], detail=False, url_path='update',
            parser_classes=[parsers.MultiPartParser])
    def price_info(self, request):
        """
        Загрузка файла или ссылки для обновления прайс-листа
        """

        data = {'file': None, 'url': None,
                'update_dt': datetime.date.today(), 'is_uptodate': False}
        file = request.FILES.get('file')
        url = request.data.get('url')
        if file:
            data['file'] = file
        if url:
            validate_url = URLValidator()
            try:
                validate_url(url)
            except ValidationError as e:
                return JsonResponse({'Status': False, 'Error': str(e)},
                                    status=status.HTTP_400_BAD_REQUEST)
            data['url'] = url
        else:
            return JsonResponse({'Status': False,
                                 'Error': 'Необходимa ссылка.'},
                                status=status.HTTP_400_BAD_REQUEST)

        shop, created = Shop.objects.get_or_create(user_id=request.user.id)
        if created:
            data['name'] = f"- Актуализируйте прайс-лист -"
        shop_serializer = ShopSerializer(shop, data=data, partial=True)
        if shop_serializer.is_valid():
            shop_serializer.save()

            # отправляем письмо администратору о новом прайс-листе
            title = f"{shop_serializer.data['name']}: обновление прайса"
            message = (f"Пользователь {request.user} сообщил о новом "
                       f"прайс-листе магазина {shop_serializer.data['name']}")
            addressee_list = [settings.ADMIN_EMAIL]
            send_email_task(title, message, addressee_list)

            return JsonResponse({'Status': True})
        else:
            return JsonResponse(
                {'Status': False, 'Errors': shop_serializer.errors},
                status=status.HTTP_400_BAD_REQUEST
            )

    @action(methods=['get', 'post'], detail=False)
    def state(self, request):
        """
        Получение и изменение статуса поставщика
        """

        if request.method == 'GET':
            try:
                shop = request.user.shop
            except Exception as e:
                return JsonResponse(
                    {'Status': False, 'Error': str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )
            else:
                serializer = ShopSerializer(shop)
                return Response(serializer.data)

        else:
            state = request.data.get('state')
            if not state:
                return JsonResponse(
                    {'Status': False,
                     'Errors': 'Указаны не все необходимые аргументы'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                Shop.objects.filter(
                    user_id=request.user.id
                ).update(
                    state=strtobool(state)
                )
                return JsonResponse({'Status': True})
            except ValueError as error:
                return JsonResponse(
                    {'Status': False, 'Errors': str(error)},
                    status=status.HTTP_400_BAD_REQUEST
                )

    # @extend_schema(examples=[PARTNER_ORDERS_RESPONSE])
    @action(detail=False)
    def orders(self, request):
        """
        Просмотр заказов поставщика
        """

        order = Order.objects.filter(
            ordered_items__product_info__shop__user_id=request.user.id
        ).exclude(
            state='basket'
        ).prefetch_related(
            'ordered_items__product_info__shop',
            'ordered_items__product_info__product__category',
            'ordered_items__product_info__product_parameters__parameter'
        ).select_related(
            'user'
        ).annotate(
            total_sum=Sum(F('ordered_items__quantity') *
                          F('ordered_items__product_info__price'))
        ).distinct()

        serializer = PartnerOrderSerializer(order, partner_id=request.user.id,
                                            many=True)
        return Response(serializer.data)

    @action(methods=['get', 'post'], detail=False)
    def delivery(self, request):
        """
        Получение и изменение стоимости доставки
        """

        if request.method == 'GET':
            delivery = Delivery.objects.filter(
                shop=request.user.shop
            ).order_by('min_sum')
            serializer = DeliverySerializer(delivery, many=True)
            return Response(serializer.data)
        else:
            delivery = request.data.get('delivery')
            if not delivery:
                return JsonResponse(
                    {'Status': False,
                     'Errors': 'Указаны не все необходимые аргументы'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            for item in delivery:
                delivery_obj = Delivery.objects.filter(
                    shop=request.user.shop, min_sum=item['min_sum']
                ).first()
                if delivery_obj:
                    delivery_serializer = DeliverySerializer(
                        delivery_obj, data={'cost': item['cost']}, partial=True
                    )
                else:
                    data = {'shop': request.user.shop.id, **item}
                    delivery_serializer = DeliverySerializer(data=data)

                if delivery_serializer.is_valid():
                    delivery_serializer.save()
                    return JsonResponse({'Status': True})
                else:
                    return JsonResponse(
                        {'Status': False,
                         'Errors': delivery_serializer.errors},
                        status=status.HTTP_400_BAD_REQUEST
                    )
