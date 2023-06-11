from django.db.models import Sum, F
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

from .models import User, Shop, Product, ProductParameter, \
    ProductInfo, OrderItem, Order, Category, Address, Delivery


class AddressSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        # Don't pass the 'user_id' arg up to the superclass
        user_id = kwargs.pop('user_id', None)

        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        if user_id and kwargs.get('data'):
            self.initial_data['user'] = user_id

    def validate(self, attrs):
        MAX_ADDRESS_COUNT = 5
        address_count = Address.objects.filter(
            user_id=self.initial_data['user']
        ).count()
        if address_count >= MAX_ADDRESS_COUNT:
            raise ValidationError(
                # TODO change error message?
                f'Максимальное количество адресов: {MAX_ADDRESS_COUNT}.'
            )
        return attrs

    class Meta:
        model = Address
        fields = ['id', 'user', 'city', 'street',
                  'house', 'structure', 'building', 'apartment']
        read_only_fields = ['id']
        extra_kwargs = {
            'user': {'write_only': True}
        }



class PartnerSerializer(serializers.ModelSerializer):
    is_active = serializers.BooleanField(default=False)
    type = serializers.CharField(default='shop', write_only=True)
    address = AddressSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'last_name', 'first_name', 'company', 'position', 
                  'phone', 'address', 'type', 'is_active']
        read_only_fields = ['id']


class UserSerializer(serializers.ModelSerializer):
    address = AddressSerializer(read_only=True, many=True)

    class Meta:
        model = User
        fields = ['id', 'email', 'password', 'last_name', 
                  'first_name', 'company', 'position', 
                  'phone', 'address']
        read_only_fields = ['id']


class UserWithPasswordSerializer(serializers.ModelSerializer):
    password = serializers.CharField(required=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'last_name', 'first_name',
                  'company', 'position', 'phone']



class DeliverySerializer(serializers.ModelSerializer):

    class Meta:
        model = Delivery
        fields = ['shop', 'min_sum', 'cost']
        extra_kwargs = {
            'shop': {'write_only': True},
        }


class ShopStateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Shop
        fields = ['id', 'name', 'state']


class ShopSerializer(serializers.ModelSerializer):
    delivery = DeliverySerializer(read_only=True, many=True)

    class Meta:
        model = Shop
        fields = ['id', 'name', 'state', 'delivery', 'file', 'url',
                  'update_dt', 'is_uptodate']
        read_only_fields = ['id']
        extra_kwargs = {
            'file': {'write_only': True},
            'url': {'write_only': True},
            'update_dt': {'write_only': True},
            'is_uptodate': {'write_only': True},
        }


class ProductSerializer(serializers.ModelSerializer):
    category = serializers.StringRelatedField()

    class Meta:
        model = Product
        fields = ['name', 'category', ]


class ProductParameterSerializer(serializers.ModelSerializer):
    parameter = serializers.StringRelatedField()

    class Meta:
        model = ProductParameter
        fields = ['parameter', 'value', ]


class ProductInfoSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)
    product_parameters = ProductParameterSerializer(read_only=True, many=True)
    shop = ShopSerializer(read_only=True)

    class Meta:
        model = ProductInfo
        fields = ['id', 'external_id', 'model', 'product', 'shop', 'quantity',
                  'price', 'price_rrc', 'product_parameters', ]
        read_only_fields = ['id']


class OrderProductInfoSerializer(ProductInfoSerializer):
    class Meta:
        model = ProductInfo
        fields = ['id', 'external_id', 'model',
                  'product', 'product_parameters', 'price', 'price_rrc', ]
        read_only_fields = ['id']


class OrderItemSerializer(serializers.ModelSerializer):
    class Meta:
        model = OrderItem
        fields = ['id', 'quantity', 'product_info', 'order', ]
        read_only_fields = ['id']
        extra_kwargs = {
            'order': {'write_only': True}
        }


class ShopOrderItemSerializer(OrderItemSerializer):
    product_info = OrderProductInfoSerializer(read_only=True)


class ShopOrderSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        # Don't pass the 'order_id' arg up to the superclass
        order_id = kwargs.pop('order_id', None)

        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        self.order_id = order_id

    shop_sum = serializers.IntegerField()

    class Meta:
        model = Shop
        fields = ['id', 'name', 'shop_sum', ]
        read_only_fields = ['id']

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if self.order_id is not None:
            ordered_items = OrderItem.objects.filter(
                product_info__shop=instance.id, order=self.order_id
            )
            ret['ordered_items'] = [ShopOrderItemSerializer(item).data
                                    for item in ordered_items]

        return ret


class OrderSerializer(serializers.ModelSerializer):
    total_sum = serializers.IntegerField()
    address = AddressSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ['id', 'state', 'dt', 'total_sum', 'address']
        read_only_fields = ['id']

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        delivery_costs = []
        invalid_deliveries = []
        shops = Shop.objects.filter(
            product_infos__ordered_items__order=instance.id
        ).annotate(
            shop_sum=Sum(F('product_infos__ordered_items__quantity')
                         * F('product_infos__price'))
        ).distinct()
        ret['shops'] = []
        for shop in shops:
            shop_data = ShopOrderSerializer(shop, order_id=instance.id).data
            shop_deliveries = Delivery.objects.filter(shop=shop)
            if shop_deliveries:
                shop_delivery = shop_deliveries.filter(
                    min_sum__lte=shop_data['shop_sum']
                ).order_by('-min_sum').first()
                if shop_delivery is None:
                    shop_data['delivery'] = (f"{shop_data['name']}: "
                                             f"сумма заказа меньше минимальной.")
                    invalid_deliveries.append(shop_data['delivery'])
                else:
                    shop_data['delivery'] = shop_delivery.cost
                    delivery_costs.append(shop_data['delivery'])
            else:
                shop_data['delivery'] = (f"{shop_data['name']}: "
                                         f"стоимость доставки недоступна.")
                invalid_deliveries.append(shop_data['delivery'])
            ret['shops'].append(shop_data)

        if invalid_deliveries:
            ret['total_delivery'] = invalid_deliveries
        else:
            ret['total_delivery'] = sum(delivery_costs)

        return ret


class PartnerOrderSerializer(serializers.ModelSerializer):
    def __init__(self, *args, **kwargs):
        # Don't pass the 'partner_id' arg up to the superclass
        partner_id = kwargs.pop('partner_id', None)

        # Instantiate the superclass normally
        super().__init__(*args, **kwargs)

        self.partner_id = partner_id

    total_sum = serializers.IntegerField()
    address = AddressSerializer(read_only=True)

    class Meta:
        model = Order
        fields = ['id', 'state', 'dt', 'total_sum', 'address']
        read_only_fields = ['id']

    def to_representation(self, instance):
        ret = super().to_representation(instance)
        if self.partner_id is not None:
            ordered_items = OrderItem.objects.filter(
                product_info__shop__user_id=self.partner_id, order=instance.id
            ).distinct()
            ret['ordered_items'] = [
                ShopOrderItemSerializer(item).data for item in ordered_items
            ]

        return ret


class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = ['id', 'name', ]
        read_only_fields = ['id']
