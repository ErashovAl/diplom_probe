from django.conf import settings
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _
from django_rest_passwordreset.tokens import get_token_generator

STATE_CHOICES = (
    ('basket', 'Статус корзины'),
    ('new', 'Новый'),
    ('confirmed', 'Подтвержден'),
    ('assembled', 'Собран'),
    ('sent', 'Отправлен'),
    ('delivered', 'Доставлен'),
    ('canceled', 'Отменен'),
)

USER_TYPE_CHOICES = (
    ('shop', 'Магазин'),
    ('buyer', 'Покупатель'),
)


# Create your models here.


class UserManager(BaseUserManager):
    """
    Миксин для управления пользователями
    """
    use_in_migrations = True

    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    """
    Стандартная модель пользователей
    Без изменений наследуются поля password, last_login, first_name, last_name,
    is_staff, is_active, date_joined
    """
    username = None
    email = models.EmailField(_('email address'), unique=True)
    # patronymic = models.CharField(verbose_name='Отчество',
    #                               max_length=40,
    #                               blank=True)
    company = models.CharField(verbose_name='Компания',
                               max_length=40,
                               blank=True)
    position = models.CharField(verbose_name='Должность',
                                max_length=40,
                                blank=True)
    phone = models.CharField(max_length=20, verbose_name='Телефон')
    type = models.CharField(verbose_name='Тип пользователя',
                            choices=USER_TYPE_CHOICES,
                            max_length=5,
                            default='buyer')

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return (f'"{self.company}" '
                f'{self.last_name} {self.first_name} ')#{self.patronymic}

    class Meta:
        verbose_name = 'Пользователь'
        verbose_name_plural = "Список пользователей"
        ordering = ('company',)


def shop_pricelist_dir_path(instance, filename):
    return f'price_lists/shop_{instance.id}/{filename}'


class Shop(models.Model):
    name = models.CharField(max_length=50, verbose_name='Название')
    url = models.URLField(verbose_name='Ссылка', null=True, blank=True)
    file = models.FileField(upload_to=shop_pricelist_dir_path,
                            verbose_name='Файл',
                            null=True,
                            blank=True)
    update_dt = models.DateField(
        verbose_name='Дата сообщения об обновлении прайс-листа',
        null=True,
        blank=True
    )
    is_uptodate = models.BooleanField(verbose_name='Актуальность прайс-листа',
                                      default=False)
    user = models.OneToOneField(settings.AUTH_USER_MODEL,
                                verbose_name='Пользователь',
                                blank=True,
                                null=True,
                                on_delete=models.CASCADE)
    state = models.BooleanField(verbose_name='статус получения заказов',
                                default=True)

    class Meta:
        verbose_name = 'Магазин'
        verbose_name_plural = "Список магазинов"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class Category(models.Model):
    name = models.CharField(max_length=40, verbose_name='Название')
    shops = models.ManyToManyField(Shop,
                                   verbose_name='Магазины',
                                   related_name='categories',
                                   blank=True)

    class Meta:
        verbose_name = 'Категория'
        verbose_name_plural = "Список категорий"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class Product(models.Model):
    name = models.CharField(max_length=80, verbose_name='Название')
    category = models.ForeignKey(Category,
                                 verbose_name='Категория',
                                 related_name='products',
                                 blank=True,
                                 on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Продукт'
        verbose_name_plural = "Список продуктов"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class ProductInfo(models.Model):
    model = models.CharField(max_length=80, verbose_name='Модель', blank=True)
    external_id = models.PositiveIntegerField(verbose_name='Внешний ИД')
    product = models.ForeignKey(Product,
                                verbose_name='Продукт',
                                related_name='product_infos',
                                blank=True,
                                on_delete=models.CASCADE)
    shop = models.ForeignKey(Shop,
                             verbose_name='Магазин',
                             related_name='product_infos',
                             blank=True,
                             on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(verbose_name='Количество')
    price = models.PositiveIntegerField(verbose_name='Цена')
    price_rrc = models.PositiveIntegerField(
        verbose_name='Рекомендуемая розничная цена'
    )

    class Meta:
        verbose_name = 'Информация о продукте'
        verbose_name_plural = "Список информации о продуктах"
        constraints = [
            models.UniqueConstraint(fields=['product', 'shop', 'external_id'],
                                    name='unique_product_info'),
        ]

    def __str__(self):
        return f"{self.product}"


class Parameter(models.Model):
    name = models.CharField(max_length=40, verbose_name='Название')

    class Meta:
        verbose_name = 'Имя параметра'
        verbose_name_plural = "Список имен параметров"
        ordering = ('-name',)

    def __str__(self):
        return self.name


class ProductParameter(models.Model):
    product_info = models.ForeignKey(ProductInfo,
                                     verbose_name='Информация о продукте',
                                     related_name='product_parameters',
                                     blank=True,
                                     on_delete=models.CASCADE)
    parameter = models.ForeignKey(Parameter,
                                  verbose_name='Параметр',
                                  related_name='product_parameters',
                                  blank=True,
                                  on_delete=models.CASCADE)
    value = models.CharField(verbose_name='Значение', max_length=100)

    class Meta:
        verbose_name = 'Параметр'
        verbose_name_plural = "Список параметров"
        constraints = [
            models.UniqueConstraint(fields=['product_info', 'parameter'],
                                    name='unique_product_parameter'),
        ]

    def __str__(self):
        return f"{self.product_info}: {self.parameter}"


class Address(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             verbose_name='Пользователь',
                             related_name='addresses',
                             on_delete=models.CASCADE)

    city = models.CharField(max_length=50, verbose_name='Город')
    street = models.CharField(max_length=100, verbose_name='Улица')
    house = models.CharField(max_length=15, verbose_name='Дом', blank=True)
    structure = models.CharField(max_length=15, verbose_name='Корпус',
                                 blank=True)
    building = models.CharField(max_length=15, verbose_name='Строение',
                                blank=True)
    apartment = models.CharField(max_length=15, verbose_name='Квартира',
                                 blank=True)

    class Meta:
        verbose_name = 'Адрес пользователя'
        verbose_name_plural = "Список адресов пользователей"

    def __str__(self):
        address_translation = {'street': 'улица', 'house': 'дом',
                               'structure': 'корпус', 'building': 'строение',
                               'apartment': 'квартира'}
        not_empty_parts = [f"{rus} {getattr(self, eng)}"
                           for eng, rus in address_translation.items()
                           if getattr(self, eng)]
        return f"{self.city}, " + ', '.join(not_empty_parts)


class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL,
                             verbose_name='Покупатель',
                             related_name='orders',
                             blank=True,
                             on_delete=models.CASCADE)
    dt = models.DateTimeField(verbose_name='Дата создания', auto_now_add=True)
    state = models.CharField(verbose_name='Статус',
                             choices=STATE_CHOICES,
                             max_length=15)
    address = models.ForeignKey(Address, verbose_name='Адрес',
                                blank=True, null=True,
                                on_delete=models.CASCADE)

    class Meta:
        verbose_name = 'Заказ'
        verbose_name_plural = "Список заказов"
        ordering = ('-dt',)

    def __str__(self):
        return f"Заказ {self.id} от {self.dt}"


class OrderItem(models.Model):
    order = models.ForeignKey(Order,
                              verbose_name='Заказ',
                              related_name='ordered_items',
                              blank=True,
                              on_delete=models.CASCADE)
    product_info = models.ForeignKey(ProductInfo,
                                     verbose_name='Информация о продукте',
                                     related_name='ordered_items',
                                     blank=True,
                                     on_delete=models.CASCADE)
    quantity = models.PositiveIntegerField(verbose_name='Количество')

    class Meta:
        verbose_name = 'Заказанная позиция'
        verbose_name_plural = "Список заказанных позиций"
        constraints = [
            models.UniqueConstraint(fields=['order_id', 'product_info'],
                                    name='unique_order_item'),
        ]

    def __str__(self):
        return f"{self.product_info}"


class Delivery(models.Model):
    shop = models.ForeignKey(Shop,
                             verbose_name='Магазин',
                             related_name='delivery',
                             on_delete=models.CASCADE,
    )
    min_sum = models.IntegerField(verbose_name='Минимальная сумма',
                                  default=0
    )
    cost = models.IntegerField(verbose_name='Стоимоcть доставки')

    class Meta:
        verbose_name = 'Стоимость доставки'
        verbose_name_plural = "Список стоимости доставки"
        ordering = ('shop', 'min_sum')
        constraints = [
            models.UniqueConstraint(fields=['shop', 'min_sum'],
                                    name='unique_shop_min_sum'),
        ]

    def __str__(self):
        return (f"{self.shop}: при заказе от {self.min_sum} "
                f"стоимость доставки {self.cost}")


class ConfirmEmailToken(models.Model):
    class Meta:
        verbose_name = 'Токен подтверждения Email'
        verbose_name_plural = 'Токены подтверждения Email'

    @staticmethod
    def generate_key():
        """
        generates a pseudo random code using os.urandom and binascii.hexlify
        """
        return get_token_generator().generate_token()

    user = models.ForeignKey(
        User,
        related_name='confirm_email_tokens',
        on_delete=models.CASCADE,
        verbose_name=_(
            "The User which is associated to this password reset token"
        )
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name=_("When was this token generated")
    )

    # Key field, though it is not the primary key of the model
    key = models.CharField(
        _("Key"),
        max_length=64,
        db_index=True,
        unique=True
    )

    def save(self, *args, **kwargs):
        if not self.key:
            self.key = self.generate_key()
        return super(ConfirmEmailToken, self).save(*args, **kwargs)

    def __str__(self):
        return "Password reset token for user {user}".format(user=self.user)
