# from celery import shared_task
from django.conf import settings
from django.core.mail import EmailMultiAlternatives

from .models import Category, ProductInfo, Product, Parameter, \
    ProductParameter, Shop


# @shared_task()
def send_email_task(title, message, addressee_list,
                    sender=settings.EMAIL_HOST_USER):
    # send an e-mail to the user
    msg = EmailMultiAlternatives(title, message, sender, addressee_list)
    msg.send()


# @shared_task()
def do_import_task(shop_id, data):
    # TODO select_related and prefetch_related?
    shop = Shop.objects.get(id=shop_id)

    # TODO clear shop categories?
    for category in data['categories']:
        category_object, _ = Category.objects.get_or_create(
            id=category['id'], name=category['name']
        )
        category_object.shops.add(shop.id)
        category_object.save()
    ProductInfo.objects.filter(shop_id=shop.id).delete()
    for item in data['goods']:
        product, _ = Product.objects.get_or_create(
            name=item['name'], category_id=item['category']
        )

        product_info = ProductInfo.objects.create(
            product_id=product.id,
            external_id=item['id'],
            model=item['model'],
            price=item['price'],
            price_rrc=item['price_rrc'],
            quantity=item['quantity'],
            shop_id=shop.id
        )
        for name, value in item['parameters'].items():
            parameter_object, _ = Parameter.objects.get_or_create(
                name=name
            )
            ProductParameter.objects.create(
                product_info_id=product_info.id,
                parameter_id=parameter_object.id,
                value=value
            )

    shop.name = data['shop']
    shop.is_uptodate = True
    shop.save()


