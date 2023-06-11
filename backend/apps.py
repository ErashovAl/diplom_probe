from django.apps import AppConfig


class BackendConfig(AppConfig):
    name = 'backend'

    def ready(self):
        # Implicitly connect signal handlers decorated with @receiver.
        from . import signals
