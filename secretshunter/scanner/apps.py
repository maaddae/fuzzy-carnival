from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class ScannerConfig(AppConfig):
    """Configuration for scanner app."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "secretshunter.scanner"
    verbose_name = _("Scanner")
