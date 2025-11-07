from django.conf import settings
from rest_framework.routers import DefaultRouter
from rest_framework.routers import SimpleRouter

from secretshunter.scanner.api.views import RepositoryScanViewSet
from secretshunter.scanner.api.views import SecretFindingViewSet
from secretshunter.users.api.views import UserViewSet

router = DefaultRouter() if settings.DEBUG else SimpleRouter()

router.register("users", UserViewSet)
router.register("scans", RepositoryScanViewSet, basename="scan")
router.register("findings", SecretFindingViewSet, basename="finding")


app_name = "api"
urlpatterns = router.urls
