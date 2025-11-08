"""API views for scanner app."""

from django.db import transaction
from rest_framework import mixins
from rest_framework import status
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from secretshunter.scanner.models import RepositoryScan
from secretshunter.scanner.models import SecretFinding
from secretshunter.scanner.tasks import scan_repository_task

from .serializers import IdempotentRepositoryScanSerializer
from .serializers import RepositoryScanListSerializer
from .serializers import RepositoryScanSerializer
from .serializers import SecretFindingSerializer
from .serializers import SecretFindingUpdateSerializer


class RepositoryScanViewSet(
    mixins.CreateModelMixin,
    mixins.RetrieveModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """ViewSet for managing repository scans.

    Supports:
    - POST /api/scans/ - Create new scan
    - GET /api/scans/ - List all scans
    - GET /api/scans/{id}/ - Get scan details with findings
    - PATCH /api/scans/{id}/findings/{finding_id}/ - Update finding

    """

    queryset = RepositoryScan.objects.all().select_related("created_by")
    serializer_class = RepositoryScanSerializer
    permission_classes = [AllowAny]  # Allow anonymous scans for now

    def get_serializer_class(self):
        """Return appropriate serializer based on action.

        Returns:
            Serializer class.

        """
        if self.action == "list":
            return RepositoryScanListSerializer
        if self.action == "create_idempotent":
            return IdempotentRepositoryScanSerializer
        return RepositoryScanSerializer

    def get_queryset(self):
        """Get queryset with optimizations based on action.

        Returns:
            Optimized queryset.

        """
        queryset = super().get_queryset()

        # For detail view, prefetch findings
        if self.action == "retrieve":
            queryset = queryset.prefetch_related("findings")

        return queryset

    def perform_create(self, serializer):
        """Create scan and trigger async scanning task.

        Args:
            serializer: Validated serializer instance.

        """
        # Save the scan
        scan = serializer.save()

        # Trigger async Celery task after transaction commits
        # This ensures the scan exists in the database before the worker
        # tries to fetch it
        transaction.on_commit(lambda: scan_repository_task.delay(scan.id))

    def create(self, request, *args, **kwargs):
        """Create a new scan and return immediately.

        Args:
            request: HTTP request.
            args: Positional arguments.
            kwargs: Keyword arguments.

        Returns:
            Response with scan details.

        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)

        headers = self.get_success_headers(serializer.data)

        return Response(
            {
                **serializer.data,
                "message": (
                    "Scan initiated successfully. Check status using the provided ID."
                ),
            },
            status=status.HTTP_201_CREATED,
            headers=headers,
        )

    @action(
        detail=False,
        methods=["post"],
        url_path="idempotent",
        serializer_class=IdempotentRepositoryScanSerializer,
    )
    def create_idempotent(self, request):
        """Create or reuse a scan with idempotency checks.

        This endpoint implements smart idempotency:
        1. Fetches latest commit SHA from GitHub
        2. Returns existing scan if commit SHA matches (true idempotency)
        3. Returns in-progress scan if one exists
        4. Creates new scan only if none of above conditions met

        Query Parameters:
            force_rescan (bool): Bypass idempotency checks and create new scan.

        Request Body:
            repository_url (str): GitHub repository URL to scan.

        Returns:
            Response with scan details and reuse information.

        Example:
            POST /api/scans/idempotent/
            {
                "repository_url": "https://github.com/owner/repo"
            }

            Response:
            {
                "id": 123,
                "repository_url": "https://github.com/owner/repo",
                "commit_sha": "abc123...",
                "scan_status": "completed",
                "reused": true,
                "reused_reason": "Exact commit SHA match - repository unchanged",
                ...
            }

        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Save (creates new or returns existing)
        scan = serializer.save()

        # Check if scan was reused
        reused = getattr(scan, "_reused", False)

        # Only trigger Celery task if it's a new scan
        # Use transaction.on_commit to ensure scan is committed before worker fetches it
        if not reused:
            transaction.on_commit(lambda: scan_repository_task.delay(scan.id))

        headers = self.get_success_headers(serializer.data)

        # Prepare response message
        if reused:
            reused_reason = getattr(scan, "_reused_reason", "Existing scan found")
            message = f"Reusing existing scan: {reused_reason}"
            response_status = status.HTTP_200_OK
        else:
            message = (
                "New scan initiated successfully. Check status using the provided ID."
            )
            response_status = status.HTTP_201_CREATED

        return Response(
            {
                **serializer.data,
                "message": message,
            },
            status=response_status,
            headers=headers,
        )

    @action(
        detail=True,
        methods=["patch"],
        url_path="findings/(?P<finding_id>[^/.]+)",
        serializer_class=SecretFindingUpdateSerializer,
    )
    def update_finding(self, request, pk=None, finding_id=None):
        """Update a specific finding (e.g., mark as false positive).

        Args:
            request: HTTP request.
            pk: Scan ID.
            finding_id: Finding ID.

        Returns:
            Response with updated finding.

        """
        try:
            # Get the scan
            scan = self.get_object()

            # Get the finding for this scan
            finding = SecretFinding.objects.get(id=finding_id, scan=scan)

            # Update the finding
            serializer = self.get_serializer(finding, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            # Return the full finding details
            return Response(
                SecretFindingSerializer(finding).data,
                status=status.HTTP_200_OK,
            )

        except SecretFinding.DoesNotExist:
            return Response(
                {"detail": "Finding not found for this scan."},
                status=status.HTTP_404_NOT_FOUND,
            )

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        """Get all findings for a scan with filtering and pagination.

        Args:
            request: HTTP request.
            pk: Scan ID.

        Returns:
            Response with filtered findings.

        """
        scan = self.get_object()
        findings = scan.findings.all()

        # Filter by severity
        severity = request.query_params.get("severity")
        if severity:
            findings = findings.filter(severity=severity)

        # Filter by secret type
        secret_type = request.query_params.get("secret_type")
        if secret_type:
            findings = findings.filter(secret_type=secret_type)

        # Filter out false positives
        exclude_false_positives = request.query_params.get(
            "exclude_false_positives",
            "false",
        )
        if exclude_false_positives.lower() == "true":
            findings = findings.filter(is_false_positive=False)

        # Paginate
        page = self.paginate_queryset(findings)
        if page is not None:
            serializer = SecretFindingSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = SecretFindingSerializer(findings, many=True)
        return Response(serializer.data)


class SecretFindingViewSet(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.ListModelMixin,
    viewsets.GenericViewSet,
):
    """ViewSet for managing secret findings.

    Supports:
    - GET /api/findings/ - List all findings
    - GET /api/findings/{id}/ - Get finding details
    - PATCH /api/findings/{id}/ - Update finding (mark false positive)

    """

    queryset = SecretFinding.objects.all().select_related("scan")
    serializer_class = SecretFindingSerializer
    permission_classes = [AllowAny]

    def get_serializer_class(self):
        """Return appropriate serializer based on action.

        Returns:
            Serializer class.

        """
        if self.action in ["update", "partial_update"]:
            return SecretFindingUpdateSerializer
        return SecretFindingSerializer

    def get_queryset(self):
        """Get queryset with optional filters.

        Returns:
            Filtered queryset.

        """
        queryset = super().get_queryset()

        # Filter by severity
        severity = self.request.query_params.get("severity")
        if severity:
            queryset = queryset.filter(severity=severity)

        # Filter by secret type
        secret_type = self.request.query_params.get("secret_type")
        if secret_type:
            queryset = queryset.filter(secret_type=secret_type)

        # Filter by scan
        scan_id = self.request.query_params.get("scan_id")
        if scan_id:
            queryset = queryset.filter(scan_id=scan_id)

        return queryset
