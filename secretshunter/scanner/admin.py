from django.contrib import admin
from django.utils.html import format_html

from .models import RepositoryScan
from .models import RepositoryWatchlist
from .models import SecretFinding


@admin.register(RepositoryScan)
class RepositoryScanAdmin(admin.ModelAdmin):
    """Admin interface for RepositoryScan model."""

    list_display = [
        "id",
        "repository_full_name",
        "scan_status_badge",
        "secrets_found_count",
        "total_files_scanned",
        "created_by",
        "created_at",
    ]
    list_filter = ["scan_status", "created_at"]
    search_fields = ["repository_owner", "repository_name", "repository_url"]
    readonly_fields = [
        "created_at",
        "completed_at",
        "total_files_scanned",
        "secrets_found_count",
    ]
    date_hierarchy = "created_at"
    ordering = ["-created_at"]

    fieldsets = (
        (
            "Repository Information",
            {
                "fields": (
                    "repository_url",
                    "repository_owner",
                    "repository_name",
                ),
            },
        ),
        (
            "Scan Status",
            {
                "fields": (
                    "scan_status",
                    "created_by",
                    "created_at",
                    "completed_at",
                ),
            },
        ),
        (
            "Results",
            {
                "fields": (
                    "total_files_scanned",
                    "secrets_found_count",
                    "error_message",
                ),
            },
        ),
    )

    @admin.display(
        description="Status",
    )
    def scan_status_badge(self, obj):
        """Display colored status badge."""
        colors = {
            "pending": "gray",
            "in_progress": "blue",
            "completed": "green",
            "failed": "red",
        }
        color = colors.get(obj.scan_status, "gray")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',  # noqa: E501
            color,
            obj.get_scan_status_display(),
        )


@admin.register(SecretFinding)
class SecretFindingAdmin(admin.ModelAdmin):
    """Admin interface for SecretFinding model."""

    list_display = [
        "id",
        "scan",
        "file_path",
        "line_number",
        "secret_type",
        "severity_badge",
        "is_false_positive",
        "created_at",
    ]
    list_filter = [
        "secret_type",
        "severity",
        "is_false_positive",
        "created_at",
    ]
    search_fields = [
        "file_path",
        "context_snippet",
        "scan__repository_owner",
        "scan__repository_name",
    ]
    readonly_fields = [
        "created_at",
        "scan",
        "file_path",
        "line_number",
        "matched_pattern",
    ]
    date_hierarchy = "created_at"
    ordering = ["-created_at"]

    fieldsets = (
        (
            "Finding Location",
            {
                "fields": (
                    "scan",
                    "file_path",
                    "line_number",
                ),
            },
        ),
        (
            "Finding Details",
            {
                "fields": (
                    "secret_type",
                    "matched_pattern",
                    "context_snippet",
                    "severity",
                ),
            },
        ),
        (
            "False Positive Management",
            {
                "fields": (
                    "is_false_positive",
                    "false_positive_reason",
                ),
            },
        ),
        (
            "Metadata",
            {
                "fields": ("created_at",),
            },
        ),
    )

    @admin.display(
        description="Severity",
    )
    def severity_badge(self, obj):
        """Display colored severity badge."""
        colors = {
            "high": "red",
            "medium": "orange",
            "low": "green",
        }
        color = colors.get(obj.severity, "gray")
        return format_html(
            '<span style="background-color: {}; color: white; padding: 3px 10px; border-radius: 3px;">{}</span>',  # noqa: E501
            color,
            obj.get_severity_display(),
        )


@admin.register(RepositoryWatchlist)
class RepositoryWatchlistAdmin(admin.ModelAdmin):
    """Admin interface for RepositoryWatchlist model."""

    list_display = [
        "id",
        "repository_full_name",
        "is_active_badge",
        "scan_interval_display",
        "last_scanned_at",
        "next_scan_at",
        "total_scans",
        "last_secrets_found",
    ]
    list_filter = ["is_active", "scan_interval", "created_at"]
    search_fields = ["repository_owner", "repository_name", "repository_url"]
    readonly_fields = [
        "repository_owner",
        "repository_name",
        "created_at",
        "last_scanned_at",
        "next_scan_at",
        "total_scans",
        "last_secrets_found",
    ]
    date_hierarchy = "created_at"
    ordering = ["-created_at"]

    fieldsets = (
        (
            "Repository Information",
            {
                "fields": (
                    "repository_url",
                    "repository_owner",
                    "repository_name",
                ),
            },
        ),
        (
            "Watchlist Settings",
            {
                "fields": (
                    "is_active",
                    "scan_interval",
                    "added_by",
                ),
            },
        ),
        (
            "Scan Tracking",
            {
                "fields": (
                    "last_scanned_at",
                    "next_scan_at",
                    "last_scan",
                    "total_scans",
                    "last_secrets_found",
                ),
            },
        ),
        (
            "Metadata",
            {
                "fields": ("created_at",),
            },
        ),
    )

    @admin.display(
        description="Active Status",
    )
    def is_active_badge(self, obj):
        """Display active status badge."""
        if obj.is_active:
            return format_html(
                '<span style="background-color: green; color: white; '
                'padding: 3px 10px; border-radius: 3px;">Active</span>',
            )
        return format_html(
            '<span style="background-color: gray; color: white; '
            'padding: 3px 10px; border-radius: 3px;">Inactive</span>',
        )

    @admin.display(
        description="Scan Interval",
    )
    def scan_interval_display(self, obj):
        """Display scan interval."""
        return obj.get_scan_interval_display()
