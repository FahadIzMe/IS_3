from django.urls import path

from . import views

urlpatterns = [
    path("health/", views.health, name="health"),
    path("scan/start/", views.scan_start, name="scan-start"),
    path("scan/jobs/", views.scan_job_list, name="scan-job-list"),
    path("scan/jobs/<str:job_id>/", views.scan_job_status, name="scan-job-status"),
    path("firewall/rules/", views.firewall_rules, name="firewall-rule-list-create"),
    path("firewall/rules/<int:pk>/", views.firewall_rule_delete, name="firewall-rule-delete"),
    path("firewall/simulate/", views.firewall_simulate, name="firewall-simulate"),
]
