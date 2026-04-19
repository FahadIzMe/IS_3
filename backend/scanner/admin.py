from django.contrib import admin

from .models import FirewallRule


@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
	list_display = ("id", "priority", "action", "source_ip", "port", "protocol", "enabled")
	list_filter = ("action", "protocol", "enabled")
	search_fields = ("source_ip", "note")

# Register your models here.
