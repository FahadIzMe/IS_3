from django.db import models


class FirewallRule(models.Model):
	ACTION_CHOICES = (
		("allow", "Allow"),
		("deny", "Deny"),
	)

	PROTOCOL_CHOICES = (
		("any", "Any"),
		("tcp", "TCP"),
		("udp", "UDP"),
	)

	action = models.CharField(max_length=8, choices=ACTION_CHOICES)
	source_ip = models.GenericIPAddressField(blank=True, null=True)
	port = models.PositiveIntegerField(blank=True, null=True)
	protocol = models.CharField(max_length=8, choices=PROTOCOL_CHOICES, default="any")
	priority = models.PositiveIntegerField(default=100)
	enabled = models.BooleanField(default=True)
	note = models.CharField(max_length=150, blank=True, default="")
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ["priority", "id"]

	def __str__(self) -> str:
		src = self.source_ip or "any"
		port = self.port if self.port is not None else "any"
		return f"[{self.priority}] {self.action.upper()} {self.protocol.upper()} {src}:{port}"
