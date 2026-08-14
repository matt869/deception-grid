"""Outbound notifications for high-severity detections.

Kept dependency-free (stdlib ``urllib`` only) so it adds nothing to the image
and can run inside the API container that already evaluates detection.
"""

from pipeline.alerting.notify import Notifier, notify_new_alerts

__all__ = ["Notifier", "notify_new_alerts"]
