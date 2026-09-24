"""API schemas are the domain wire models; re-exported here so routes depend only on api.schemas."""
from app.models.scan import EntityAction, ScanRequest, ScanResult

__all__ = ["EntityAction", "ScanRequest", "ScanResult"]
