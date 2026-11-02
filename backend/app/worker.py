from celery import Celery

celery_app = Celery(
    "threat_intel_worker",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0",
    include=["app.tasks.enrichment_tasks"]
)