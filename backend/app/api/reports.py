"""
Report Retrieval and Generation Endpoints.
"""
from fastapi import APIRouter, HTTPException, Response
from backend.app.services.report_service import report_service

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/demo-summary")
def get_demo_summary_report():
    """Returns the comprehensive system demonstration report."""
    return report_service.generate_demo_summary()

@router.get("/markdown/{run_id}")
def get_run_markdown_report(run_id: str):
    """Generates and returns an artifact screening report in markdown format."""
    md_content = report_service.generate_markdown_report(run_id)
    return Response(content=md_content, media_type="text/markdown")
