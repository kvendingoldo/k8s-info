import logging
from typing import Any, Dict
from datetime import datetime
import importlib.resources
import json

HTML_TEMPLATE_RESOURCE = "html_template.html"
HTML_TEMPLATE_PACKAGE = "k8s_info.resources"


def render_html_report(data: Dict[str, Any], html_path: str) -> None:
    """Render the HTML report using the template from resources."""
    try:
        import jinja2
    except ImportError:
        logging.error(
            "Jinja2 is required for HTML rendering. Please install it (pip install jinja2). "
            "Skipping HTML report."
        )
        return
    try:
        with importlib.resources.open_text(
            HTML_TEMPLATE_PACKAGE, HTML_TEMPLATE_RESOURCE, encoding="utf-8"
        ) as f:
            template_str = f.read()
    except Exception as e:
        logging.error(f"Could not load HTML template: {e}")
        return
    env = jinja2.Environment(
        loader=jinja2.BaseLoader(), autoescape=jinja2.select_autoescape(["html", "xml"])
    )
    template = env.from_string(template_str)
    timestamp = data.get("timestamp", {})
    now_str = timestamp.get(
        "formatted", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    html = template.render(
        k8s_version=data.get("k8s_version", {}),
        node_count=data.get("nodes", {}).get("count", 0),
        node_details=data.get("nodes", {}).get("details", []),
        docker_images=data.get("docker_images", []),
        resource_counts=data.get("resource_counts", {}),
        crds=data.get("resource_counts", {}).get("crds", {}),
        api_versions=json.dumps(data.get("api_versions", {}), indent=2),
        now=now_str,
        timestamp=timestamp,
        total_cpu=data.get("nodes", {}).get("total_cpu", 0),
        total_memory_mib=data.get("nodes", {}).get("total_memory_mib", 0),
        helm_info=data.get("helm_info", {}),
    )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    logging.info(f"HTML report written to {html_path}")


def render_pdf_report(data: Dict[str, Any], pdf_path: str) -> None:
    """Render a PDF report from the HTML template using WeasyPrint."""
    try:
        from weasyprint import HTML
    except ImportError:
        logging.error(
            "WeasyPrint is required for PDF rendering. Please install it (pip install weasyprint). "
            "Skipping PDF report."
        )
        return
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w", encoding="utf-8") as tmp_html:
        render_html_report(data, tmp_html.name)
        tmp_html.flush()
        HTML(tmp_html.name).write_pdf(pdf_path)
    logging.info(f"PDF report written to {pdf_path}")
