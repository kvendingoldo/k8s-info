def parse_memory_k8s(mem_str: str) -> int:
    """Convert Kubernetes memory string to MiB."""
    if mem_str.endswith("Ki"):
        return round(int(mem_str[:-2]) / 1024)
    if mem_str.endswith("Mi"):
        return int(mem_str[:-2])
    if mem_str.endswith("Gi"):
        return int(float(mem_str[:-2]) * 1024)
    try:
        return round(int(mem_str) / (1024 * 1024))
    except Exception:
        return 0
