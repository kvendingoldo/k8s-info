# k8s-info

A CLI tool to gather Kubernetes cluster information, including:
- All Kubernetes API versions
- Kubernetes cluster version
- Node count, OS version, CPU, and memory
- List of all Docker images in the cluster

## Installation

### With Python (requires Python 3.8+)

```bash
pip install uv
uv pip install .
```

### With Docker

Build the image:
```bash
docker build -t k8s-info .
```

Run the CLI (mount your kubeconfig if running outside the cluster):
```bash
docker run --rm -v $HOME/.kube:/root/.kube k8s-info
```

## Usage

```bash
k8s-info [--log-level INFO|DEBUG|WARNING|ERROR|CRITICAL]
```

## Development

- Linting: [Ruff](https://github.com/astral-sh/ruff)
  ```bash
  ruff check .
  ```
- Dependency management: [uv](https://github.com/astral-sh/uv)
  ```bash
  uv pip install .
  ```

## License

MIT
