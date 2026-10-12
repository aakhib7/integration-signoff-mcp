"""Go-live sign-off checks for payment gateway integrations, exposed as an MCP server."""

__version__ = "0.1.0"


def main() -> None:
    from .server import main as run

    run()


__all__ = ["main", "__version__"]
