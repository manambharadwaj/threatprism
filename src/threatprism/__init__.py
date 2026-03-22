"""ThreatPrism — Multi-framework threat intelligence for AI coding agents."""

from __future__ import annotations

import click


@click.command()
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
    help="MCP transport protocol.",
)
@click.option("--host", default="0.0.0.0", help="Host for HTTP transports.")
@click.option("--port", default=8000, type=int, help="Port for HTTP transports.")
@click.option("-v", "--verbose", is_flag=True, help="Enable verbose logging.")
def cli(transport: str, host: str, port: int, verbose: bool) -> None:
    """Start the ThreatPrism MCP server."""
    from threatprism.server import mcp

    if verbose:
        import logging

        logging.basicConfig(level=logging.DEBUG)

    if transport == "stdio":
        mcp.run(transport="stdio")
    elif transport == "sse":
        mcp.run(transport="sse", host=host, port=port)
    else:
        mcp.run(transport="streamable-http", host=host, port=port)
