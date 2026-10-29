import asyncio
from mcp.server.fastmcp import FastMCP

server = FastMCP("cmdi-04-vulnerable")


async def _run_convert(opts: str) -> str:
    proc = await asyncio.create_subprocess_shell(
        f"convert /data/in.png {opts} /tmp/out.png",
        stdout=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    return "/tmp/out.png"


@server.tool()
async def convert_image(opts: str) -> str:
    """Convierte /data/in.png aplicando opciones de ImageMagick."""
    return await _run_convert(opts)


if __name__ == "__main__":
    server.run()
