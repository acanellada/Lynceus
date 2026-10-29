import asyncio
from mcp.server.fastmcp import FastMCP

server = FastMCP("cmdi-04-fixed")
ALLOWED_OPTS = {"-resize 50%", "-rotate 90", "-grayscale Rec709Luma"}


async def _run_convert(opts: str) -> str:
    proc = await asyncio.create_subprocess_exec(
        "convert", "/data/in.png", *opts.split(), "/tmp/out.png",
        stdout=asyncio.subprocess.PIPE,
    )
    await proc.communicate()
    return "/tmp/out.png"


@server.tool()
async def convert_image(opts: str) -> str:
    """Convierte /data/in.png aplicando opciones permitidas de ImageMagick."""
    if opts not in ALLOWED_OPTS:
        raise ValueError("opción no permitida")
    return await _run_convert(opts)


if __name__ == "__main__":
    server.run()
