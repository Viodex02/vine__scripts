async def run(ctx):
    ctx.log(f"Testing URL: {ctx.url}")

    if ctx.response.status_code == 200:
        ctx.log("Target is alive ✅")
    else:
        ctx.log(f"Target returned {ctx.response.status_code}")
