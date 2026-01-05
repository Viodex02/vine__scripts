async def run(ctx):
    if ctx.url == "https://google.com":
        ctx.log("this is url rilative to google")
    if "google" in ctx.response.text:
        ctx.log("googled found")
    else:
        ctx.log("pass")
