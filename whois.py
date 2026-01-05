async def run(ctx):
    if ctx.url == "https://google.com":
        ctx.print("this is url rilative to google")
    if "google" in ctx.response.text:
        ctx.print("googled found")
    else:
        ctx.log("pass")
