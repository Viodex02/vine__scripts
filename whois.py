async def run(ctx):
    if ctx.url == "https://google.com":
        ctx.println("this is url rilative to google")
    if "google" in ctx.response.text:
        ctx.println("googled found")
    else:
        ctx.println("pass")
