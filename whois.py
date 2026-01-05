async def run(ctx):
    if "google.com" in ctx.url:
        ctx.Println("this url is related to google")

    if "google" in ctx.response.text.lower():
        ctx.Println("google found")
    else:
        ctx.Println("pass")
