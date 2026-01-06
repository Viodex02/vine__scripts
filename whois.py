import os
async def run(ctx):
    if ctx.url == "https://google.com":
        print("found a googleSite")
    else:
        print("some URLs aren't googled here")

    if "google" in ctx.response.text:
        print(f"found some regex")
