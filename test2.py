import httpx
async def run(ctx):
    url = int(input("enter the url"))
    if url == "any":
        url = 'http://127.0.01:8000'
    else:
        url = url
    for i in range(0,100):
        resp = httpx.get(url)
        print(resp.status_code)
        
    
