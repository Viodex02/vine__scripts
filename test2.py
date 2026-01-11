import httpx
async def run(ctx):
    url = int(input("enter the url"))
    for i in range(0,100):
        resp = httpx.get(url)
        print(resp.status_code)
        
    
