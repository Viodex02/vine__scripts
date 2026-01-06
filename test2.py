from colorama import Fore
async def run(ctx):
  code = ctx.response.status_code
  if code == 200:
    print(f"[+]{Fore.GREEN} found a {code} code")
  elif code = 302:
    print(f"[+]{Fore.YELLOW} found a {code} code")
  else:
    print(f"{Fore.RED}unknow code")
    
    
