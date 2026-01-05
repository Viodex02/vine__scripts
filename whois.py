## published by Vine team
import os
import whois

def whoisThis(domain):
    domain = domain.replace("http://", "")
    domain = domain.replace("https://", "")
    domain = domain.strip("/")

    try:
        whois_info = whois.whois(domain)
        print(f"{whois_info}\n")
    except Exception as e:
        print(e)
