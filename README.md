# ssrfInjector
A thorough and reliable scanner to find Blind SSRF or Host Header Injection vulnerabilities
### Installation:
```
wget https://raw.githubusercontent.com/Scara31/ssrfInjector/main/ssrfInjector.py
```
### Manual:
```
python3 ssrfInjector.py -h
```
There are two different types of usage: without the ```-mh``` parameter and with it. By default 6 payloads will be used for every target (via HTTP and HTTPS separately):
```
Payload 0:
A clear payload without any injections just to probe the target

Payload 1:
{"Host":injection}

Payload 2:
{"Host":target+"@"+injection}

Payload 3:
{"Host":injection,"X-Forwarded-Host":target}

Payload 4:
{"Host":target, "X-Forwarded-Host":injection}

Payload 5:
{"Host":target, "X-Forwarded-Host":target+"@"+injection}
```
To use this mode, run the script with such parameters:
```
python3 ssrfInjector.py -f aFileWithYourSubdomainsInTheCurrentDirectory -i yourInjection -o outputFileInTheCurrentDirectory
```
The injection may be just ```127.0.0.1```:
```
python3 ssrfInjector.py -f subdomains -i 127.0.0.1 -o report
```
If you add the ```-mh``` parameter, only the payload below will be used:
```
Payload 6:
{"Host":injection, "Cache-Control":"no-transform", "User-Agent":injection,
"Referer":injection, "X-Forwarded-Host":injection, "X-Forwarded-For": injection,
"Origin":injection}
```
The injection may be your Burp Collaborator Client or your server's URL:
```
python3 ssrfInjector.py -f subdomains -i client.burpcollaborator.net -mh
```

Some other parameters:

```-t``` - the amount of threads, the default it is set to 30, the ideal is 30-50, but I suggest to pick it by yourself

```-d``` - debug mode, useful, if you want to know what's going on under the hood
