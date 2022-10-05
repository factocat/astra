import requests

def get(url, ssl, timeout):
	headers = {
		"Connection": "close"
	}

	request_url = site(url, ssl)
	response = requests.get(url=request_url, timeout= timeout, verify= False, headers= headers)
	return response.content


def site(url, ssl):
	url = url.replace("http://", "")
	url = url.replace("https://", "")

	site = f"http://{url}"

	if ssl:
		site = f"https://{url}"

	return site

def https(url, ssl, timeout):
	new_url = "https://" + url
	body = get(new_url, ssl, timeout)

	return body