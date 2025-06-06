import base64
import os
import requests

def lambda_handler(event, context):

    print(event)

    #######
    # Forward HTTP request to Redirector
    #######

    # Setup forwarding URL
    redirector_target = os.environ.get("REDIRECTOR_TARGET")
	
    url = "https://" + redirector_target + event["requestContext"]["http"]["path"]

    # Parse Query String Parameters
    queryStrings = {}
    if "queryStringParameters" in event.keys():
        for key, value in event["queryStringParameters"].items():
            queryStrings[key] = value

    # Parse HTTP headers
    inboundHeaders = {}
    for key, value in event["headers"].items():
        inboundHeaders[key] = value

    # Handle potential base64 encodng of body
    body = ""
    if "body" in event.keys():
        if event["isBase64Encoded"]:
            body = base64.b64decode(event["body"])
        else:
            body = event["body"]

    # Forward request to Redirector
    requests.packages.urllib3.disable_warnings() 
    
    if event["requestContext"]["http"]["method"] == "GET":
        resp = requests.get(url, headers=inboundHeaders, params=queryStrings, verify=False)
    elif event["requestContext"]["http"]["method"] == "POST":
        resp = requests.post(url, headers=inboundHeaders, params=queryStrings, data=body, verify=False)
    else:
        return "ERROR: INVALID REQUEST METHOD! Must be POST or GET"

    ########
    # Return response to beacon
    ########

    # Parse outbound HTTP headers
    outboundHeaders = {}
    
    for head, val in resp.headers.items():
        outboundHeaders[head] = val

    # build response to beacon
    response = {
        "statusCode": resp.status_code,
        "body": resp.text,
        "headers": outboundHeaders
    }

    return response