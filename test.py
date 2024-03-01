import subprocess
import time


def send_and_receive_data(host, port, data):
    # Construct the netcat command
    netcat_command = ['nc', '-w', '5', host, str(port)]

    # Start a subprocess to execute the netcat command
    process = subprocess.Popen(netcat_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        # Send data to the server
        process.stdin.write(data.encode())
        #process.stdin.flush()
        time.sleep(1)

        # Read response from the server
        #response = process.stdout.read().decode().strip()
        # Send data again (if needed) with the same pipe
        response="No response this time."
        time.sleep(1)
        
        process.stdin.write(data.encode())
        process.stdin.flush()
        time.sleep(1)

        return response
    except Exception as e:
        print("An error occurred:", e)
        # Log the error or handle it appropriately
        return response
    finally:
        # Close the subprocess and wait for it to terminate
        stdout, stderr = process.communicate()  # Capture stdout and stderr
        if stderr:
            print("Subprocess stderr:", stderr.decode())

# Example usage:
# response = send_and_receive_data("example.com", 1234, "Hello, world!")


host = 'localhost'
port = 1337

to_send="\"....\"<?xml version=\"1.0\"?><Header><NotfType>NEGO_REQ</NotfType><ContentLen>287</ContentLen><DataFormat>XML</DataFormat></Header>"+"\n\n"+"<?xml version=\"1.0\"?><Handshake><VsUUID>45228b37-6292-11ee-b5d1-000c29cdbe04</VsUUID><PolicyName>policy-test-flo</PolicyName><SessionId>d8ad84cc-79dd-11ee-b638-000c29cdbe04</SessionId><ProtVersion><Vers>1.0</Vers><Vers>1.1</Vers><Vers>1.2</Vers><Vers>2.0</Vers></ProtVersion></Handshake>."

print("Request from client:", to_send)

response = send_and_receive_data(host, port, to_send)
print("Response from server:", response)

if response: 
    count = 0
    while True: 
        send_and_receive_data(host, port, to_send)

        count = count + 1
        #print("Count:", count)
        if count > 0:
            break

import subprocess
import time


def send_and_receive_data(host, port, data):
    # Construct the netcat command
    netcat_command = ['nc', '-w', '5', host, str(port)]

    # Start a subprocess to execute the netcat command
    process = subprocess.Popen(netcat_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        # Send data to the server
        process.stdin.write(data.encode())
        #process.stdin.flush()
        time.sleep(1)

        # Read response from the server
        #response = process.stdout.read().decode().strip()
        # Send data again (if needed) with the same pipe
        response="No response this time."
        time.sleep(1)
        
        process.stdin.write(data.encode())
        process.stdin.flush()
        time.sleep(1)
        process.stdin.write(data.encode())
        process.stdin.flush()
        time.sleep(1)
        process.stdin.write(data.encode())
        process.stdin.flush()
        time.sleep(1)


        return response
    except Exception as e:
        print("An error occurred:", e)
        # Log the error or handle it appropriately
        return response
    finally:
        # Close the subprocess and wait for it to terminate
        stdout, stderr = process.communicate()  # Capture stdout and stderr
        if stderr:
            print("Subprocess stderr:", stderr.decode())

# Example usage:
# response = send_and_receive_data("example.com", 1234, "Hello, world!")


host = 'localhost'
port = 1337

to_send="\"....\"<?xml version=\"1.0\"?><Header><NotfType>SCREEN_REQ</NotfType><ContentLen>1224</ContentLen><DataFormat>XML</DataFormat></Header>"+"\n\n"+"<?xml version=\"1.0\"?><FscreenReq><ReqId>4996</ReqId><ReqType>SMB_REN</ReqType><NotfInfo><SmbRenReq><CommonInfo><ProtCommonInfo><ClientIp>10.202.17.170</ClientIp><GenerationTime>1707492532045224</GenerationTime><UsrIdType>MAPPED_ID</UsrIdType><UsrContext><MappedId><Uid>65534</Uid><WinSid>S-1-5-21-1390067357-2139871995-682003330-305426</WinSid></MappedId></UsrContext><FileOwner><WinSid>S-1-5-21-1390067357-2139871995-682003330-305426</WinSid></FileOwner><AccessPath><Path><PathNameType>WIN_NAME</PathNameType><PathName>\renamed6.txt</PathName></Path><Path><PathNameType>UNIX_NAME</PathNameType><PathName>/renamed6.txt</PathName></Path></AccessPath><VolMsid>2147830405</VolMsid><FileSize>0</FileSize><NumHardLnk>1</NumHardLnk><IsOfflineAttr>0</IsOfflineAttr><FileType>FILE</FileType><IsSparse>0</IsSparse><IsDense>0</IsDense></ProtCommonInfo><DisplayPath>\\NLABNASC9003\test123\renamed6.txlayPath><ProtVer><MajorNum>3</MajorNum><MinorNum>1</MinorNum></ProtVer></CommonInfo><TargetAccessPath><Path><PathNameType>WIN_NAME</PathNameType><PathName>\renamed66.txt</PathName></Path><Path><PathNameType>UNIX_NAME</PathNameType><PathName>/renamed66.txt</PathName></Path></TargetAccessPath></SmbRenReq></NotfInfo></FscreenReq>"

print("Request from client:", to_send)

response = send_and_receive_data(host, port, to_send)
print("Response from server:", response)

if response: 
    count = 0
    while True: 
        send_and_receive_data(host, port, to_send)

        count = count + 1
        #print("Count:", count)
        if count > 0:
            break