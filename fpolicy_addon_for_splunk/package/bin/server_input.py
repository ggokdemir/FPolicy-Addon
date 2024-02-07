import import_declare_test

import sys
import json

from splunklib import modularinput as smi

import os
import traceback
import requests
from splunklib import modularinput as smi
from solnlib import conf_manager
from solnlib import log
from solnlib.modular_input import checkpointer
from splunktaucclib.modinput_wrapper import base_modinput  as base_mi 

import socket
import re
import struct
import xml.etree.ElementTree as ET
import json

bin_dir  = os.path.basename(__file__)
app_name = os.path.basename(os.path.dirname(os.getcwd()))

class ModInputSERVER_INPUT(base_mi.BaseModInput): 

    def __init__(self):
        use_single_instance = False
        super(ModInputSERVER_INPUT, self).__init__(app_name, "server_input", use_single_instance) 
        self.global_checkbox_fields = None

    def get_scheme(self):
        scheme = smi.Scheme('server_input')
        scheme.description = 'server_input'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        scheme.add_argument(
            smi.Argument(
                'account',
                required_on_create=True,
            )
        )
        
        return scheme

    def validate_input(self, definition):
        """validate the input stanza"""
        """Implement your own validation logic to validate the input stanza configurations"""
        pass

    def get_app_name(self):
        return "app_name" 

    def collect_events(helper, ew):
        #Start the Add-on Server to listen to the file events.

        base_segment_length = 345
        base_message_length = 219
        policy_name = helper.get_arg("Policy_Name")
        #helper.log_info("\n\n [INFO] Settings for the FPolicy : ["+policy_name+"] \n\n")
        name_length = len(policy_name)
        message_length = base_message_length + name_length

        host = helper.get_arg("Server_IP")
        port = int(helper.get_arg("Server_Port"))
        # socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket
        sock.bind((host, port))
        sock.listen(5)
        # listen for two connection at a time
        helper.log_info(f"\n\n [INFO] Listening on {host}:{port} [FPolicy : "+policy_name+"] \n\n")
        accept_counter = 0

        # get input values
        index=helper.get_arg("index")
        account=helper.get_arg("account")['name']
        
        # wait for the first connection
        client_sock, client_addr = sock.accept()
        accept_counter=accept_counter+1
        helper.log_info(f"\n\n [INFO] (loop:"+str(accept_counter)+") Connection from {client_addr} [FPolicy : "+policy_name+"] \n\n")

        while True:

            #FIXME:
            all_data = ""
            while True:
                raw_data = ""
                # receive text data
                raw_data = client_sock.recv(1024)
                if raw_data: 
                    helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
                    all_data += raw_data.decode()
                    helper.log_info(f"\n\n [INFO] Received all data: {all_data}  [FPolicy : "+policy_name+"] \n\n")
                else: 
                    break

            if all_data:
                #cut the non decode part, then decode
                helper.log_info(f"\n\n [INFO] Data to write {index} index: {all_data}  [FPolicy : "+policy_name+"] \n\n")

                sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=all_data)
                ew.write_event(event)
                helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+all_data+" [FPolicy : "+policy_name+"] \n\n")
            #FIXME:

            # wait for a connection
            client_sock, client_addr = sock.accept()
            accept_counter=accept_counter+1
            helper.log_info(f"\n\n [INFO] (loop:"+str(accept_counter)+") Connection from {client_addr} [FPolicy : "+policy_name+"] \n\n")

            # receive text data
            raw_data = client_sock.recv(1024)
            helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
            #cut the non decode part, then decode
            hex_data = raw_data[6:-1]
            unk_hex_data = raw_data[:6]
            data = hex_data.decode()

            # here edit find the <SessionId>
            tag_start = "<SessionId>"
            tag_end = "</SessionId>"
            pattern = f'{re.escape(tag_start)}(.*?)\s*{re.escape(tag_end)}'
            match_SessionId = re.search(pattern, data)
            # here edit find the <VsUUID>
            tag_start = "<VsUUID>"
            tag_end = "</VsUUID>"
            pattern = f'{re.escape(tag_start)}(.*?)\s*{re.escape(tag_end)}'
            match_VsUUID = re.search(pattern, data)

            if (match_VsUUID and match_SessionId):
                # here edit find the <NotfType>
                tag_start = "<NotfType>"
                tag_end = "</NotfType>"
                pattern = f'{re.escape(tag_start)}(.*?)\s*{re.escape(tag_end)}'
                match_NotfType = re.search(pattern, data)
                result_NotfType = match_NotfType.group(1)
                helper.log_info("\n\n [INFO] NotfType : {}".format(result_NotfType) + " [FPolicy : "+policy_name+"] \n\n")

            if (match_VsUUID and match_SessionId and result_NotfType == 'NEGO_REQ'):
                result_SessionId = match_SessionId.group(1)
                #helper.log_info("\n\n [INFO] SessionId : {}".format(result_SessionId) +" [FPolicy : "+policy_name+"] \n\n")
                result_VsUUID = match_VsUUID.group(1)
                #helper.log_info("\n\n [INFO] VsUUID : {}".format(result_VsUUID) + " [FPolicy : "+policy_name+"] \n\n")

                header_resp = ("<?xml version=\"1.0\"?><Header><NotfType>NEGO_RESP</NotfType><ContentLen>"+str(message_length)+"</ContentLen><DataFormat>XML</DataFormat></Header>")
                # send a header
                #helper.log_info("\n\n [INFO] Header to send : {}".format(header_resp)+" [FPolicy : "+policy_name+"] \n\n")
                # SessionId and VsUUID should change only
                handshake_resp = ("<?xml version=\"1.0\"?><HandshakeResp><VsUUID>" + ("%s" % (result_VsUUID)) + "</VsUUID><PolicyName>"+policy_name+"</PolicyName><SessionId>"+("%s" % (result_SessionId))+"</SessionId><ProtVersion>1.2</ProtVersion></HandshakeResp>")

                try:
                    # send a response
                    #helper.log_info("\n\n [INFO] Response to send : {}".format(header_resp+"\n\n"+handshake_resp)+" [FPolicy : "+policy_name+"] \n\n")
                    #the size of the input string
                    size = len(header_resp+"\n\n"+handshake_resp)
                    #helper.log_info("\n\n [INFO] Size of the segment : "+str(size) +" [FPolicy : "+policy_name+"] \n\n")
                    # the size in big-endian format
                    size_bytes = struct.pack('>I', size)
                    # the size bytes and the original string
                    to_send ="\"".encode('utf-8') + size_bytes + "\"".encode('utf-8') +(header_resp+"\n\n"+handshake_resp).encode('utf-8')

                    # the results
                    client_sock.send(to_send)
                    complete = to_send
                    helper.log_info("\n\n [INFO] Complete the segment sent below  [FPolicy : "+policy_name+"] : \n")
                    helper.log_info((complete))
                    helper.log_info("\n [INFO] Please confirm if handshake is/was successful by using FPolicy console. [FPolicy : "+policy_name+"] \n\n")
                except IOError as err:
                    helper.log_error('\n\n [ERROR] IO Error (Handshake) ' + str(err)+" [FPolicy : "+policy_name+"] \n\n")

                try:
                    #FIXME:
                    all_data = ""
                    while True:
                        raw_data = ""
                        # receive text data
                        raw_data = client_sock.recv(1024)
                        if raw_data: 
                            helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
                            all_data += raw_data.decode()
                            helper.log_info(f"\n\n [INFO] Received all data: {all_data}  [FPolicy : "+policy_name+"] \n\n")
                        else: 
                            break

                    if all_data:
                        #cut the non decode part, then decode
                        helper.log_info(f"\n\n [INFO] Data to write {index} index: {all_data}  [FPolicy : "+policy_name+"] \n\n")

                        sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                        event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=all_data)
                        ew.write_event(event)
                        helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+all_data+" [FPolicy : "+policy_name+"] \n\n")
                    #FIXME:

                    client_sock, client_addr = sock.accept()
                    accept_counter=accept_counter+1
                    helper.log_info(f"\n\n [INFO] (loop:"+str(accept_counter)+") Connection from {client_addr} [FPolicy : "+policy_name+"] \n\n")
                    
                    # receive text data
                    raw_data = client_sock.recv(1024)
                    #helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
                    #cut the non decode part, then decode
                    hex_data = raw_data[6:-1]
                    unk_hex_data = raw_data[:6]
                    data = hex_data.decode()
                    
                    sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                    event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=data)
                    ew.write_event(event)
                    helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+data+" [FPolicy : "+policy_name+"] \n\n")
                except IOError as err:
                    helper.log_error("\n\n [ERROR] IO Error - (loop:"+str(accept_counter)+") " + str(err)+" [FPolicy : "+policy_name+"] \n\n")

            # if match_VsUUID and match_SessionId and result_NotfType == 'NEGO_REQ': FALSE
            else:
                #An event came, write that to an Index.
                helper.log_info(f"\n\n [INFO] No match_VsUUID, match_SessionId and match_NotfType == NEGO_REQ. [FPolicy : "+policy_name+"] \n\n")
                data = hex_data.decode()
                #helper.log_info(f"\n\n [INFO] Data to write to an Index: \n {data} \n [FPolicy : "+policy_name+"] \n\n")

                #TRY TO CONVERT JSON
                try:
                    root = ET.fromstring(data)
                    def xml_to_dict(item):
                        if len(item) == 0:
                            return item.text
                        result = {}
                        for i in item:
                            i_data = xml_to_dict(i)
                            if i.tag in result:
                                if type(result[i.tag]) is list:
                                    result[i.tag].append(i_data)
                                else:
                                    result[i.tag] = [result[i.tag], i_data]
                            else:
                                result[i.tag] = i_data
                        return result
                    xml_dict = {root.tag: xml_to_dict(root)}
                    # Convert the Python dictionary to JSON
                    json_data = json.dumps(xml_dict, indent=4)

                    try:
                        sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                        event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=json_data)
                        ew.write_event(event)
                        helper.log_info("\n\n [INFO] Event Inserted in JSON format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+json_data+" [FPolicy : "+policy_name+"] \n\n")
                    except:
                        helper.log_error("\n\n [ERROR] Error inserting JSON event. [FPolicy : "+policy_name+"] \n\n")
                    
                    try:
                        #FIXME:
                        all_data = ""
                        while True:
                            raw_data = ""
                            # receive text data
                            raw_data = client_sock.recv(1024)
                            if raw_data: 
                                helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
                                all_data += raw_data.decode()
                                helper.log_info(f"\n\n [INFO] Received all data: {all_data}  [FPolicy : "+policy_name+"] \n\n")
                            else: 
                                break

                        if all_data:
                            #cut the non decode part, then decode
                            helper.log_info(f"\n\n [INFO] Data to write {index} index: {all_data}  [FPolicy : "+policy_name+"] \n\n")

                            sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                            event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=all_data)
                            ew.write_event(event)
                            helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+all_data+" [FPolicy : "+policy_name+"] \n\n")
                        #FIXME:
                            
                        client_sock, client_addr = sock.accept()
                        accept_counter=accept_counter+1
                        helper.log_info(f"\n\n [INFO] (loop:"+str(accept_counter)+") Connection from {client_addr} [FPolicy : "+policy_name+"] \n\n")

                        # receive text data
                        raw_data = client_sock.recv(1024)
                        #helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
                        #cut the non decode part, then decode
                        hex_data = raw_data[6:-1]
                        unk_hex_data = raw_data[:6]
                        data = hex_data.decode()
                        
                        sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                        event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=data)
                        ew.write_event(event)
                        helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+data+" [FPolicy : "+policy_name+"] \n\n")
                    

                    except IOError as err:
                        helper.log_error('\n\n [ERROR] IO Error - (loop:2)' + str(err)+" [FPolicy : "+policy_name+"] \n\n")
                except:
                    try:
                        sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                        event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=data)
                        ew.write_event(event)
                        helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+data+" [FPolicy : "+policy_name+"] \n\n")
                    except:
                        helper.log_error("\n\n [ERROR] Error inserting XML event. [FPolicy : "+policy_name+"] \n\n")

                try:
                    #FIXME:
                    all_data = ""
                    while True:
                        raw_data = ""
                        # receive text data
                        raw_data = client_sock.recv(1024)
                        if raw_data: 
                            helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
                            all_data += raw_data.decode()
                            helper.log_info(f"\n\n [INFO] Received all data: {all_data}  [FPolicy : "+policy_name+"] \n\n")
                        else: 
                            break

                    if all_data:
                        #cut the non decode part, then decode
                        helper.log_info(f"\n\n [INFO] Data to write {index} index: {all_data}  [FPolicy : "+policy_name+"] \n\n")

                        sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                        event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=all_data)
                        ew.write_event(event)
                        helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+all_data+" [FPolicy : "+policy_name+"] \n\n")
                    #FIXME:

                    client_sock, client_addr = sock.accept()
                    accept_counter=accept_counter+1
                    helper.log_error("\n\n [ERROR] IO Error - (loop:"+str(accept_counter)+") " + str(err)+" [FPolicy : "+policy_name+"] \n\n")

                    # receive text data
                    raw_data = client_sock.recv(1024)
                    #helper.log_info(f"\n\n [INFO] Received raw data: {raw_data}  [FPolicy : "+policy_name+"] \n\n")
                    #cut the non decode part, then decode
                    hex_data = raw_data[6:-1]
                    unk_hex_data = raw_data[:6]
                    data = hex_data.decode()
                    
                    sourcetype=  policy_name  + "://" + helper.get_input_stanza_names()
                    event = helper.new_event(source=policy_name, index=index, sourcetype=sourcetype , data=data)
                    ew.write_event(event)
                    helper.log_info("\n\n [INFO] Event Inserted in XML format. \n source="+policy_name+", index="+index+", sourcetype="+sourcetype+" , data="+data+" [FPolicy : "+policy_name+"] \n\n")
                except IOError as err:
                    helper.log_error("\n\n [ERROR] IO Error - (loop:"+str(accept_counter)+") " + str(err)+" [FPolicy : "+policy_name+"] \n\n")


    def get_account_fields(self):
        account_fields = []
        return account_fields


    def get_checkbox_fields(self):
        checkbox_fields = []
        return checkbox_fields


    def get_global_checkbox_fields(self):
        if self.global_checkbox_fields is None:
            checkbox_name_file = os.path.join(bin_dir, 'global_checkbox_param.json')
            try:
                if os.path.isfile(checkbox_name_file):
                    with open(checkbox_name_file, 'r') as fp:
                        self.global_checkbox_fields = json.load(fp)
                else:
                    self.global_checkbox_fields = []
            except Exception as e:
                self.log_error('\n\n [ERROR] Get exception when loading global checkbox parameter names. '+ str(e)+" \n\n")
                self.global_checkbox_fields = []
        return self.global_checkbox_fields


if __name__ == '__main__':
    exit_code = ModInputSERVER_INPUT().run(sys.argv)
    sys.exit(exit_code)


