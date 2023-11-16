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
        #Start Server to listen the events.

        import socket
        import re
        host = helper.get_arg("Server_IP")
        port = int(helper.get_arg("Server_Port"))
        # socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # bind the socket
        sock.bind((host, port))
        sock.listen(1)
        # listen for one connection at a time
        helper.log_info(f"\n\n ... Listening on {host}:{port} ... \n\n")
        while True:
            # wait for a connection
            client_sock, client_addr = sock.accept()
            helper.log_info(f"\n\n !! Connection from {client_addr} !! \n\n")
            # receive text data
            raw_data = client_sock.recv(1024)
            helper.log_info(f"\n\n **Received raw data: {raw_data} \n\n")
            #cut the non decode part, then decode
            hex_data = raw_data[6:-1]
            unk_hex_data = raw_data[:6]
            #helper.log_info(f"\n\n **Received hex data: {hex_data} \n\n")
            data = hex_data.decode()
            helper.log_info(f"\n\n **Received data decoded: {data} \n\n")
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
                result_SessionId = match_SessionId.group(1)
                helper.log_info("\n\n >>> SessionId : {}".format(result_SessionId))
                result_VsUUID = match_VsUUID.group(1)
                helper.log_info("\n\n >>> VsUUID : {}".format(result_VsUUID))
                header_resp = ("<?xml version=\"1.0\"?><Header><NotfType>NEGO_RESP</NotfType><ContentLen>234</ContentLen><DataFormat>XML</DataFormat></Header>")
                # send a header
                helper.log_info("\n\n --> Header to send : {}".format(header_resp))
                # SessionId and VsUUID should change only
                handshake_resp = ("<?xml version=\"1.0\"?><HandshakeResp><VsUUID>" + ("%s" % (result_VsUUID)) + "</VsUUID><PolicyName>policy-test-flo</PolicyName><SessionId>"+("%s" % (result_SessionId))+"</SessionId><ProtVersion>1.2</ProtVersion></HandshakeResp>")
                helper.log_info("\n\n --> Handshake response length below: _ \n")
                helper.log_info(len(handshake_resp.encode()))
                try:
                    # send a response
                    helper.log_info("\n\n --> Response to send : {}".format(handshake_resp))
                    # client_sock.send(header_resp.encode()+bytes.fromhex('0a 0a')+handshake_resp.encode())
                    client_sock.send(("""\"\x00\x00\x01\x68\""""+header_resp+"\n\n"+handshake_resp).encode())
                    complete = ("""\"\x00\x00\x01\x68\""""+header_resp+"\n\n"+handshake_resp).encode()
                    helper.log_info("\n\n !!! Complete the segment sent below : _ \n")
                    helper.log_info((complete))
                except IOError as err:
                    helper.log_info('\n\n IO Err.' + str(err))
            else:
                #helper.log_info("\n\n SessionId and VsUUID not found.^^ Check the data above ^^")
                #TODO: An event came, write that to an Index.

                data = hex_data.decode()
                helper.log_info(f"\n\n ===> Data to write: \n {data} \n\n")


                #FIXME:
                # insert input values into the url and/or header (helper class handles credential store)

                index=helper.get_arg("index")
                account=helper.get_arg("account")['name']

                import xml.etree.ElementTree as ET
                import json

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
                    #helper.log_info(f"\n\n ===> Converted to JSON: \n {json_data} \n\n")

                    try:
                        sourcetype=  "server_input"  + "://" + helper.get_input_stanza_names()
                        event = helper.new_event(source="server_input", index=index, sourcetype=sourcetype , data=json_data)
                        helper.log_info("\n\n   (.) JSON Event Inserted (.) \n source="+account+", index="+index+", sourcetype="+sourcetype+" , data="+json_data)
                        ew.write_event(event)
                    except:
                        helper.log_info("\n\n   (!) Error inserting JSON event. (!)  \n\n")

                except:
                    try:
                        sourcetype=  account  + "://" + helper.get_input_stanza_names()
                        event = helper.new_event(source=account, index=index, sourcetype=sourcetype , data=data)
                        helper.log_info("\n\n   (.) XML Event Inserted (.) \n source="+account+", index="+index+", sourcetype="+sourcetype+" , data="+data)
                        ew.write_event(event)
                    except:
                        helper.log_info("\n\n   (!) Error inserting XML event. (!)  \n\n")

                #FIXME: 


                try:
                    # close the socket
                    client_sock.close()
                except IOError as err:
                    helper.log_info('\n\n IO Err.' + str(err))


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
                self.log_error('Get exception when loading global checkbox parameter names. ' + str(e))
                self.global_checkbox_fields = []
        return self.global_checkbox_fields


if __name__ == '__main__':
    exit_code = ModInputSERVER_INPUT().run(sys.argv)
    sys.exit(exit_code)


