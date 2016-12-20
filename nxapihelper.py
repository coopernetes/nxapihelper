#!/usr/bin/env python3
import requests
import re
import json
import ipaddress
import socket

DEFAULT_HEADERS = { 'content-type' : 'application/json-rpc' }
ROUTING_COMMANDS = [ "show bgp all neighbors vrf all",
    "show bgp all summary vrf all",
    "show ip ospf",
    "show ip pim rp" ]
INFO_COMMANDS = [ "show cdp neighbor",
    "show hostname",
    "show version" ]
INTERFACE_COMMANDS = [ "show interface" ,
    "show ip interface vrf all" ]
VXLAN_COMMANDS = [ "show nve vrf",
    "show nve peers" ]

class NXAPIHelper(object):
    def __init__(self, device, username, password, use_https=True):
        self.device = self.check_device_validity(device)
        self.username = username
        self.password = password
        self.use_https = use_https

    @staticmethod
    '''
    Upon creating the NXAPI obj, check that the device IP address or DNS name can be resolved
     or is a valid IPv4 address
    '''
    def check_device_validity(device):
        match = re.search(r'^\d+\.\d+\.\d+\.\d+$', device)
        try:
            if match:
                return str(ipaddress.IPv4Address(device))
            else:
                return socket.gethostbyname(device)
        except (socket.gaierror, ipaddress.AddressValueError):
            pass
        raise ValueError("Invalid DNS name or IP address supplied.") from None

    def build_url(self):
        '''
        Create URI used to query NXAPI (http or https based on object.__init__)
        '''
        if self.use_https:
            return "{}{}/ins".format("https://", self.device)
        else:
            return "{}{}/ins".format("http://", self.device)

    def setup_connection(self, headers=DEFAULT_HEADERS):
        '''
        Setup request.session with provided credentials and default headers (JSON)
        '''
        session = requests.Session()
        session.auth = (self.username, self.password)
        session.headers.update(headers)
        return session

    def send_query(self, payload):
        '''
        Main query function. Handles errors returned from NXAPI or if something goes wrong
        '''
        session = self.setup_connection()
        response = None
        error_msg = None
        try:
            response = session.post(self.build_url(),data=json.dumps(payload), verify=False).json()
        except requests.exceptions.ConnectionError as e:
            error_msg = "{}: Connection timed out. Check device IP/name.".format(e.args[0])
            pass
        except json.JSONDecodeError as e:
            error_msg = "{}: No data returned. Check username/password.".format(e.args[0])
            pass
        else:
            if not response:
                error_msg = "No response from server"
            elif type(response) == dict:
                if 'error' in response:
                    error_msg = "Error from server: {}".format(response['error']['message'])
                if response['result'] == None:
                    error_msg = "Response from server is null (is this feature enabled?)"
            else:
                for row in response:
                    if 'error' in row:
                        error_msg = "Error from server: {}".format(row['error']['message'])
                        break
                    elif row['result'] == None:
                        error_msg = "Response from server is null (is this feature enabled?)"
                        break
                    else:
                        continue
        if not error_msg:
            return response
        else:
            raise Exception("{}".format(error_msg))

    def build_payloads(self, list_of_commands):
        '''
        Given a list of CLI commands, builds a list formatted for NXAPI to receive & parsed_result
        '''
        payloads = []
        for index, cmd in enumerate(list_of_commands):
            payloads.append({
                "jsonrpc": "2.0",
                "method": "cli",
                "params": {
                    "cmd": cmd,
                    "version": 1
                },
                "id": index+1
            })
        return payloads

    def send_single_query(self, command):
        '''
        Setup to send a single query to NXAPI
        '''
        return self.scrub_all_results(self.send_query(self.build_payloads([command])))

    def send_multiple_queries(self, commands):
        '''
        Setup to send multiple queries (passed as a list) to NXAPI in a single HTTP/S query
        '''
        return self.scrub_all_results(self.send_query(self.build_payloads(commands)))

    @staticmethod
    def scrub_all_results(results):
        '''
        Removes extraneous JSON data from NXAPI result
        Returns only the body of the response
        '''
        if type(results) == list:
            scrubbed_results = []
            for row in results:
                scrubbed_results.append(row['result']['body'])
            return scrubbed_results
        else:
            return results['result']['body']

    def query_all_bgp_neighbors(self):
        '''
        Send "show bgp all neighbors vrf all" and save query result
        Used by other functions that parse the data
        Only sends a single query and saves the result for additional processing
        '''
        self.all_bgp_neighbors = self.send_single_query(ROUTING_COMMANDS[0])
        return self.all_bgp_neighbors

    def get_bgp_neighbors_evpn(self, result=None):
        '''
        Obtain EVPN BGP neighbors
        '''
        if not result:
            try:
                result = self.all_bgp_neighbors
            except AttributeError:
                result = self.query_all_bgp_neighbors()
        list_of_peers = []
        for row in result['TABLE_neighbor']['ROW_neighbor']:
            try:
                if row['TABLE_af']['ROW_af']['af-afi'] == "25" and row['TABLE_af']['ROW_af']['TABLE_saf']['ROW_saf']['af-safi'] == "70":
                    list_of_peers.append({
                        'neighbor': row['neighbor'],
                        'remoteas': row['remoteas'],
                        'description': row['description']
                    })
            except KeyError:
                continue
        return list_of_peers

    def bgp_neighbors_ipv4(self, result=None):
        '''
        Obtain IPv4 BGP neighbors
        '''
        if not result:
            try:
                result = self.all_bgp_neighbors
                if not result:
                    result = self.query_all_bgp_neighbors()
            except AttributeError:
                result = self.query_all_bgp_neighbors()
        list_of_peers = []
        for row in result['TABLE_neighbor']['ROW_neighbor']:
            try:
                if row['TABLE_af']['ROW_af']['af-afi'] == "1" and row['TABLE_af']['ROW_af']['TABLE_saf']['ROW_saf']['af-safi'] == "1":
                    list_of_peers.append({
                        'neighbor': row['neighbor'],
                        'remoteas': row['remoteas'],
                        'description': row['description']
                    })
            except KeyError:
                continue
        return list_of_peers

    def get_bgp_asn(self, result=None):
        '''
        Obtain BGP ASN
        '''
        if not result:
            result = self.send_single_query(ROUTING_COMMANDS[1])
        if type(result['TABLE_vrf']['ROW_vrf']) == dict:
            return result['TABLE_vrf']['ROW_vrf']['vrf-local-as']
        else:
            return result['TABLE_vrf']['ROW_vrf'][0]['vrf-local-as']

    def vxlan_vrf_single_tenant(self, result=None):
        '''
        Obtain VXLAN VRF for single tenant environments
        '''
        if not result:
            result = self.send_single_query(VXLAN_COMMANDS[0])
        return result['TABLE_nve_vrf']['ROW_nve_vrf']['vrf-name']

    def query_all_cdp_neighbors(self):
        '''
        Send "show cdp neighbors" to NXAPI; saved for further processing
        '''
        self.all_cdp_neighbors = self.send_single_query(INFO_COMMANDS[0])
        return self.all_cdp_neighbors

    def get_cdp_neighbors(self, result=None):
        '''
        Obtain and parse CDP neighbors
        Returns a list of dicts with ['name'] and ['serial_number'] of CDP neighbors
        '''
        if not result:
            try:
                result = self.all_cdp_neighbors
                if not result:
                    result = self.query_all_cdp_neighbors()
            except AttributeError:
                result = self.query_all_cdp_neighbors()
        neighbors = []
        for row in result['TABLE_cdp_neighbor_brief_info']['ROW_cdp_neighbor_brief_info']:
            match_only_name = re.search(r'^\w+', row['device_id'])
            device_name = row['device_id'][match_only_name.start():match_only_name.end()]
            matched_serialnum = re.search(r'\(\w+\)$', row['device_id'])
            if matched_serialnum:
                serial_number = row['device_id'][matched_serialnum.start()+1:matched_serialnum.end()-1]
                neighbors.append({
                    'name': device_name,
                    'serial_number': serial_number,
                })
            else:
                neighbors.append({
                    'name': device_name,
                    'serial_number': 'none',
                })
        return neighbors

    def count_cdp_spines(self, parsed_result=None):
        '''
        Count # of spines seen in CDP output
        Right now, just regex matches on hostnames with "SP" in name
        Will add customizable regex
        '''
        if not parsed_result:
            parsed_result = self.get_cdp_neighbors()
        count = 0
        for neighbor in parsed_result:
            match = re.search(r'^\w+SP\d+$', neighbor["name"])
            if match:
                count += 1
        return count

    def count_cdp_leafs(self, parsed_result=None):
        '''
        Count # of leaf switches seen in CDP output
        Right now, just regex matches on hostnames with "LF" in name
        Will add customizable regex
        '''
        if not parsed_result:
            parsed_result = self.get_cdp_neighbors()
        count = 0
        for neighbor in parsed_result:
            match = re.search(r'^\w+LF\d+$', neighbor["name"])
            if match:
                count += 1
        return count


    def get_ospf_areaid(self, result=None):
        '''
        Obtain the first OSPF area ID. Only useful for switches configured with
         a single area
        '''
        if not result:
            result = self.send_single_query(ROUTING_COMMANDS[2])
        if type(result['TABLE_ctx']['ROW_ctx']['TABLE_area']['ROW_area']) == list:
            for row in result['TABLE_ctx']['ROW_ctx']['TABLE_area']['ROW_area']:
                if 'aname' in row:
                    return row['aname']
                else:
                    continue
        else:
            return result['TABLE_ctx']['ROW_ctx']['TABLE_area']['ROW_area']['aname']

    def get_interface_first_three_octets(self, int_name, result=None):
        '''
        Given an interface name, obtain the first three octets.
        Assumes only the first three octets are important, interprets the subnet
        as X.X.X.0/24
        '''
        if not result:
            result = self.send_single_query(INTERFACE_COMMANDS[1])
        for row in result['TABLE_intf']:
            if row['ROW_intf']['intf-name'] == int_name:
                try:
                    return ipaddress.IPv4Network(row['ROW_intf']['subnet'] + "/24", strict=False)
                except KeyError:
                    continue
            else:
                continue

    def get_prefix_from_hostname(self, result=None):
        '''
        Gets the hostname prefix (first 7 characters)
        Will add custom prefix length
        '''
        if not result:
            result = self.send_single_query(self, INFO_COMMANDS[1])
        return result['hostname'][:7]
