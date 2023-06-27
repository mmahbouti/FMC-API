import requests
import json
import urllib3
from ipaddress import IPv4Network
import getpass
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def generate_token(fmc_host,port,api_version,username,password):
    
    auth_url = f"https://{fmc_host}:{port}/api/fmc_platform/{api_version}/auth/generatetoken"

    auth_response = requests.post(auth_url, auth=(username, password), verify=False)

    if auth_response.status_code == 201 or auth_response.status_code == 204:    
        access_token = auth_response.headers.get("X-auth-access-token")
        domain_uuid = auth_response.headers.get("DOMAIN_UUID")
    else:
        print(f"Failed to authenticate with status code: {auth_response.status_code}")
        
    return access_token,domain_uuid

def get_device_information(fmc_host,port,api_version,access_token,domain_uuid):
    
    access_token,domain_uuid = generate_token(fmc_host,port,api_version,username,password)
    headers = {"X-auth-access-token": access_token}
    offset = 0
    limit = 20000
    result=[]

    device_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/devices/devicerecords?expanded=true&limit={limit}&offset={offset}"

    device_response = requests.get(device_url, headers=headers, verify=False).json()
    
    pages_count = (device_response['paging']['pages'])
    result = device_response['items']
    list_result=[]
    for entity in result:
        d={}
        if (entity['metadata']['containerDetails']['type']) == 'DeviceHAPair':
            name_HA = entity['metadata']['containerDetails']['name']
            role_HA = entity['metadata']['containerDetails']['status']
        ftd_name = entity['name']
        acl_name=entity['accessPolicy']['name']
        ftd_ip = entity['hostName']
        ftd_id = entity['id']
        
        d = {"FTD_name":ftd_name, "HA_name":name_HA, "HA_role":role_HA, "FTD_ip":ftd_ip, "FTD_ID":ftd_id, "ACL_name":acl_name}

        list_result.append(d)

    return list_result

def detect_HA_devices():
    
    list_devices_info = get_device_information(fmc_host,port,api_version,access_token,domain_uuid)
    
    list_devices_output=[]
    for entity in list_devices_info:
        if entity["HA_role"] != "Standby": #this FTD is Active & You can add to output list
            list_devices_output.append(entity)
    
    return list_devices_output
    

def get_network_interfaces(fmc_host,port,api_version,access_token,domain_uuid):
    offset = 0
    limit = 20000
    
    type_interfaces = ['physicalinterfaces','redundantinterfaces','etherchannelinterfaces','subinterfaces','loopbackinterfaces','vniinterfaces']
    
    list_devices_info = detect_HA_devices()
    
    access_token,domain_uuid = generate_token(fmc_host,port,api_version,username,password)
    headers = {"X-auth-access-token": access_token}
    
    
    for entity in list_devices_info:
        
        device_id = entity["FTD_ID"]
                
        ip_interfaces_list=[]
        
        for type_interface in type_interfaces:
            interface_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/devices/devicerecords/{device_id}/{type_interface}?expanded=true&limit={limit}&offset={offset}"
            interface_response = requests.get(interface_url, headers=headers, verify=False).json()
            
            if interface_response != {'links': {}, 'paging': {'offset': 0, 'limit': 0, 'count': 0, 'pages': 0}}:
                result =  interface_response['items']
                
                for x in result:
                    interfaces_ip_address = []
                    if ("ipv4" in x) and (x["ipv4"] !=  {'static': {}}):
                        network_id = (x["ipv4"]['static']['address'])
                        netmask = (x["ipv4"]['static']['netmask'])
                        interface_ip = str(IPv4Network(str(network_id + "/" + netmask), strict=False))
                        ip_interfaces_list.append(interface_ip)
        entity["ip-interfaces"] = ip_interfaces_list
    return list_devices_info
    
    
    #print (list_devices_info)
    
    

if __name__ == '__main__':

    username = input("Enter Your FMC Username : ")
    password = getpass.getpass()
    fmc_host = input("Enter Your FMC IP Address : ")
    port = input("Enter Your FMC Port : ")
    api_version = "v1"

    access_token,domain_uuid = generate_token(fmc_host,port,api_version,username,password)

    #print(get_device_information(fmc_host,port,api_version,access_token,domain_uuid))
    
    #print(detect_HA_devices())
    print(get_network_interfaces(fmc_host,port,api_version,access_token,domain_uuid))