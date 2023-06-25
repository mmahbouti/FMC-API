import requests
import json
import urllib3
from ipaddress import IPv4Network
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
        #print (name_HA, ftd_name , acl_name,ftd_ip)

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
        
        #["interfaces_ip_address":{"10.252.15.0/24","10.252.16.0/24"}]
        
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
                        #print(interface_ip)
        #print(ip_interfaces_list)
        entity["ip-interfaces"] = ip_interfaces_list
        #print(entity["ip-interfaces"])
        #print(entity)
                #print("---------------------------")
            
        #print("==============================")
    return list_devices_info
    
    
    #print (list_devices_info)
    
    
    '''    
    type_interfaces = ['physicalinterfaces','redundantinterfaces','etherchannelinterfaces','subinterfaces','vlaninterfaces','loopbackinterfaces','vniinterfaces']
    
    #aaf366d2-35ff-11ec-8d54-e7545ff76e05
    #e276abec-e0f2-11e3-8169-6d9ed49b625f
    #3d3f5ea4-35df-11ec-8fab-bd4ad3c95d86
    interface_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/devices/devicerecords/3d3f5ea4-35df-11ec-8fab-bd4ad3c95d86/physicalinterfaces?expanded=true&limit={limit}&offset={offset}"
    #interface_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/devices/devicerecords/aaf366d2-35ff-11ec-8d54-e7545ff76e05/subinterfaces?expanded=true&limit={limit}&offset={offset}"
    
    interface_response = requests.get(interface_url, headers=headers, verify=False).json()
    #print(interface_response)
    result1 = interface_response['items']
    #print(result1)
    for entity in result1:
        print (entity)

    if pages_count >= 1:
        for i in range (1,10):
            offset = i*1000
            device_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/devices/devicerecords?expanded=true&limit={limit}&offset={offset}"
            device_response = requests.get(device_url, headers=headers, verify=False).json().
            

    #result = []
    #result = result + device_response['items']
    

    for i in range (1,10):
        offset = i*1000
        device_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/devices/devicerecords?expanded=true&limit={limit}&offset={offset}"
        
        if type_address == 'host':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/hosts?expanded=true&limit={limit}&offset={offset}"
        elif type_address == 'fqdn':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/fqdns?expanded=true&limit={limit}&offset={offset}"
        elif type_address == 'network':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/networks?expanded=true&limit={limit}&offset={offset}"
        elif type_address == 'range':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/ranges?expanded=true&limit={limit}&offset={offset}"
        
        device_response = requests.get(device_url, headers=headers, verify=False).json()
        
        if device_response != {'links': {}, 'paging': {'offset': 0, 'limit': 0, 'count': 0, 'pages': 0}}:
            result = result + device_response['items']
        else:
            break
    print(result)

    for entity in result:
        if entity['value'] == value_address:
            print(entity['name'])
            
    
    for entity in result:
        print(entity['name'],entity['value'])
    
    '''


if __name__ == '__main__':

    username = 'mahbouti'
    password = 'K!ng8934'
    fmc_host = '172.16.50.200'
    port = '443'
    api_version = "v1"

    access_token,domain_uuid = generate_token(fmc_host,port,api_version,username,password)

    #print(get_device_information(fmc_host,port,api_version,access_token,domain_uuid))
    
    #print(detect_HA_devices())
    print(get_network_interfaces(fmc_host,port,api_version,access_token,domain_uuid))