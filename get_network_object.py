import requests
import json
import urllib3
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


def get_object_network(fmc_host,port,api_version,access_token,domain_uuid,value_address,type_address):
    
    access_token,domain_uuid = generate_token(fmc_host,port,api_version,username,password)
    headers = {"X-auth-access-token": access_token}
    offset = 0
    limit = 20000
    result=[]
    
    #type_address_list = ['host','fqdn','network','range']
    
    if type_address == 'host':
        network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/hosts?expanded=true&limit={limit}&offset={offset}"
    elif type_address == 'fqdn':
        network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/fqdns?expanded=true&limit={limit}&offset={offset}"
    elif type_address == 'network':
        network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/networks?expanded=true&limit={limit}&offset={offset}"
    elif type_address == 'range':
        network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/ranges?expanded=true&limit={limit}&offset={offset}"


    network_addresses_response = requests.get(network_addresses_url, headers=headers, verify=False).json()
    
    result = []
    result = result + network_addresses_response['items']
    
    for i in range (1,10):
        offset = i*1000
        
        if type_address == 'host':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/hosts?expanded=true&limit={limit}&offset={offset}"
        elif type_address == 'fqdn':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/fqdns?expanded=true&limit={limit}&offset={offset}"
        elif type_address == 'network':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/networks?expanded=true&limit={limit}&offset={offset}"
        elif type_address == 'range':
            network_addresses_url = f"https://{fmc_host}:{port}/api/fmc_config/{api_version}/domain/global/object/ranges?expanded=true&limit={limit}&offset={offset}"
        
        network_addresses_response = requests.get(network_addresses_url, headers=headers, verify=False).json()
        
        if network_addresses_response != {'links': {}, 'paging': {'offset': 0, 'limit': 0, 'count': 0, 'pages': 0}}:
            result = result + network_addresses_response['items']
        else:
            break

    
    for entity in result:
        if entity['value'] == value_address:
            print(entity['name'])
            
    '''
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

    get_object_network(fmc_host,port,api_version,access_token,domain_uuid,'10.253.200.4-10.253.200.6','range')
