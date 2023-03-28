import nmap as np

import pandas as pd

# initialize the Nmap scanner
nm = np.PortScanner()


network = "192.168.0.1/24"



# run the Nmap scan to discover open ports on each host
try:
    nm.scan(hosts=network, arguments="-sS -n --min-rate=5000")
except np.PortScannerError as e:
    print("Nmap scan faile: {}".format(e))
    exit()
 
# create an empty list to store the host information
hosts_list = []

# iterate over each host in the scan results and append its MAC, IP, and open port information to the list
for host in nm.all_hosts():
    if nm[host].state() == "up":
        # gather the host's MAC and IP addresses
        if 'mac' in nm[host]['addresses']:
            mac = nm[host]['addresses']['mac']
        else:
            mac = 'unknown'

        if 'ipv4' in nm[host]['addresses']:
            ip = nm[host]['addresses']['ipv4']
        elif 'ipv6' in nm[host]['addresses']:
            ip = nm[host]['addresses']['ipv6']
        else:
            ip = 'unknown'

        # gather the host's open port information
        if 'tcp' in nm[host]:
            open_ports = list(nm[host]['tcp'].keys())
        else:
            open_ports = 'unknown'

        # add the host's information to the list
        hosts_list.append({'Host': host, 'MAC': mac, 'IP': ip, 'Open Ports': open_ports})

# create a pandas DataFrame from the list of hosts
hosts_df = pd.DataFrame(hosts_list)

# iterate over each host in the DataFrame and attempt to discover its OS
for index, row in hosts_df.iterrows():
    host = row['Host']

    
    
   # attempt to discover the OS of the host, and handle any errors that may occur
    
    
    scan_os = nm.scan(hosts=host, arguments="-O")['scan'][host]['osmatch']
    if scan_os:
        
        hosts_df.at[index, 'OS'] = scan_os[0]['name']
    else:
        hosts_df.at[index, 'OS'] = 'Unknown'
         

    

# print the DataFrame
print(hosts_df)