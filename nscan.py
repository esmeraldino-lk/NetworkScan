import os
import argparse
import socket
import platform
import psutil
import netifaces
import ipaddress
from scapy.all import IP, TCP, sr1
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)
terminal_width = int(os.get_terminal_size().columns)

def print_result(str, subresult=False):
    print(f"{"  |--" if subresult else ""}{Fore.GREEN} [*] {str}{Style.RESET_ALL}")
def print_error(str):
    print(f"{Fore.RED} [!] {str}{Style.RESET_ALL}")
def print_warning(str):
    print(f"{Fore.YELLOW} [.] {str}{Style.RESET_ALL}")
def print_info(str):
    print(f"{Fore.LIGHTBLUE_EX} [>] {str}{Style.RESET_ALL}")

def print_exact_fade(ascii_art):
    lines = ascii_art.splitlines()
    lines = [line for line in lines if line.strip()] 
    total_lines = len(lines)
    
    green_shades = [190, 154, 118, 82, 76, 46, 40, 34, 28, 22]
    
    for i, line in enumerate(lines):
        shade_index = (i * 10) // total_lines
        shade_index = min(shade_index, 9)
        color_code = f"\033[38;5;{green_shades[shade_index]}m"
        
        # Imprime a linha exatamente como ela está na string
        print(f"{color_code}{line}")

def banner():

    def get_interface_name():
        for interface in netifaces.interfaces():
            if interface == 'lo':
                continue
            
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ipv4_info = addrs[netifaces.AF_INET][0]
                gateway = netifaces.gateways().get('default', {}).get(netifaces.AF_INET, [None])[0]

                return {
                    'interface': interface,
                    'gateway': gateway,
                    'IPAddress': ipv4_info.get('addr'),
                    'Subnet': ipv4_info.get('netmask'),
                    'Broadcast': ipv4_info.get('broadcast')
                }
        return None

    net_name = get_interface_name()
    
    pattern = rf""" 
                 .                                                           
                /=\\                                                         
               /===\ \                    ╔═══════════════════════════════════╗
              /=====\' \                    Hostname: {platform.node()}
             /=======\'' \                  OS Version: {platform.system()}
            /=========\ ' '\                Python Version: {platform.python_version()}   
           /===========\''   \              {net_name['interface']} IP Address: {net_name['IPAddress']}
          /=============\ ' '  \            {net_name['interface']} Subnet: {net_name['Subnet']}
         /===============\   ''  \          {net_name['interface']} Gateway: {net_name['gateway']}
        /=================\' ' ' ' \        {net_name['interface']} Broadcast: {net_name['Broadcast']}
       /===================\' ' '  ' \                                       
      /=====================\' '   ' ' \                                     
     /=======================\  '   ' /                                      
    /=========================\   ' /       NScan v0.1 beta                  
   /===========================\'  /                                         
  /=============================\/        ╚═══════════════════════════════════╝
    """

    print_exact_fade(pattern)

def help():
    print("""
    Usage: python3 main.py <host>
          
    args:
        host: host to scan

    options:
        -h, --help: show this help
        -p, --port: port to scan
        -v, --verbose: show more info
        -sS, --stealth: use stealth scan
        
          
    example:
        python3 main.py 127.0.0.1 -p 0-65535 -sS -v
    """)

def verify_port(host, port, timeout=2, stealth=False) -> bool:
    if not stealth:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)

            result = s.connect_ex((host, port))
            if result == 0:
                return True
    else:
        #create packet
        pkt = IP(dst=host)/TCP(dport=port, flags="S")
        #send packet
        resp = sr1(pkt, timeout=timeout, verbose=False)
        #check for response
        if resp and resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:
                return True
        return False




if __name__ == "__main__":
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="host to scan")
    parser.add_argument("-p", "--port", help="port to scan")
    parser.add_argument("-v", "--verbose", help="show more info", action="store_true")
    parser.add_argument("-sS", "--stealth", help="use stealth scan", action="store_true")
    args = parser.parse_args()

    if "/" in args.host:
        #define network
        network = ipaddress.ip_network(str(args.host), strict=False)

        #create host list (already exclude gateway and broadcast)
        ip_list = [str(ip) for ip in network.hosts()]
    else:
        ip_list = [args.host]

    for ip in ip_list:

        print_info(f"Scanning {ip}")

        if args.port:
            ports = args.port.split("-")
            ports = list(map(int, ports))
        
    
        for port in ports:
            if verify_port(ip, port,stealth=args.stealth):
                print_result(f"Port {port} is open",subresult=True)
