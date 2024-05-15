import scapy.all as scapy
import argparse


def print_info(result):
    print('IP Address\t\tMAC Address')
    print('------------------------------------')

    for client in result:
        print(f'{client["ip"]}\t\t{client["mac"]}')


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Specify target IP address or range')

    return parser.parse_args()


def scan(ip):
    clients_list = []

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')

    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp1(arp_request_broadcast, timeout=1, verbose=False)

    if answered_list:
        client_dict = {
            'ip': answered_list.psrc,
            'mac': answered_list.hwsrc
        }
        clients_list.append(client_dict)

    return clients_list


options = get_arguments()
target_ip = options.target

if not target_ip:
    print('[-] Please specify the target. Use --help for more information.')
else:
    print_info(scan(target_ip))
