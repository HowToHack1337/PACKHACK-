import sys
from scapy.all import rdpcap
import atexit

def is_printable_ascii(data):
    return all(32 <= byte <= 126 or byte in [9, 10, 13] for byte in data)

def print_text_data(packet):
    if packet.haslayer('TCP') and packet.haslayer('Raw'):
        tcp_layer = packet.getlayer('TCP')
        raw_data = packet.getlayer('Raw').load

        # Check if the payload is likely to contain printable ASCII text
        if is_printable_ascii(raw_data):
            print(f"Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
            print("Text Data:")
            print(raw_data.decode('utf-8', errors='replace'))
            print("-" * 30)

def read_and_print_text_data(file_path):
    try:
        # Read the pcap file
        packets = rdpcap(file_path)

        # Iterate through each packet and print readable text data
        for packet in packets:
            print_text_data(packet)

    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Define a function to print the current banner with a creative style
def print_current_banner():
    print("""
    
 ######     #     #####  #    # #     #    #     #####  #    # 
 #     #   # #   #     # #   #  #     #   # #   #     # #   #  
 #     #  #   #  #       #  #   #     #  #   #  #       #  #   
 ######  #     # #       ###    ####### #     # #       ###    
 #       ####### #       #  #   #     # ####### #       #  #   
 #       #     # #     # #   #  #     # #     # #     # #   #  
 #       #     #  #####  #    # #     # #     #  #####  #    # 
                                                               
                                                       
Fast Packet Explorer by MAX\ntwiiter:HowToHack1337\n""" + "-" * 50)

# Print the banner immediately upon script execution
print_current_banner()

# Check if a command-line argument (file path) is provided
if len(sys.argv) != 2:
    file_path = input("Enter the path to the pcap file: ")
else:
    # Get the file path from the command-line argument
    file_path = sys.argv[1]

# Call the function with the provided file path
read_and_print_text_data(file_path)
