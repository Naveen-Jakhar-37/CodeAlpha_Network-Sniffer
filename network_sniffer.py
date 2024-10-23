import scapy.all as scapy
from scapy.layers.inet import IP
import os
import threading
import time  # Import time for sleep functionality

# Global variable to control the sniffing process
sniffing = False

# Function to process each captured packet
def process_packet(packet):
    """
    Callback function to process and display packet details.

    Args:
        packet: Captured packet object
    """
    if IP in packet:  # Check if the packet has an IP layer
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(packet[IP].proto, "Other")
        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol} | Length: {len(packet)} bytes")

# Function to sniff network traffic
def sniff_traffic(iface):
    """
    Sniff network traffic on the specified interface.

    Args:
        iface (str): Network interface to sniff (e.g., "eth0", "wlan0")
    """
    global sniffing
    sniffing = True  # Set to True when sniffing starts
    print(f"Starting packet capture on {iface}...")
    try:
        # Start sniffing with a callback function for processing packets
        scapy.sniff(iface=iface, prn=process_packet, store=False)
    except Exception as e:
        print(f"Error sniffing packets: {e}")

# Function to display a custom banner
def display_banner():
    os.system('clear')  # Clears the terminal for a clean banner display
    print(r"""
  _   _      _                 _    _____        __ _     _  __ _           
 | \ | |    | |               | |  / ____|      / _| |   (_)/ _| |          
 |  \| | ___| |_ ___ _ __ ___  | | | (___   ___ | |_| |__  _| |_| |_ ___ _ __ 
 | . ` |/ _ \ __/ _ \ '__/ _ \ | |  \___ \ / _ \|  _| '_ \| |  _| __/ _ \ '__|
 | |\  |  __/ ||  __/ | |  __/ | |  ____) | (_) | | | | | | | | | ||  __/ |   
 |_| \_|\___|\__\___|_|  \___| |_| |_____/ \___/|_| |_| |_|_|_|  \__\___|_|   
                                                                             
    """)
    print("=" * 70)
    print("Welcome to the Advanced Network Sniffer Tool")
    print("This tool allows you to monitor network traffic in real-time.")
    print("⚠️  Educational and research purposes only! ⚠️")
    print("=" * 70)

# Main function to handle user input and options
def main():
    global sniffing  # Declare sniffing as a global variable
    iface = "eth0"  # Change this to your network interface
    display_banner()

    while True:
        print("\nChoose an Option:")
        print("[1] 🕵️ Start Sniffing")
        print("[2] ❌ Stop Sniffing")
        print("[0] 🚪 Exit")
        choice = input("Enter Your Selection: ")

        if choice == '1':
            if not sniffing:
                # Start the sniffing thread
                sniff_thread = threading.Thread(target=sniff_traffic, args=(iface,))
                sniff_thread.start()
            else:
                print("Sniffing is already running.")

        elif choice == '2':
            if sniffing:
                print("Stopping sniffing...")
                sniffing = False
                # Allow some time for the last packets to be processed
                time.sleep(1)
            else:
                print("Sniffing is not currently running.")

        elif choice == '0':
            print("Exiting the sniffer tool. Goodbye!")
            break

        else:
            print("Invalid input. Please select a valid option.")

if __name__ == "__main__":
    main()