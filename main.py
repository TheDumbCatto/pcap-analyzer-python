import argparse
import json
from pcapparser import parsepcap

def main():

# ==========================================================================================================    
# Handling arguments =======================================================================================
    args = argparse.ArgumentParser()
    args.add_argument("-f", "--file", help="The PCAP file to analyze", required=True)
    args.add_argument("--filter", help="Wireshark filter string that will be applied to the file", required=False)

    args_parsed = args.parse_args()
    
    if args_parsed.filter:
        res = parsepcap.parsepcap(args_parsed.file, '&& ' + args_parsed.filter)
    else:
        res = parsepcap.parsepcap(args_parsed.file)

    print(json.dumps([packet.__dict__ for packet in res], indent=2))

if __name__ == "__main__":
    main()
