import csv

def parse_lookup_table(lookup_file):
    lookup_table = {}
    with open(lookup_file, 'r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            dstport = int(row['dstport'])
            protocol = row['protocol'].lower()  
            tag = row['tag']
            lookup_table[(dstport, protocol)] = tag
    return lookup_table


def parse_flow_logs(log_file):
    flow_logs = []
    with open(log_file, 'r') as file:
        for line in file:
            parts = line.strip().split()
            if len(parts) < 13 or parts[0] != '2':  
                continue
            dstport = int(parts[5])
            protocol = 'tcp' if parts[7] == '6' else 'udp' 
            flow_logs.append((dstport, protocol))
    return flow_logs


def map_logs_to_tags(flow_logs, lookup_table):
    tag_counts = {}
    port_protocol_counts = {}
    untagged_count = 0
    
    for dstport, protocol in flow_logs:
        key = (dstport, protocol)
        tag = lookup_table.get(key, 'Untagged')
        
        if tag == 'Untagged':
            untagged_count += 1
        else:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1
        
        port_protocol_counts[key] = port_protocol_counts.get(key, 0) + 1

    return tag_counts, port_protocol_counts, untagged_count


def write_output(tag_counts, port_protocol_counts, untagged_count, output_file):
    with open(output_file, 'w') as file:
        file.write("Tag Counts:\n")
        file.write("Tag,Count\n")
        for tag, count in tag_counts.items():
            file.write(f"{tag},{count}\n")
        file.write(f"Untagged,{untagged_count}\n\n")
        
        file.write("Port/Protocol Combination Counts:\n")
        file.write("Port,Protocol,Count\n")
        for (dstport, protocol), count in port_protocol_counts.items():
            file.write(f"{dstport},{protocol},{count}\n")


def main():
    lookup_file = 'lookup_table.csv'
    log_file = 'flow_logs.txt'
    output_file = 'output.txt'
    
    lookup_table = parse_lookup_table(lookup_file)
    flow_logs = parse_flow_logs(log_file)
    
    tag_counts, port_protocol_counts, untagged_count = map_logs_to_tags(flow_logs, lookup_table)
    
    write_output(tag_counts, port_protocol_counts, untagged_count, output_file)

if __name__ == '__main__':
    main()
