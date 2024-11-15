import boto3

# Initialize EC2 client
ec2 = boto3.client("ec2")

# Replace with your security group ID
security_group_id = "sg-xxxxxxxx"

# File containing the list of IP ranges (one per line)
ip_ranges_file = "ip_ranges.txt"  # Replace with the path to your file

# Load IP ranges from the file
with open(ip_ranges_file, "r") as file:
    ip_ranges = [line.strip() for line in file if line.strip()]  # Strip whitespace and skip empty lines

# Ports to manage (80 for HTTP, 443 for HTTPS)
ports = [80, 443]

# Fetch current rules in the security group
current_rules = ec2.describe_security_groups(GroupIds=[security_group_id])["SecurityGroups"][0]["IpPermissions"]

# Function to remove outdated or matching rules
def remove_matching_rules():
    for rule in current_rules:
        for port in ports:
            if rule.get("FromPort") == port and rule.get("ToPort") == port:
                for ip in rule.get("IpRanges", []):
                    if ip["CidrIp"] in ip_ranges:  # Only remove matching IPs
                        try:
                            ec2.revoke_security_group_ingress(
                                GroupId=security_group_id,
                                IpPermissions=[
                                    {
                                        "IpProtocol": "tcp",
                                        "FromPort": port,
                                        "ToPort": port,
                                        "IpRanges": [{"CidrIp": ip["CidrIp"]}],
                                    }
                                ],
                            )
                            print(f"Removed rule for {ip['CidrIp']} on port {port}")
                        except Exception as e:
                            print(f"Failed to remove rule for {ip['CidrIp']} on port {port}: {e}")

# Function to add new rules
def add_new_rules():
    for ip_range in ip_ranges:
        for port in ports:
            # Check if the IP range already exists in the SG
            if not any(
                rule.get("FromPort") == port and
                rule.get("ToPort") == port and
                any(ip["CidrIp"] == ip_range for ip in rule.get("IpRanges", []))
                for rule in current_rules
            ):
                try:
                    ec2.authorize_security_group_ingress(
                        GroupId=security_group_id,
                        IpPermissions=[
                            {
                                "IpProtocol": "tcp",
                                "FromPort": port,
                                "ToPort": port,
                                "IpRanges": [{"CidrIp": ip_range}],
                            }
                        ],
                    )
                    print(f"Added rule for {ip_range} on port {port}")
                except Exception as e:
                    print(f"Failed to add rule for {ip_range} on port {port}: {e}")

# Main execution
if __name__ == "__main__":
    # Step 1: Remove only matching rules from ip_ranges.txt
    remove_matching_rules()

    # Step 2: Add new rules from ip_ranges.txt
    add_new_rules()
