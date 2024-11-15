import boto3
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Fetch values from .env
security_group_id = os.getenv("SECURITY_GROUP_ID")
ip_ranges_file = os.getenv("IP_RANGES_FILE")

# Initialize EC2 client with specified region
ec2 = boto3.client("ec2", region_name="ap-northeast-1")

# Load IP ranges from the file and limit the number
max_ips_to_add = 3  # Limit the number of IPs to add
with open(ip_ranges_file, "r") as file:
    ip_ranges = [line.strip() for line in file if line.strip()][:max_ips_to_add]

# Ports to manage (80 for HTTP, 443 for HTTPS)
ports = [80, 443]

# Function to fetch current rules in the security group
def get_current_rules():
    try:
        response = ec2.describe_security_groups(GroupIds=[security_group_id])
        return response["SecurityGroups"][0]["IpPermissions"]
    except Exception as e:
        print(f"Failed to retrieve security group rules: {e}")
        exit(1)

# Function to remove outdated or matching rules
def remove_matching_rules():
    current_rules = get_current_rules()  # Fetch current rules before removing
    for rule in current_rules:
        for port in ports:
            if rule.get("FromPort") == port and rule.get("ToPort") == port:
                for ip in rule.get("IpRanges", []):
                    # Only remove the IP if it is both in the rule and in the list of IP ranges to add
                    if ip["CidrIp"] in ip_ranges:
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
    current_rules = get_current_rules()  # Refetch current rules after removal
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
