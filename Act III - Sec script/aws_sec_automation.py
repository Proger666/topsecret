import boto3
import os
import json
import argparse
from prettytable import PrettyTable, ALL

def load_or_prompt_settings():
    """
    Load AWS settings from a JSON file. If the file does not exist, prompt the user for AWS profile and region, 
    and save these settings to a new JSON file.

    :return: A dictionary containing AWS 'profile' and 'region'.
    :rtype: dict
    """

    settings_file = os.path.join(os.path.expanduser('~'), 'aws_profile_settings.json')
    
    if os.path.exists(settings_file):
        with open(settings_file, 'r') as file:
            settings = json.load(file)
    else:
        settings = {
            'profile': input("Enter AWS profile (default if blank): ") or 'default',
            'region': input("Enter AWS region (e.g., us-east-1): ") or 'us-east-1'
        }
        with open(settings_file, 'w') as file:
            json.dump(settings, file)
        # Set file permissions to read/write for the user only
        os.chmod(settings_file, 0o600)
    return settings

def reconfigure_profile():
    """
    Reconfigure AWS profile settings by prompting the user to enter new values. 
    The new settings are saved to a JSON file.

    :return: A dictionary containing updated AWS 'profile' and 'region'.
    :rtype: dict
    """

    settings_file = os.path.join(os.path.expanduser('~'), 'aws_profile_settings.json')
    settings = {
        'profile': input("Enter AWS profile (default if blank): ") or 'default',
        'region': input("Enter AWS region (e.g., us-east-1): ") or 'us-east-1'
    }
    with open(settings_file, 'w') as file:
        json.dump(settings, file)
    os.chmod(settings_file, 0o600)
    print("Profile reconfigured successfully.")
    return settings



def get_latest_ami(ec2_client, os_name, architecture='x86_64'):
    """
    Get the latest Amazon Machine Image (AMI) ID based on the specified OS name and architecture.

    :param ec2_client: An EC2 client object from boto3.
    :type ec2_client: boto3.client
    :param os_name: The name of the operating system.
    :type os_name: str
    :param architecture: The architecture type, defaults to 'x86_64'.
    :type architecture: str, optional
    :return: The latest AMI ID, or None if no AMI found.
    :rtype: str or None
    """

    filters = [
        {'Name': 'architecture', 'Values': [architecture]},
        {'Name': 'virtualization-type', 'Values': ['hvm']},
        {'Name': 'root-device-type', 'Values': ['ebs']},
        {'Name': 'state', 'Values': ['available']}
    ]
    amis = ec2_client.describe_images(Filters=filters, Owners=['amazon'])
    if not amis['Images']:
        return None
    latest_ami = max(amis['Images'], key=lambda x: x['CreationDate'])
    return latest_ami['ImageId']

from prettytable import PrettyTable

def list_ec2_instances(aws_profile, aws_region, upgrade=False, environment=None):
    """
    List all running EC2 instances in a specified region and profile. Optionally, list instances based on environment tag 
    and provide option to upgrade instances.

    :param aws_profile: AWS profile to use.
    :type aws_profile: str
    :param aws_region: AWS region where the instances are located.
    :type aws_region: str
    :param upgrade: Flag to indicate if instance AMI upgrade recommendation is required.
    :type upgrade: bool, optional
    :param environment: Optional environment tag to filter instances.
    :type environment: str, optional
    """

    try:
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        ec2 = session.client('ec2')

        filters = [{'Name': 'instance-state-name', 'Values': ['running']}]
        if environment:
            filters.append({'Name': 'tag:Environment', 'Values': [environment]})

        instances = ec2.describe_instances(Filters=filters)
        
        # Initialize PrettyTable
        table = PrettyTable()
        table.field_names = ["Instance ID", "AMI Status", "Region", "Tags"]
        table.max_width = 30  # Sets maximum width for all columns
        table.hrules = ALL   # Draws a line between each row

        found_instances = False

        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                found_instances = True
                os_name = instance.get('PlatformDetails', 'Linux/UNIX')
                latest_ami = get_latest_ami(ec2, os_name)
                instance_ami = instance['ImageId']
                ami_status = 'using the latest AMI' if instance_ami == latest_ami else f'NOT using the latest AMI. Upgrade ({instance_ami}) -> ({latest_ami})'
                
                # Retrieve tags
                tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in instance.get('Tags', [])])

                table.add_row([instance['InstanceId'], ami_status, aws_region, tags])

        if not found_instances:
            print(f"No running instances found with the environment tag '{environment}'" if environment else "No running instances found")
        else:
            print(table)
            
            if(upgrade):
                update_instance_recommendation()

    except Exception as e:
        print(f"Error: {e}")



def update_instance_recommendation():
    """
    Print a step-by-step recommendation for upgrading an instance's AMI.
    """

    print(f"Due to complexity of upgrade operation, here is the example of steps to upgrade AMI:")
    print("1. Launch a new instance with the latest AMI in staging env.")
    print("2. Migrate your configurations and data from the old instance to the new one.")
    print("3. Run e2e and other tests on the new instance to ensure it operates as expected.")
    print("4. Repeat steps 1-3 for prod env")
    print("5. Redirect part of the traffic/incoming pods/load to new instance")
    print("6. Once confirmed, decommission the old instance/add full load")

def check_security_groups(aws_profile, aws_region):
    """
    Check security groups for overly permissive rules in a specified AWS profile and region.

    :param aws_profile: AWS profile to use.
    :type aws_profile: str
    :param aws_region: AWS region to check.
    :type aws_region: str
    """

    try:
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        ec2 = session.client('ec2')

        security_groups = ec2.describe_security_groups()
        for sg in security_groups['SecurityGroups']:
            permissive_rules = []
            for rule in sg['IpPermissions']:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        permissive_rules.append({'description': 'Allows all IPv4 traffic (0.0.0.0/0)'})
                for ipv6_range in rule.get('Ipv6Ranges', []):
                    if ipv6_range.get('CidrIpv6') == '::/0':
                        permissive_rules.append({'description': 'Allows all IPv6 traffic (::/0)'})
            
            if permissive_rules:
                print(f"Security Group with overly permissive rules: {sg['GroupId']}")

    except Exception as e:
        print(f"Error: {e}")


def list_security_groups(aws_profile, aws_region, show_only_overpermissive=False):
    """
    List security groups and their details in a specified AWS profile and region. Optionally, list only overpermissive security groups.

    :param aws_profile: AWS profile to use.
    :type aws_profile: str
    :param aws_region: AWS region to check.
    :type aws_region: str
    :param show_only_overpermissive: Flag to show only overpermissive security groups.
    :type show_only_overpermissive: bool, optional
    """

    try:
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        ec2 = session.client('ec2')

        security_groups = ec2.describe_security_groups()

        table = PrettyTable()
        table.field_names = ["Group Name", "Group ID", "Description", "Ports", "Overpermissive"]
        table.max_width = 30
        table.hrules = ALL

        for sg in security_groups['SecurityGroups']:
            rule_names = []
            overpermissive_warning = ""

            for rule in sg['IpPermissions']:
                if is_overpermissive_rule(rule):
                    overpermissive_warning = "Y"
                rule_name = rule.get('FromPort', 'N/A')
                rule_names.append(str(rule_name))

            if not show_only_overpermissive or overpermissive_warning == "Y":
                table.add_row([sg['GroupName'], sg['GroupId'], sg['Description'], ', '.join(rule_names), overpermissive_warning])

        print(table)

    except Exception as e:
        print(f"Error: {e}")


def is_overpermissive_rule(rule):
    """
    Check if a security group rule is overpermissive.

    :param rule: A security group rule to check.
    :type rule: dict
    :return: True if the rule is overpermissive, False otherwise.
    :rtype: bool
    """

    # Check within IpRanges and Ipv6Ranges for overpermissive rules (For SGP)
    for ip_range in rule.get('IpRanges', []):
        if ip_range.get('CidrIp') == '0.0.0.0/0':
            return True
    for ipv6_range in rule.get('Ipv6Ranges', []):
        if ipv6_range.get('CidrIpv6') == '::/0':
            return True

    # Additionally, check the rule directly for CidrIpv4 and CidrIpv6 fields (For SGF)
    if 'CidrIpv4' in rule and rule['CidrIpv4'] == '0.0.0.0/0':
        return True
    if 'CidrIpv6' in rule and rule['CidrIpv6'] == '::/0':
        return True

    return False


def show_overpermissive_groups(aws_profile, aws_region):
    """
    Show overpermissive security group rules in a specified AWS profile and region.

    :param aws_profile: AWS profile to use.
    :type aws_profile: str
    :param aws_region: AWS region to check.
    :type aws_region: str
    """

    try:
        session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
        ec2 = session.client('ec2')

        security_groups = ec2.describe_security_groups()

        table = PrettyTable()
        table.field_names = ["Group ID", "Port Range", "Source"]

        for sg in security_groups['SecurityGroups']:
            for rule in sg['IpPermissions']:
                if is_overpermissive_rule(rule):
                    # Determine port range
                    from_port = rule.get('FromPort', 'All')
                    to_port = rule.get('ToPort', 'All')
                    port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                    rule_position = sg['IpPermissions'].index(rule)  # Position of the rule in the list

                    # Determine source
                    sources = [ip_range.get('CidrIp') for ip_range in rule.get('IpRanges', []) if 'CidrIp' in ip_range]
                    sources.extend([ipv6_range.get('CidrIpv6') for ipv6_range in rule.get('Ipv6Ranges', []) if 'CidrIpv6' in ipv6_range])
                    source = ', '.join(sources) if sources else 'N/A'

                    table.add_row([sg['GroupId'], port_range, source])
        print(table)

    except Exception as e:
        print(f"Error: {e}")


def remove_overpermissive_permissions(aws_profile, aws_region, sg_ids):
    """
    Remove overpermissive permissions from specified security groups in a given AWS profile and region.

    :param aws_profile: AWS profile to use.
    :type aws_profile: str
    :param aws_region: AWS region where the security groups are located.
    :type aws_region: str
    :param sg_ids: List of security group IDs to fix.
    :type sg_ids: list[str]
    """

    session = boto3.Session(profile_name=aws_profile, region_name=aws_region)
    ec2 = session.client('ec2')

    try:
        fixed_sgs = []  # List to keep track of fixed security groups

        for sg_id in sg_ids:
            # Describe the rules of the security group
            response = ec2.describe_security_group_rules(
                Filters=[
                    {'Name': 'group-id', 'Values': [sg_id]}
                ]
            )

            for rule in response['SecurityGroupRules']:
                if rule['IsEgress']:  # Skip egress rules
                    continue

                if is_overpermissive_rule(rule):
                    print(f"Removing overpermissive ingress rule {rule['SecurityGroupRuleId']} from SG {sg_id}")
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        SecurityGroupRuleIds=[rule['SecurityGroupRuleId']]
                    )

                    if sg_id not in fixed_sgs:
                        fixed_sgs.append(sg_id)

        if fixed_sgs:
            print(f"Fixed security groups: {', '.join(fixed_sgs)}")
        else:
            print("No overpermissive ingress rules found or removed.")

    except Exception as e:
        print(f"Error occurred: {e}")


def get_user_choice():
    """
    Prompt the user to choose an action from a predefined list of options.

    :return: The user's choice.
    :rtype: str
    """
    
    valid_choices = {
        'RINT': 'Reconfigure AWS profile and region',
        'SGL': 'List security groups in a region',
        'SGP': 'Show overpermissive security groups',
        'SGF': 'Fix overpermissive security groups',
        'IL': 'List all running instances in a region',
        'ITG': 'List instances by tag',
        'ILU': 'Upgrade Instances AMI',
        'Q': 'Quit'
    }
    while True:
        print("\nChoose an option:")
        for key, value in valid_choices.items():
            print(f"[{key}] {value}")
        choice = input().strip().upper()
        if choice in valid_choices:
            return choice
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    settings = load_or_prompt_settings()

    while True:
        user_choice = get_user_choice()
        if user_choice == 'RINT':
            settings = reconfigure_profile()
        elif user_choice == 'SGL':
            list_security_groups(settings['profile'], settings['region'])
        elif user_choice == 'SGP':
            list_security_groups(settings['profile'], settings['region'], show_only_overpermissive=True)
        elif user_choice == 'SGF':  # Ask user for SG to fix
            sg_input = input("Enter Security Group IDs to fix, separated by commas: ")
            sg_ids = [sg_id.strip() for sg_id in sg_input.split(',') if sg_id.strip()]
            remove_overpermissive_permissions(settings['profile'], settings['region'], sg_ids)
        elif user_choice == 'IL':
            list_ec2_instances(settings['profile'], settings['region'])
        elif user_choice == 'ITG':
            env = input("Enter environment (Dev, Prod, Staging): ").capitalize()
            list_ec2_instances(settings['profile'], settings['region'], environment=env)
        elif user_choice == 'ILU':
            list_ec2_instances(settings['profile'], settings['region'], upgrade=True)
        elif user_choice == 'Q':
            print("Exiting script.")
            break