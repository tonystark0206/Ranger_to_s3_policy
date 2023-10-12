import json
import os

def convert_hive_policy(data):
    # Define mappings for Hive actions to AWS actions
    action_mappings = {
        "read": "s3:GetObject",
        "select": "s3:GetObject",
        "update": "s3:PutObject",
        "create": "s3:PutObject",
        "drop": "s3:DeleteObject",
        "alter": "s3:PutObject",
        "index": "s3:PutObject",
        "lock": "s3:PutObject",
        "all": "s3:PutObject",
        "write": "s3:PutObject",
        "repladmin": "s3:ReplicateObject",
        "serviceadmin": "s3:AdministerAccount",
        "tempudfadmin": "s3:AdministerAccount",
        "refresh": "s3:RefreshObject",
    }

    # Initialize AWS policy objects
    user_policies = {}
    group_policies = {}
    role_policies = {}

    # Process each policy item
    for policy in data["policies"]:
        for policy_item in policy["policyItems"]:
            for access in policy_item["accesses"]:
                aws_action = action_mappings.get(access["type"], access["type"])
                for user in policy_item["users"]:
                    user_policies.setdefault(user, []).append(aws_action)

                role_policies.setdefault(policy_item["roles"], []).extend(
                    [action_mappings.get(a["type"], a["type"]) for a in policy_item["accesses"]]
                )

                group_policies.setdefault(policy_item["groups"], []).extend(
                    [action_mappings.get(a["type"], a["type"]) for a in policy_item["accesses"]
                ])

    # Generate the AWS policies
    aws_policies = {"users": {}, "groups": {}, "roles": {}}

    for user, actions in user_policies.items():
        aws_policies["users"][user] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}

    for group, actions in group_policies.items():
        aws_policies["groups"][group] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}

    for role, actions in role_policies.items():
        aws_policies["roles"][role] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}

    return aws_policies

import json
def convert_hdfs_policy(ranger_data):
    policies = ranger_data["policies"]
    #print(policies)
    aws_s3_policies = []

    for policy in policies:
        # Extract relevant information from the Ranger policy
        name = policy["name"]
        print(name)
        accesses = []
        for policy_item in policy["policyItems"]:
            accesses.extend([access["type"] for access in policy_item["accesses"] if access["isAllowed"]])
        users = policy["policyItems"][0]["users"]
        groups = policy["policyItems"][0]["groups"]
        roles = policy["policyItems"][0]["roles"]

        # Define the S3 policy
        s3_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:" + access for access in accesses],
                    "Resource": "arn:aws:s3:::your-bucket" + policy["resources"]["path"]["values"][0] + "/*"
                }
            ]
        }

        # Add users, groups, and roles to the policy
        if users:
            s3_policy["Statement"][0]["Principal"] = {"AWS": ["arn:aws:iam::your-account-id:user/" + user for user in users]}
        elif groups:
            s3_policy["Statement"][0]["Principal"] = {"AWS": ["arn:aws:iam::your-account-id:group/" + group for group in groups]}
        elif roles:
            s3_policy["Statement"][0]["Principal"] = {"AWS": ["arn:aws:iam::your-account-id:role/" + role for role in roles]}

        aws_s3_policies.append(s3_policy)

    return aws_s3_policies


def segregate_aws_policy(policies):
    segregated_policies = []
    print("inside")
    for policy in policies:
        if isinstance(policy, dict):
            if "Statement" in policy:
                principal_aws = policy.get("Statement", [])[0].get("Principal", {}).get("AWS", [])
                if any("user/" in principal for principal in principal_aws):
                    segregated_policies.append(("user", policy))
                elif any("role/" in principal for principal in principal_aws):
                    segregated_policies.append(("role", policy))
                elif any("group/" in principal for principal in principal_aws):
                    segregated_policies.append(("group", policy))

    return segregated_policies

def write_aws_policy_to_file(policy, output_dir, policy_type):
    with open(os.path.join(output_dir, f"{policy_type}_policy.json"), "a") as output_file:
        json.dump(policy, output_file, indent=4)

if __name__ == "__main__":
    file_path = os.path.abspath(r'<path>\hdfs_policy.json')
    output_dir = os.path.abspath(r'<path>\output-aws-policies')

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    with open(file_path) as ranger_file:
        ranger_data = json.load(ranger_file)
        #print('Data loaded', ranger_data)

        for policy in ranger_data.get("policies", []):
            if policy.get("serviceType") == "hive":
                aws_s3_policies = convert_hive_policy(ranger_data)
            elif policy.get("serviceType") == "hdfs":
                #print('Data loaded')
                aws_s3_policies = convert_hdfs_policy(ranger_data)
                print(aws_s3_policies)

            # Segregate and write the Hive policy
            segregated = segregate_aws_policy(aws_s3_policies)
            for policy_type, policy_statement in segregated:
                print(f"Policy Type: {policy_type}")
                print("Policy Statement:")
                print(policy_statement)
                print("\n")
                if policy_type:
                    write_aws_policy_to_file(segregated, output_dir, policy_type)
            '''
            policy_type, segregated_policy = segregate_aws_policy(segregated)
            if policy_type:
                write_aws_policy_to_file(segregated_policy, output_dir, policy_type)
                '''
