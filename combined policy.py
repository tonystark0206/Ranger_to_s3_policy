import json
import os
#import boto3

# Load the Ranger exported JSON file


# Generate AWS S3 policy based on Ranger policies
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
                    if user not in user_policies:
                        user_policies[user] = []
                    user_policies[user].append(aws_action)

            for role in policy_item["roles"]:
                if role not in role_policies:
                    role_policies[role] = []
                role_policies[role].extend([action_mappings.get(a["type"], a["type"]) for a in policy_item["accesses"]])

        for group in policy_item["groups"]:
            if group not in group_policies:
                group_policies[group] = []
            group_policies[group].extend([action_mappings.get(a["type"], a["type"]) for a in policy_item["accesses"]])

    # Generate the AWS policies
    aws_policies = {"users": {}, "groups": {}, "roles": {}}

    for user, actions in user_policies.items():
        aws_policies["users"][user] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}

    for group, actions in group_policies.items():
        aws_policies["groups"][group] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}

    for role, actions in role_policies.items():
        aws_policies["roles"][role] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}]}

    return aws_policies

def convert_hdfs_policy(ranger_policy):
    # Initialize an empty list to store IAM policy statements
    iam_policy_statements = []

    # Function to map Ranger accesses to IAM actions
    def map_ranger_accesses_to_iam_actions(accesses):
        iam_actions = []
        for access in accesses:
            if access["type"] == "read" and access["isAllowed"]:
                iam_actions.append("s3:GetObject")
            elif access["type"] == "write" and access["isAllowed"]:
                iam_actions.append("s3:PutObject")
            elif access["type"] == "execute" and access["isAllowed"]:
                iam_actions.append("s3:ListBucket")
        return iam_actions

    # Loop through Ranger policy items
    for policy_item in ranger_policy["policies"][0]["policyItems"]:
        # Extract elements from the Ranger policy
        accesses = policy_item["accesses"]
        users = policy_item["users"]
        groups = policy_item["groups"]

        # Map Ranger accesses to IAM actions
        iam_actions = map_ranger_accesses_to_iam_actions(accesses)

        # Create an IAM policy statement
        statement = {
            "Effect": "Allow",
            "Action": iam_actions,
            "Resource": "arn:aws:s3:::your-bucket/*"  # Replace with your S3 bucket ARN
        }

        # Add users and groups to the statement
        if users:
            statement["Principal"] = {"AWS": [f"arn:aws:iam::your-account-id:user/{user}" for user in users]}
        if groups:
            statement["Principal"] = {"AWS": [f"arn:aws:iam::your-account-id:group/{group}" for group in groups]}

        # Add the statement to the list of IAM policy statements
        iam_policy_statements.append(statement)

    # Create an AWS IAM policy
    iam_policy = {
        "Version": "2012-10-17",
        "Statement": iam_policy_statements
    }

    return iam_policy

if __name__ == "__main__":
    file_path = os.path.abspath(r'C:\Users\1998484\Documents\Code\hdfs_policy.json')
    output_dir = os.path.abspath(r'C:\Users\1998484\Documents\Code\output-aws-policies')

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    output_dir_file=os.path.abspath(r'C:\Users\1998484\Documents\Code\output-aws-policies\output.json')
    with open(file_path) as ranger_file:
        ranger_data = json.load(ranger_file)
        print('dataloaded', ranger_data)
        for policy in ranger_data.get("policies", []):
            if policy.get("serviceType") == "hive":
                aws_s3_policies = convert_hive_policy(ranger_data)
                with open(output_dir_file, "a") as output_file:
                    json.dump(aws_s3_policies, output_file, indent=4)

            elif policy.get("serviceType") == "hdfs":
                aws_s3_policies = convert_hdfs_policy(ranger_data)
                with open(output_dir_file, "a") as output_file:
                    json.dump(aws_s3_policies, output_file, indent=4)





# Write the AWS S3 policies to a JSON file



'''
# Apply the AWS S3 policies to an S3 bucket using boto3
bucket_name = "s3a://<bucket-name>/"
s3_client = boto3.client("s3")
for s3_policy in aws_s3_policies:
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(s3_policy))

print(f"AWS S3 policies have been applied to the '{bucket_name}' bucket.")
'''
