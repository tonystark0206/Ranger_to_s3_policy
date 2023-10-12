import json
import os
import boto3

# Load the Ranger exported JSON file
file_path = os.path.abspath('path-to-ranger-policy.json')
with open(file_path) as ranger_file:
    ranger_data = json.load(ranger_file)

# Generate AWS S3 policy based on Ranger policies
def generate_s3_policies(data):
    s3_policies = []

    for policy in data.get("policies", []):
        if policy.get("serviceType") == "hdfs":
            s3_policy = {
                "Version": "2012-10-17",
                "Statement": []
            }

            for item in policy.get("policyItems", []):
                statement = {
                    "Effect": "Allow" if item["accesses"][0]["isAllowed"] else "Deny",
                    "Action": [],
                    "Resource": []
                }

                for access in item["accesses"]:
                    if access["type"] == "read":
                        statement["Action"].append("s3:GetObject")
                    elif access["type"] == "write":
                        statement["Action"].append("s3:PutObject")
                    elif access["type"] == "execute":
                        statement["Action"].append("s3:ListBucket")

                for path in policy.get("resources", {}).get("path", {}).get("values", []):
                    statement["Resource"].append(f"arn:aws:s3:::{path}")

                s3_policy["Statement"].append(statement)

            s3_policies.append(s3_policy)

    return s3_policies

aws_s3_policies = generate_s3_policies(ranger_data)

# Write the AWS S3 policies to a JSON file
output_file_path = os.path.abspath('output-policy.json')
with open(output_file_path, "w") as output_file:
    json.dump(aws_s3_policies, output_file, indent=4)
'''
# Apply the AWS S3 policies to an S3 bucket using boto3
bucket_name = "s3a://<bucket-name>/"
s3_client = boto3.client("s3")
for s3_policy in aws_s3_policies:
    s3_client.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(s3_policy))

print(f"AWS S3 policies have been applied to the '{bucket_name}' bucket.")
'''
