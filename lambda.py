import json
import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")

BUCKET_NAME = "acc-demo-bucket-849076101014"

SECURE_SETTINGS = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def get_settings():
    try:
        return s3.get_public_access_block(Bucket=BUCKET_NAME)["PublicAccessBlockConfiguration"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise


def is_secure(settings):
    return all(settings.get(k) is True for k in SECURE_SETTINGS)


def lambda_handler(event, context):
    print("Received event:", json.dumps(event))

    detail = event.get("detail", {}) or {}
    params = detail.get("requestParameters", {}) or {}
    bucket = params.get("bucketName")

    if bucket != BUCKET_NAME:
        print(f"Ignoring unrelated bucket: {bucket}")
        return {"statusCode": 200, "body": "Ignored"}

    current = get_settings()
    print("Current settings:", json.dumps(current))

    if is_secure(current):
        print("Bucket already secure. No remediation required.")
        return {"statusCode": 200, "body": "Already secure"}

    s3.put_public_access_block(
        Bucket=BUCKET_NAME,
        PublicAccessBlockConfiguration=SECURE_SETTINGS,
    )

    verified_settings = get_settings()
    verified = is_secure(verified_settings)

    result = {
        "bucket": BUCKET_NAME,
        "action": "restore_bucket_public_access_block",
        "triggered_by": detail.get("eventName"),
        "verified": verified,
        "settings": verified_settings,
    }
    print("Remediation result:", json.dumps(result))

    if not verified:
        raise RuntimeError("Remediation verification failed")

    return {"statusCode": 200, "body": json.dumps(result)}
