from prometheus_client import Gauge, start_http_server
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import time
from datetime import datetime, timezone

#----AWS Session
session = boto3.Session(profile_name="cloud-telemetry-monitor")

cloudtrail = session.client("cloudtrail")
guardduty = session.client("guardduty")
iam = session.client("iam")
kms = session.client("kms")

#---Prometheus Metrics
cloudtrail_logging = Gauge(
    "aws_cloudtrail_logging_enabled",
    "If cloudtrai logging is enabled for at least one multi-region trail, value is 1, else is 0"
)

gd_high_findings = Gauge(
    "aws_guardduty_high_findings",
    "Number of high severity GuardDuty findings (severity >= 7)"
)

iam_access_key_max_age_days = Gauge(
    "aws_iam_access_key_max_age_days",
    "Maximum age in days among all active IAM access keys"
)

kms_rotation_all_enabled = Gauge(
    "aws_kms_rotation_all_enabled",
    "If KMS automatic rotation is enabled for all customer-managed keys, value is 1, else is 0"
)

def collect_cloudtrail_status():
    try:
        trails = cloudtrail.describe_trails()["trailList"]
        logging_ok = 0

        for trail in trails:
            name = trail["Name"]
            status = cloudtrail.get_trail_status(Name=name)
            if status.get("IsLogging"):
                logging_ok = 1
                break
        
        cloudtrail_logging.set(logging_ok)
    except (BotoCoreError, ClientError) as e:
        print(f"[Error] collect_cloud_trail_status: {e}")
        cloudtrail_logging.set(0)

def collect_guardduty_findings():
    try:
        detectors = guardduty.list_detectors()["DetectorIds"]

        if not detectors:
            gd_high_findings.set(0)
            return

        total_high = 0

        severity_criterion = {
            "Criterion": {
                "severity": {
                    "Gte": 7
                }
            }
        }

        for detector_id in detectors:
            resp = guardduty.list_findings(
                DetectorId=detector_id,
                FindingCriteria=severity_criterion
            )
            total_high += len(resp.get("FindingIds",  []))

        gd_high_findings.set(total_high)

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code == "SubscriptionRequiredException":
            print("[WARN] GuardDuty is not enabled for this account/region.")
            gd_high_findings.set(-1)
        else:
            print(f"[ERROR] collect_guardduty_findings: {e}")
            gd_high_findings.set(-1)
    except BotoCoreError as e:
        print(f"[ERROR] collect_guardduty_findings (BotoCore): {e}")
        gd_high_findings.set(-1)

def collect_iam_access_key_max_age():
    try:
        today = datetime.now(timezone.utc)
        max_age_days = 0

        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]
                keys_resp = iam.list_access_keys(UserName=username)
                for key in keys_resp["AccessKeyMetadata"]:
                    if key["Status"] != "Active":
                        continue
                    created = key["CreateDate"]
                    age_days = (today - created).days
                    if age_days > max_age_days:
                        max_age_days = age_days
        
        iam_access_key_max_age_days.set(max_age_days)
    except(BotoCoreError, ClientError) as e:
        print(f"[ERROR] collect_iam_access_key_max_age: {e}")
        iam_access_key_max_age_days.set(-1)

def collect_kms_rotation():
    try:
        all_ok = 1
        paginator = kms.get_paginator("list_keys")

        for page in paginator.paginate():
            for key in page["Keys"]:
                key_id = key["KeyId"]
                desc = kms.describe_key(KeyId=key_Id)
                metadata = desc["KeyMetadata"]

                if metadata["KeyManager"] != "Customer":
                    continue

                rotation_status = kms.get_key_rotation_status(KeyId=key_id)
                if not rotation_status.get("KeyRotationEnabled", False):
                    all_ok = 0
            
        kms_rotation_all_enabled.set(all_ok)
    except (BotoCoreError, ClientError) as e:
        print(f"[ERROR] collect_kms_rotation: {e}")
        kms_rotation_all_enabled.set(0)


COLLECTION_INTERVAL_SECONDS = 60

def collect_all():
    collect_cloudtrail_status()
    collect_guardduty_findings()
    collect_iam_access_key_max_age()
    collect_kms_rotation()
    print("Metrics collected")

if __name__ == "__main__":
    start_http_server(9100)
    print("AWS Cloud Security exporter running on :9100/metrics")
    while True:
        collect_all()
        time.sleep(COLLECTION_INTERVAL_SECONDS)
