import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import evaluate  # noqa: E402
import scanner  # noqa: E402


def test_file_matches_handles_absolute_windows_paths():
    assert evaluate.file_matches("terraform/aws/s3.tf", r"C:\work\fixed\terraform\aws\s3.tf")
    assert not evaluate.file_matches("terraform/aws/s3.tf", "terraform/aws/ec2.tf")


def test_resource_matches_short_name():
    assert evaluate.resource_matches("aws_s3_bucket.data", "aws_s3_bucket.data")
    assert evaluate.resource_matches("aws_s3_bucket.data", "data")
    assert not evaluate.resource_matches("aws_s3_bucket.data", "aws_s3_bucket.logs")


def test_checkov_adapter():
    data = {
        "results": {
            "failed_checks": [
                {
                    "file_path": "/terraform/aws/s3.tf",
                    "resource": "aws_s3_bucket.data",
                    "file_line_range": [1, 10],
                    "check_name": "Ensure the S3 bucket has access logging enabled",
                    "check_id": "CKV_AWS_18",
                }
            ]
        }
    }
    findings = scanner._checkov(data)
    assert len(findings) == 1
    assert findings[0].resource == "aws_s3_bucket.data"
    assert findings[0].line == 1
    assert "access logging" in findings[0].text


def test_trivy_adapter():
    data = {
        "Results": [
            {
                "Target": "tests/k8s/01-privileged.yaml",
                "Misconfigurations": [
                    {
                        "ID": "KSV017",
                        "Title": "Privileged container",
                        "Message": "Container should not be privileged",
                        "CauseMetadata": {"Resource": "Pod/privileged-pod", "StartLine": 4},
                    }
                ],
            }
        ]
    }
    findings = scanner._trivy(data)
    assert findings[0].file.endswith("01-privileged.yaml")
    assert findings[0].resource == "Pod/privileged-pod"


def test_kube_linter_adapter():
    data = {
        "Reports": [
            {
                "Check": "privileged-container",
                "Diagnostic": {"Message": "container is privileged"},
                "Object": {
                    "Metadata": {"FilePath": "/src/tests/k8s/01-privileged.yaml"},
                    "K8sObject": {"Name": "privileged-pod"},
                },
            }
        ]
    }
    findings = scanner._kube_linter(data)
    assert findings[0].resource == "privileged-pod"
    assert findings[0].check == "privileged-container"
    assert findings[0].message == "container is privileged"
    assert findings[0].file.endswith("01-privileged.yaml")


def test_kics_adapter():
    data = {
        "queries": [
            {
                "query_name": "Privileged Container",
                "query_id": "abc",
                "files": [{"file_name": "tests/k8s/01-privileged.yaml", "line": 7}],
            }
        ]
    }
    findings = scanner._kics(data)
    assert findings[0].line == 7
    assert findings[0].check == "Privileged Container"


def test_terraform_resource_at_line(tmp_path):
    tf = tmp_path / "main.tf"
    tf.write_text(
        'resource "aws_s3_bucket" "data" {\n  bucket = "x"\n}\n\n'
        'resource "aws_s3_bucket" "logs" {\n  bucket = "y"\n}\n',
        encoding="utf-8",
    )
    finding = scanner.Finding("kics", str(tf), "", 2, "x", "")
    assert scanner.resource_at_line(tmp_path, finding) == "aws_s3_bucket.data"
    finding = scanner.Finding("kics", str(tf), "", 6, "x", "")
    assert scanner.resource_at_line(tmp_path, finding) == "aws_s3_bucket.logs"


def test_item_found_requires_resource_for_terraform(tmp_path):
    item = {
        "target": "terraform",
        "file": "terraform/aws/s3.tf",
        "resource": "aws_s3_bucket.data",
        "category": "unencrypted_storage",
    }
    finding = scanner.Finding(
        "checkov", "terraform/aws/s3.tf", "aws_s3_bucket.logs", 3, "encryption", ""
    )
    assert not evaluate.item_found(item, finding, ["encrypt"])
    finding = scanner.Finding(
        "checkov", "terraform/aws/s3.tf", "aws_s3_bucket.data", 3, "encryption", ""
    )
    assert evaluate.item_found(item, finding, ["encrypt"])


def test_item_found_kubernetes_by_file():
    item = {
        "target": "kubernetes",
        "file": "tests/k8s/01-privileged.yaml",
        "resource": "privileged-pod",
        "category": "privileged",
    }
    finding = scanner.Finding("trivy", "tests/k8s/01-privileged.yaml", "", 4, "Privileged", "")
    assert evaluate.item_found(item, finding, ["privileged"])
    other = scanner.Finding("trivy", "tests/k8s/02-hostpath.yaml", "", 4, "Privileged", "")
    assert not evaluate.item_found(item, other, ["privileged"])
