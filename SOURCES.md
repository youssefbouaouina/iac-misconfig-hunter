# Sources and licences

| Target / tool | Version | Licence | Use |
|---|---|---|---|
| TerraGoat | commit `729f8da62c6a85ce4af5ad3d123de97776d954c4` | Apache-2.0 | Vulnerable Terraform target |
| Kubernetes manifests | written for this repo | MIT | 15 vulnerable manifests |
| Checkov | 3.2.458 | Apache-2.0 | Scanner |
| Trivy | 0.76.1 | Apache-2.0 | Scanner (`trivy config`) |
| KICS | 2.2.0 (container image) | Apache-2.0 | Scanner |
| kube-linter | 0.8.3 | Apache-2.0 | Kubernetes scanner |
| PyYAML / pytest / ruff | 6.0.2 / 8.3.4 / 0.8.4 | MIT | Evaluation and CI |

TerraGoat is cloned at run time by `scripts/fetch_targets.sh`; its source is not vendored in
this repository (only the `fixed/` copy of the AWS module is committed, with the Apache-2.0
licence of the original project). The vulnerable Kubernetes manifests are original work.
