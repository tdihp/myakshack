# Samples and scripts for working with Azure Kubernetes Custom Policy

This directory contains example and scripts for building and publishing Azure
Policy definitions of custom Kubernetes policies. The intent is to showcase
the walkthrough of creating a Kubernetes Custom Policy from scratch, while try
to move away some distractions dealing with the full Azure policy json
definition.

## Workflow of adding a new policy

### Step0: Prerequisites

Running the scripts requires below tools:

* bash
* GNU coreutils (for `cat` and `base64`), alternatives like busybox is untested
* [azure-cli](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli)
* [jq](https://jqlang.github.io/jq/)
* [Gator](https://open-policy-agent.github.io/gatekeeper/website/docs/gator/#installation)

To install latest Gator on Linux at momemnt of writing:

  curl -L https://github.com/open-policy-agent/gatekeeper/releases/download/v3.13.4/gator-v3.13.4-linux-amd64.tar.gz | sudo tar -C/usr/local/bin -zx

### Step1: Copy and rename an existing template

Find a policy directory in `policies` directory, copy and rename.

### Step2: Update policy details

Including below details:

* `extra_params.json`: All input parameters that will show in portal.
* `rule_overrides.json`: Overriding `.then.details` of `rules.template.json`,
  mainly used for specifying `apiGroups` and `kinds`. There is no need to
  update `then.details.values`, as all parameters in `extra_params.json` will be
  populated here.
* `template.yaml`: Speicifying the
  [OPA constraint template](https://open-policy-agent.github.io/gatekeeper/website/docs/constrainttemplates),
  including the embedded [rego script]https://www.openpolicyagent.org/docs/latest/policy-reference/).
  Optionally, utilize [Rego playground](https://play.openpolicyagent.org/) for
  developing Rego script.
* `suite.yaml`: A test suite to be checked with `gator verify`. All contents under
  `samples` are also used for test suite. See
  [gator documentation](https://open-policy-agent.github.io/gatekeeper/website/docs/gator/#the-gator-verify-subcommand)
  for further detail.

### Step3: Test the new ConstraintTemplate

Run `gator verify .` in the policy directory

### Step4: Build and publish policy

Run `bash build-policy.sh <policy-name>` or `bash build-policy all`. This tool
builds the complete output jsons required by `az policy definition create` 
command in `output` direcory. Command line parameters of the
`az policy definiton create` command needed to publish the policy definition
will be printed in stdout.

### Step5: Configure policy assignments

After publishing, the policy definition should be visible both in portal and
with `az policy definition list --query "[?policyType == 'Custom'] | [?mode == 'Microsoft.Kubernetes.Data']" -otable`.

Either use [portal](https://learn.microsoft.com/en-us/azure/governance/policy/assign-policy-portal)
or [azure-cli](https://learn.microsoft.com/en-us/azure/governance/policy/assign-policy-azurecli)
to create assignment.

Note: Remember to finetune parameters before assigning.

For a AKS cluster or connected Kubenetes cluster with Azure policy enabled, we
should find the constraint template when synced, by
`kubectl get ConstraintTemplate`.
