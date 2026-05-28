#!/usr/bin/env python3

import aws_cdk as cdk
from Detective_Stack import SecurityGroupSshCheckStack

app = cdk.App()

SecurityGroupSshCheckStack(
    app,
    "SecurityGroupSSHDetectiveStack",
)

app.synth()