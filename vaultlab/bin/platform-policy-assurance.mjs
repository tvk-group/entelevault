#!/usr/bin/env node
import { runPlatformPolicyAssurance } from "../src/platform-policy-assurance.mjs";

process.stdout.write(`${JSON.stringify(runPlatformPolicyAssurance(), null, 2)}\n`);
