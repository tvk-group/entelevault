#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { verifyProductionBoundary } from "../src/production-boundary.mjs";

const repositoryRoot = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const report = await verifyProductionBoundary(repositoryRoot);
console.log(JSON.stringify(report, null, 2));
if (report.status !== "PASS") process.exitCode = 1;
