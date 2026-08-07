import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { extname, relative, resolve, sep } from "node:path";
import { VaultLabError } from "./errors.mjs";

const SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".github",
  ".next",
  "coverage",
  "node_modules",
  "vaultlab"
]);

const SCANNED_EXTENSIONS = new Set([
  ".bash",
  ".bat",
  ".cjs",
  ".cmd",
  ".css",
  ".go",
  ".gradle",
  ".html",
  ".java",
  ".js",
  ".json",
  ".jsx",
  ".kt",
  ".kts",
  ".mjs",
  ".php",
  ".ps1",
  ".py",
  ".rb",
  ".rs",
  ".sh",
  ".swift",
  ".toml",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml"
]);

const MAX_SCANNED_FILES = 10_000;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const EXTENSIONLESS_BUILD_FILES = new Set(["Dockerfile", "Makefile", "Procfile"]);

const RULES = Object.freeze([
  {
    id: "VL-PROD-IMPORT",
    pattern: /(?:@enteleclos\/vaultlab|(?:from|require|import)\s*\(?\s*["'][^"']*vaultlab)/iu
  },
  {
    id: "VL-PROD-SCHEMA-MARKER",
    pattern: /entelevault\.vaultlab\.synthetic\.v1/iu
  },
  {
    id: "VL-PROD-FIXTURE-MARKER",
    pattern: /(?:SYNTHETIC-NONVALUE|ENTELE-VAULTLAB-1|vlab_[0-9a-f]{32})/iu
  },
  {
    id: "VL-PROD-TEST-CREDENTIAL",
    pattern: /VaultLab-[A-Za-z0-9_-]{8,}/u
  }
]);

function portablePath(path) {
  return path.split(sep).join("/");
}

async function walk(rootPath, currentPath, state) {
  const entries = await readdir(currentPath, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, "en"));
  for (const entry of entries) {
    const absolutePath = resolve(currentPath, entry.name);
    const relativePath = portablePath(relative(rootPath, absolutePath));

    if (entry.isSymbolicLink()) {
      state.skippedSymlinks += 1;
      state.violations.push({ path: relativePath, rule: "VL-PROD-SYMLINK" });
      continue;
    }
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRECTORIES.has(entry.name)) {
        await walk(rootPath, absolutePath, state);
      }
      continue;
    }
    if (
      !entry.isFile() ||
      (!SCANNED_EXTENSIONS.has(extname(entry.name).toLowerCase()) &&
        !EXTENSIONLESS_BUILD_FILES.has(entry.name))
    ) {
      continue;
    }

    state.scannedFiles += 1;
    if (state.scannedFiles > MAX_SCANNED_FILES) {
      throw new VaultLabError("VAULTLAB_SCAN_LIMIT", "Production boundary file limit exceeded");
    }

    const fileInfo = await lstat(absolutePath);
    if (fileInfo.size > MAX_FILE_BYTES) {
      state.violations.push({ path: relativePath, rule: "VL-PROD-FILE-SIZE" });
      continue;
    }
    state.totalBytes += fileInfo.size;
    if (state.totalBytes > MAX_TOTAL_BYTES) {
      throw new VaultLabError("VAULTLAB_SCAN_LIMIT", "Production boundary byte limit exceeded");
    }

    const content = await readFile(absolutePath, "utf8");
    for (const rule of RULES) {
      if (rule.pattern.test(content)) {
        state.violations.push({ path: relativePath, rule: rule.id });
      }
    }
  }
}

export async function verifyProductionBoundary(rootPath) {
  if (typeof rootPath !== "string" || rootPath.length === 0) {
    throw new VaultLabError("VAULTLAB_SCAN_ROOT_REJECTED", "Repository root is required");
  }
  const resolvedRoot = await realpath(resolve(rootPath));
  const state = {
    scannedFiles: 0,
    skippedSymlinks: 0,
    totalBytes: 0,
    violations: []
  };
  await walk(resolvedRoot, resolvedRoot, state);
  return {
    schema: "entelevault.vaultlab.production-boundary-report.v1",
    status: state.violations.length === 0 ? "PASS" : "FAIL",
    scannedFiles: state.scannedFiles,
    skippedSymlinks: state.skippedSymlinks,
    scannedBytes: state.totalBytes,
    violations: state.violations
  };
}
