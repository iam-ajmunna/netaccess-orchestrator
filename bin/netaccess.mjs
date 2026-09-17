#!/usr/bin/env node

/**
 * NetAccess Orchestrator — Executable CLI Entrypoint
 */

import { runCli } from "../src/netaccess/cli.js";

const exitCode = await runCli(process.argv.slice(2));
process.exit(exitCode);
