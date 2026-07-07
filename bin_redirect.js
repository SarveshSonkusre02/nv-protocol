#!/usr/bin/env node

/**
 * $nv$ Protocol Binary Redirector
 * Dynamically detects host operating system, locates the appropriate
 * zero-dependency precompiled binary, and executes it with forwarded pipes.
 * Fallbacks to executing the local Python script if in development mode.
 */

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const platform = os.platform();
const binaryName = platform === 'win32' ? 'nvenv.exe' : 'nvenv';
const binaryPath = path.join(__dirname, 'bin', platform, binaryName);

const args = process.argv.slice(2);

// Check if precompiled native binary is present for the target platform
if (fs.existsSync(binaryPath)) {
    // Spawns the native compiled executable binary directly
    const child = spawn(binaryPath, args, { stdio: 'inherit' });
    child.on('close', (code) => {
        process.exit(code === null ? 1 : code);
    });
    child.on('error', (err) => {
        console.error(`[nv-redirect] Failed to start native process: ${err.message}`);
        process.exit(1);
    });
} else {
    // Development Fallback: If native binary hasn't been built yet, execute using local python context
    const devScriptPath = path.join(__dirname, 'nv.py');
    if (fs.existsSync(devScriptPath)) {
        // Resolve target python command
        const pythonCmd = platform === 'win32' ? 'python' : 'python3';
        const childArgs = [devScriptPath, ...args];

        // Use shell context for Windows fallback execution stability
        const useShell = platform === 'win32';

        const child = spawn(pythonCmd, childArgs, { stdio: 'inherit', shell: useShell });
        child.on('close', (code) => {
            process.exit(code === null ? 1 : code);
        });
        child.on('error', (err) => {
            console.error(`[nv-redirect-dev] Failed to execute dev script: ${err.message}`);
            process.exit(1);
        });
    } else {
        console.error(`[nv-redirect] Critical Error: Precompiled binary not found at: ${binaryPath}`);
        console.error(`[nv-redirect] Development source script was also missing at: ${devScriptPath}`);
        console.error("[nv-redirect] Please check your installation or build binaries using 'python build_binary.py'");
        process.exit(1);
    }
}
