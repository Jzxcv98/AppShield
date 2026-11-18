// SPDX-License-Identifier: GPL-3.0-only
#pragma once

// Shared Windows ABI; include windows.h or fltKernel.h first. Only x64 is built.
#define ASF_PROTOCOL 1u
#define ASF_PORT_NAME L"\\AppShieldFilterPort"
#define ASF_QUERY 1u
#define ASF_BIND  2u
#define ASF_READ  1u
#define ASF_WRITE 2u
#define ASF_MAX_RULES 24u
#define ASF_PATH_CHARS 512u

typedef struct _ASF_REQUEST {
    ULONG Version;
    ULONG Operation;
    ULONGLONG ProcessHandle;   // Valid only in the connected administrator's process
    ULONG RuleCount;
    ULONG Reserved;
} ASF_REQUEST;

typedef struct _ASF_RULE {
    ULONG Access;              // READ, or READ | WRITE
    ULONG Chars;               // UTF-16 code units, excludes terminator
    WCHAR Path[ASF_PATH_CHARS]; // Canonical NT path of an existing directory
} ASF_RULE;

typedef struct _ASF_REPLY {
    ULONG Version;
    ULONG ManagedProcesses;
    ULONG HandleBound;         // Query: whether this exact process object has a policy
    ULONG Reserved;
} ASF_REPLY;

C_ASSERT(sizeof(ASF_REQUEST) == 24);
C_ASSERT(sizeof(ASF_RULE) == 1032);
C_ASSERT(sizeof(ASF_REPLY) == 16);
