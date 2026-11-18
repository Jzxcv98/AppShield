// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "Protocol.h"

// Shared by the kernel callbacks and by the offline, unprivileged policy checks.
static __inline BOOLEAN AsfAllowsOpen(ULONG options, BOOLEAN targetDirectory) {
    return (options >> 24) == FILE_OPEN && !targetDirectory &&
        !(options & (FILE_OPEN_BY_FILE_ID | FILE_DELETE_ON_CLOSE | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT));
}
static __inline BOOLEAN AsfAllowsFinalObject(ULONG attributes, BOOLEAN directory, ULONG links, BOOLEAN deletePending) {
    return !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) && !deletePending && (directory || links == 1);
}
static __inline BOOLEAN AsfPrefix(const WCHAR *a, const WCHAR *b, ULONG length) {
    ULONG i;
    for (i = 0; i < length; ++i) if (a[i] != b[i]) return FALSE;
    return TRUE;
}
static __inline BOOLEAN AsfValidRoot(const ASF_RULE *r) {
    static const WCHAR prefix[] = L"\\Device\\HarddiskVolume";
    const ULONG prefixLen = (sizeof(prefix) / sizeof(WCHAR)) - 1;
    ULONG i, start;
    if ((r->Access != ASF_READ && r->Access != (ASF_READ | ASF_WRITE)) ||
        r->Chars >= ASF_PATH_CHARS || r->Chars <= prefixLen + 2 || r->Path[r->Chars] != 0 ||
        !AsfPrefix(r->Path, prefix, prefixLen)) return FALSE;
    i = prefixLen;
    while (i < r->Chars && r->Path[i] >= L'0' && r->Path[i] <= L'9') ++i;
    if (i == prefixLen || i >= r->Chars || r->Path[i] != L'\\') return FALSE;
    start = ++i;
    for (; i <= r->Chars; ++i) {
        WCHAR c = r->Path[i];
        if (i == r->Chars || c == L'\\') {
            if (i == start || r->Path[i - 1] == L'.' || r->Path[i - 1] == L' ') return FALSE;
            start = i + 1;
        } else if (c < L' ' || c == L':' || c == L'/' || c == L'*' || c == L'?' ||
                   c == L'"' || c == L'<' || c == L'>' || c == L'|') return FALSE;
    }
    return TRUE;
}

static __inline ULONG AsfGrantForName(const ASF_RULE *rules, ULONG count, const WCHAR *name, ULONG chars) {
    ULONG i, longest = 0, grant = 0;
    for (i = 0; i < count; ++i) {
        const ASF_RULE *r = &rules[i];
        if (r->Chars <= chars && r->Chars >= longest &&
            (r->Chars == chars || name[r->Chars] == L'\\') && AsfPrefix(r->Path, name, r->Chars)) {
            // Exact case preserves isolation on per-directory case-sensitive NTFS trees.
            grant = r->Chars == longest ? (grant & r->Access) : r->Access;
            longest = r->Chars;
        }
    }
    return grant;
}
