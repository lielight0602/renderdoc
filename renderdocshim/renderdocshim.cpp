/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2014-2026 Baldur Karlsson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 ******************************************************************************/

// This project deliberately references only kernel32.dll (ie. not even the CRT)
// so that when inserted into an application it has as small an overhead/impact
// as possible. Ideally it would be present only to be a pass-through hook and
// the first time only to allocate a little, check if this process should be hooked
// and load the renderdoc dll.
//
// The no-CRT restriction causes some awkward bits and pieces but the dll is simple
// enough that it's not a big issue.

#include "renderdocshim.h"
#include <windows.h>

struct CaptureOptions;
typedef void(__cdecl *pINTERNAL_SetCaptureOptions)(const CaptureOptions *opts);
typedef void(__cdecl *pINTERNAL_SetLogFile)(const char *logfile);
typedef void(__cdecl *pINTERNAL_SetDebugLogFile)(const char *logfile);

// Diagnostic logging for the shim.
//
// Kept OFF by default so that a normal build behaves exactly like upstream: this DLL is loaded
// into *every* GUI process while the global hook is armed, so logging from each of them would
// add file IO everywhere and produce a very noisy log.
//
// Flip to 1 to build a diagnostic shim that appends every step to <temp>\rendertestshim.log.
// Set it back to 0 once the diagnosis is done.
//
// (An alternative that needs no file IO at all is `#define LOGPRINT(txt) OutputDebugStringW(txt)`,
//  with the output captured by DbgView.)
#define RENDERTEST_SHIM_LOG 0

#if RENDERTEST_SHIM_LOG
// deliberately no CRT here - only kernel32 and plain Win32 APIs

// tiny no-CRT string builders, only used to format the PID/error-code prefixes
static void ShimAppendStr(wchar_t *dst, int &pos, const wchar_t *src)
{
  while(*src)
    dst[pos++] = *src++;
}

static void ShimAppendUInt(wchar_t *dst, int &pos, DWORD val, DWORD radix)
{
  wchar_t tmp[16];
  int n = 0;

  if(val == 0)
    tmp[n++] = L'0';

  while(val)
  {
    DWORD digit = val % radix;
    tmp[n++] = (wchar_t)(digit < 10 ? (L'0' + digit) : (L'a' + digit - 10));
    val /= radix;
  }

  while(n > 0)
    dst[pos++] = tmp[--n];
}

static void ShimLogLine(const wchar_t *txt)
{
  wchar_t path[MAX_PATH + 1] = {};
  DWORD len = GetTempPathW(MAX_PATH, path);

  static const wchar_t filename[] = L"rendertestshim.log";
  const int filenamelen = (int)(sizeof(filename) / sizeof(wchar_t));

  if(len == 0 || len + filenamelen > MAX_PATH + 1)
    return;

  for(int i = 0; i < filenamelen; i++)
    path[len + i] = filename[i];

  HANDLE f = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

  if(f == INVALID_HANDLE_VALUE)
    return;

  // every line is prefixed with our PID. While the hook is armed this file is written by every GUI
  // process on the machine at once, with no locking and with each LOGPRINT being its own write, so
  // records from different processes interleave and become unreadable. The PID makes them groupable
  // again without needing any synchronisation.
  wchar_t prefix[32];
  int prefixlen = 0;
  prefix[prefixlen++] = L'[';
  ShimAppendUInt(prefix, prefixlen, GetCurrentProcessId(), 10);
  prefix[prefixlen++] = L']';
  prefix[prefixlen++] = L' ';

  int txtlen = 0;
  while(txt[txtlen])
    txtlen++;

  DWORD written = 0;
  WriteFile(f, prefix, (DWORD)(prefixlen * sizeof(wchar_t)), &written, NULL);
  WriteFile(f, txt, (DWORD)(txtlen * sizeof(wchar_t)), &written, NULL);
  WriteFile(f, L"\r\n", 2 * sizeof(wchar_t), &written, NULL);

  CloseHandle(f);
}

#define LOGPRINT(txt) ShimLogLine(txt)
#else
#define LOGPRINT(txt) \
  do                  \
  {                   \
  } while(0)
#endif

void CheckHook()
{
  ShimData *data = NULL;

#if RENDERTEST_SHIM_LOG
  // log which process we ended up in before anything can fail, so that a process where the
  // shim loaded but bailed early (no mapping / no pathmatch) is still identifiable
  {
    wchar_t selfpath[MAX_PATH + 1] = {};
    GetModuleFileNameW(NULL, selfpath, MAX_PATH);
#ifdef WIN64
    LOGPRINT(L"renderdocshim: CheckHook entered for (shim64)");
#else
    LOGPRINT(L"renderdocshim: CheckHook entered for (shim32)");
#endif
    LOGPRINT(selfpath);
  }
#endif

  HANDLE datahandle = OpenFileMappingA(FILE_MAP_READ, FALSE, GLOBAL_HOOK_DATA_NAME);

  if(datahandle == NULL)
  {
    LOGPRINT(L"renderdocshim: can't open global data\n");
    return;
  }

  data = (ShimData *)MapViewOfFile(datahandle, FILE_MAP_READ, 0, 0, sizeof(ShimData));

  if(data == NULL)
  {
    CloseHandle(datahandle);
    LOGPRINT(L"renderdocshim: can't map global data\n");
    return;
  }

  if(data->pathmatchstring[0] == 0 || data->pathmatchstring[1] == 0 ||
     data->pathmatchstring[2] == 0 || data->pathmatchstring[3] == 0)
  {
    LOGPRINT(L"renderdocshim: invalid pathmatchstring: '");
    LOGPRINT(data->pathmatchstring);
    LOGPRINT(L"'\n");

    UnmapViewOfFile(data);
    CloseHandle(datahandle);
    return;
  }

  // no new[], need to use VirtualAlloc
  const int exepathLen = 1024;
  wchar_t *exepath = (wchar_t *)VirtualAlloc(NULL, exepathLen * sizeof(wchar_t),
                                             MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

  if(exepath)
  {
    // no memset :).
    for(int i = 0; i < exepathLen; i++)
      exepath[i] = 0;

    GetModuleFileNameW(NULL, exepath, exepathLen - 1);

    // no str*cmp functions
    int find = FindStringOrdinal(FIND_FROMSTART, exepath, -1, data->pathmatchstring, -1, TRUE);

    if(find >= 0)
    {
      LOGPRINT(L"renderdocshim: Hooking into '");
      LOGPRINT(exepath);
      LOGPRINT(L"', based on '");
      LOGPRINT(data->pathmatchstring);
      LOGPRINT(L"'\n");

      HMODULE mod = LoadLibraryW(data->rdocpath);

#if RENDERTEST_SHIM_LOG
      DWORD directErr = mod ? 0 : GetLastError();
      DWORD directAttrs = mod ? 0 : GetFileAttributesW(data->rdocpath);
#endif

      // If the plain load failed, retry with the search path anchored at the dll's own directory.
      // When resolving the imports of a dll the loader searches the directory of the *executable*
      // first, so a game that ships its own CRT next to the exe (MSVCP140/VCRUNTIME140/api-ms-win-
      // crt-*) shadows the system copies for us. That's a genuine ordering difference, and anchoring
      // at our own directory is the correct fix rather than a workaround.
      if(mod == NULL)
        mod = LoadLibraryExW(data->rdocpath, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);

      if(mod)
      {
#if RENDERTEST_SHIM_LOG
        if(directErr != 0)
        {
          wchar_t fb[128];
          int fbpos = 0;
          ShimAppendStr(fb, fbpos, L"renderdocshim: plain LoadLibraryW failed err=");
          ShimAppendUInt(fb, fbpos, directErr, 10);
          ShimAppendStr(fb, fbpos, L" attrs=0x");
          ShimAppendUInt(fb, fbpos, directAttrs, 16);
          ShimAppendStr(fb, fbpos, L" - succeeded with LOAD_WITH_ALTERED_SEARCH_PATH");
          fb[fbpos] = 0;
          LOGPRINT(fb);
        }
#endif

        pINTERNAL_SetCaptureOptions setopts =
            (pINTERNAL_SetCaptureOptions)GetProcAddress(mod, "INTERNAL_SetCaptureOptions");
        pINTERNAL_SetLogFile setlogfile =
            (pINTERNAL_SetLogFile)GetProcAddress(mod, "INTERNAL_SetLogFile");
        pINTERNAL_SetDebugLogFile setdebuglog =
            (pINTERNAL_SetDebugLogFile)GetProcAddress(mod, "INTERNAL_SetDebugLogFile");

        if(setopts)
          setopts((const CaptureOptions *)data->opts);

        if(setlogfile && data->capfile[0])
          setlogfile(data->capfile);

        if(setdebuglog && data->debuglog[0])
          setdebuglog(data->debuglog);
      }
      else
      {
        // previously silent - this is one of the ways the hook can fail without a trace.
        //
        // Log both error codes and the file attributes. A readable dll that still refuses to load
        // means the *target process* is rejecting it (module filter / policy / AV) rather than it
        // being missing or corrupt - GetLastError tells the two apart:
        // 5 = access denied (policy/AV), 126 = dependency not found, 1114 = DllMain returned FALSE.
#if RENDERTEST_SHIM_LOG
        wchar_t errbuf[160];
        int errpos = 0;
        ShimAppendStr(errbuf, errpos, L"renderdocshim: LoadLibraryW FAILED direct err=");
        ShimAppendUInt(errbuf, errpos, directErr, 10);
        ShimAppendStr(errbuf, errpos, L" fallback err=");
        ShimAppendUInt(errbuf, errpos, GetLastError(), 10);
        ShimAppendStr(errbuf, errpos, L" fileattrs=0x");
        ShimAppendUInt(errbuf, errpos, directAttrs, 16);
        errbuf[errpos] = 0;

        LOGPRINT(errbuf);
#endif
        LOGPRINT(data->rdocpath);
      }
    }
    else
    {
      LOGPRINT(L"renderdocshim: NOT Hooking into '");
      LOGPRINT(exepath);
      LOGPRINT(L"', based on '");
      LOGPRINT(data->pathmatchstring);
      LOGPRINT(L"'\n");
    }

    VirtualFree(exepath, 0, MEM_RELEASE);
  }
  else
  {
    LOGPRINT(L"renderdocshim: Failed to allocate exepath\n");
  }

  UnmapViewOfFile(data);
  CloseHandle(datahandle);
}

DWORD WINAPI CheckHookThread(LPVOID param)
{
  CheckHook();

  // this makes sure that we remove the reference to the shim dll and unload from
  // the target process. That minimises the impact of having the dll inserted into
  // every process
  FreeLibraryAndExitThread((HMODULE)param, 0);
  return 0;
}

BOOL APIENTRY dll_entry(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
  if(ul_reason_for_call == DLL_PROCESS_ATTACH)
  {
    DisableThreadLibraryCalls(hModule);

    // create a thread so that we can perform more complex actions (DllMain must be minimal
    // in size, even this is a bit dodgy).
    CreateThread(NULL, 0, CheckHookThread, (LPVOID)hModule, 0, NULL);
  }

  return TRUE;
}
