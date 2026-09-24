/******************************************************************************
 * The MIT License (MIT)
 *
 * Copyright (c) 2015-2026 Baldur Karlsson
 * Copyright (c) 2014 Crytek
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

// must be separate so that it's included first and not sorted by clang-format
#include <windows.h>

#include <tlhelp32.h>
#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include "common/common.h"
#include "common/threading.h"
#include "hooks/hooks.h"
#include "os/os_specific.h"
#include "strings/string_utils.h"

#define VERBOSE_DEBUG_HOOK OPTION_OFF

// map from address of IAT entry, to original contents
std::map<void **, void *> s_InstalledHooks;
Threading::CriticalSection installedLock;

bool ApplyHook(FunctionHook &hook, void **IATentry, bool &already)
{
  DWORD oldProtection = PAGE_EXECUTE;

  if(*IATentry == hook.hook)
  {
    already = true;
    return true;
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("Patching IAT for %s: %p to %p", hook.function.c_str(), IATentry, hook.hook);
#endif

  {
    SCOPED_LOCK(installedLock);
    if(s_InstalledHooks.find(IATentry) == s_InstalledHooks.end())
      s_InstalledHooks[IATentry] = *IATentry;
  }

  BOOL success = VirtualProtect(IATentry, sizeof(void *), PAGE_READWRITE, &oldProtection);
  if(!success)
  {
    RDCERR("Failed to make IAT entry writeable 0x%p", IATentry);
    return false;
  }

  *IATentry = hook.hook;

  success = VirtualProtect(IATentry, sizeof(void *), oldProtection, &oldProtection);
  if(!success)
  {
    RDCERR("Failed to restore IAT entry protection 0x%p", IATentry);
    return false;
  }

  return true;
}

struct DllHookset
{
  HMODULE module = NULL;
  bool hooksfetched = false;
  // if we have multiple copies of the dll loaded (unlikely), the other module handles will be
  // stored here
  rdcarray<HMODULE> altmodules;
  rdcarray<FunctionHook> FunctionHooks;
  DWORD OrdinalBase = 0;
  rdcarray<rdcstr> OrdinalNames;
  rdcarray<FunctionLoadCallback> Callbacks;
  Threading::CriticalSection ordinallock;

  void FetchOrdinalNames()
  {
    SCOPED_LOCK(ordinallock);

    // return if we already fetched the ordinals
    if(!OrdinalNames.empty())
      return;

    byte *baseAddress = (byte *)module;

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("FetchOrdinalNames");
#endif

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)baseAddress;

    if(dosheader->e_magic != 0x5a4d)
      return;

    char *PE00 = (char *)(baseAddress + dosheader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(PE00 + 4);
    PIMAGE_OPTIONAL_HEADER optHeader =
        (PIMAGE_OPTIONAL_HEADER)((BYTE *)fileHeader + sizeof(IMAGE_FILE_HEADER));

    DWORD eatOffset = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    IMAGE_EXPORT_DIRECTORY *exportDesc = (IMAGE_EXPORT_DIRECTORY *)(baseAddress + eatOffset);

    WORD *ordinals = (WORD *)(baseAddress + exportDesc->AddressOfNameOrdinals);
    DWORD *names = (DWORD *)(baseAddress + exportDesc->AddressOfNames);

    DWORD count = RDCMIN(exportDesc->NumberOfFunctions, exportDesc->NumberOfNames);

    WORD maxOrdinal = 0;
    for(DWORD i = 0; i < count; i++)
      maxOrdinal = RDCMAX(maxOrdinal, ordinals[i]);

    OrdinalBase = exportDesc->Base;
    OrdinalNames.resize(maxOrdinal + 1);

    for(DWORD i = 0; i < count; i++)
    {
      OrdinalNames[ordinals[i]] = (char *)(baseAddress + names[i]);

#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("ordinal found: '%s' %u", OrdinalNames[ordinals[i]].c_str(), (uint32_t)ordinals[i]);
#endif
    }
  }
};

struct CachedHookData
{
  bool hookAll = true;

  std::map<rdcstr, DllHookset> DllHooks;
  HMODULE ownmodule = NULL;
  Threading::CriticalSection lock;

  std::set<rdcstr> ignores;

  bool missedOrdinals = false;
  std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> libraryIntercept;

  int32_t posthooking = 0;

  void ApplyHooks(const char *modName, HMODULE module)
  {
    char lowername[512] = {};

    {
      size_t i = 0;
      while(modName[i])
      {
        lowername[i] = (char)tolower(modName[i]);
        i++;
      }
      lowername[i] = 0;
    }

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== ApplyHooks(%s, %p)", modName, module);
#endif

    // fraps seems to non-safely modify the assembly around the hook function, if
    // we modify its import descriptors it leads to a crash as it hooks OUR functions.
    // instead, skip modifying the import descriptors, it will hook the 'real' d3d functions
    // and we can call them and have fraps + renderdoc playing nicely together.
    // we also exclude some other overlay renderers here, such as steam's
    //
    // Also we exclude ourselves here - just in case the application has already loaded
    // renderdoc.dll, or tries to load it.
    if(strstr(lowername, "fraps") || strstr(lowername, "gameoverlayrenderer") ||
       strstr(lowername, STRINGIZE(RDOC_BASE_NAME) ".dll") == lowername)
      return;

    // set module pointer if we are hooking exports from this module
    for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
    {
      if(!_stricmp(it->first.c_str(), modName))
      {
        if(it->second.module == NULL)
        {
          it->second.module = module;

          it->second.hooksfetched = true;

          // fetch all function hooks here, since we want to fill out the original function pointer
          // even in case nothing imports from that function (which means it would not get filled
          // out through FunctionHook::ApplyHook)
          for(FunctionHook &hook : it->second.FunctionHooks)
          {
            if(hook.orig && *hook.orig == NULL)
              *hook.orig = GetProcAddress(module, hook.function.c_str());
          }

          it->second.FetchOrdinalNames();
        }
        else if(it->second.module != module)
        {
          // if it's already in altmodules, bail
          bool already = false;

          for(size_t i = 0; i < it->second.altmodules.size(); i++)
          {
            if(it->second.altmodules[i] == module)
            {
              already = true;
              break;
            }
          }

          if(already)
            break;

          // check if the previous module is still valid
          SetLastError(0);
          char filename[MAX_PATH] = {};
          GetModuleFileNameA(it->second.module, filename, MAX_PATH - 1);
          DWORD err = GetLastError();
          char *slash = strrchr(filename, L'\\');

          rdcstr basename = slash ? strlower(rdcstr(slash + 1)) : "";

          if(err == 0 && basename == it->first)
          {
            // previous module is still loaded, add this to the alt modules list
            it->second.altmodules.push_back(module);
          }
          else
          {
            // previous module is no longer loaded or there's a new file there now, add this as the
            // new location
            RDCWARN("%s moved from %p to %p, re-initialising orig pointers", it->first.c_str(),
                    it->second.module, module);

            // we also need to re-initialise the hooks as the orig pointers are now stale
            for(FunctionHook &hook : it->second.FunctionHooks)
            {
              if(hook.orig)
                *hook.orig = GetProcAddress(module, hook.function.c_str());
            }

            it->second.module = module;
          }
        }
      }
    }

    // for safety (and because we don't need to), ignore these modules
    if(!_stricmp(modName, "kernel32.dll") || !_stricmp(modName, "powrprof.dll") ||
       !_stricmp(modName, "CoreMessaging.dll") || !_stricmp(modName, "opengl32.dll") ||
       !_stricmp(modName, "gdi32.dll") || !_stricmp(modName, "gdi32full.dll") ||
       !_stricmp(modName, "windows.storage.dll") || !_stricmp(modName, "nvoglv32.dll") ||
       !_stricmp(modName, "nvoglv64.dll") || !_stricmp(modName, "vulkan-1.dll") ||
       !_stricmp(modName, "atio6axx.dll") || !_stricmp(modName, "atioglxx.dll") ||
       !_stricmp(modName, "nvcuda.dll") || strstr(lowername, "cudart") == lowername ||
       strstr(lowername, "msvcr") == lowername || strstr(lowername, "msvcp") == lowername ||
       strstr(lowername, "nv-vk") == lowername || strstr(lowername, "amdvlk") == lowername ||
       strstr(lowername, "igvk") == lowername || strstr(lowername, "nvopencl") == lowername ||
       strstr(lowername, "nvapi") == lowername)
      return;

    if(ignores.find(lowername) != ignores.end())
      return;

    // the module could have been unloaded after our toolhelp snapshot, especially if we spent a
    // long time
    // dealing with a previous module (like adding our hooks).
    wchar_t modpath[1024] = {0};
    GetModuleFileNameW(module, modpath, 1023);
    if(modpath[0] == 0)
      return;

    // windows 11 and newer versions have weird hotpatch DLLs that don't act like real DLLs. The
    // LoadLibraryW below will fail for these DLLs even when using the module path provided.
    // Only check the path for DLLs that might be a windows-hotpatch but if it matches we'll skip
    // hooking these to avoid problems
    if(strstr(lowername, "hotpatch"))
    {
      wchar_t lowerpath[1024] = {};

      size_t i = 0;
      while(modpath[i])
      {
        lowerpath[i] = towlower(modpath[i]);
        i++;
      }
      lowerpath[i] = 0;

      if(wcsstr(lowerpath, L"\\windows\\winsxs\\"))
        return;
    }

    // increment the module reference count, so it doesn't disappear while we're processing it
    // there's a very small race condition here between if GetModuleFileName returns, the module is
    // unloaded then we load it again. The only way around that is inserting very scary locks
    // between here
    // and FreeLibrary that I want to avoid. Worst case, we load a dll, hook it, then unload it
    // again.
    HMODULE refcountModHandle = LoadLibraryW(modpath);
    RDCASSERTEQUAL(refcountModHandle, module);
    byte *baseAddress = (byte *)refcountModHandle;

    PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)baseAddress;

    if(dosheader->e_magic != 0x5a4d)
    {
      RDCDEBUG("Ignoring module %s, since magic is 0x%04x not 0x%04x", modName,
               (uint32_t)dosheader->e_magic, 0x5a4dU);
      FreeLibrary(refcountModHandle);
      return;
    }

    char *PE00 = (char *)(baseAddress + dosheader->e_lfanew);
    PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(PE00 + 4);
    PIMAGE_OPTIONAL_HEADER optHeader =
        (PIMAGE_OPTIONAL_HEADER)((BYTE *)fileHeader + sizeof(IMAGE_FILE_HEADER));

    DWORD iatOffset = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

    IMAGE_IMPORT_DESCRIPTOR *importDesc = (IMAGE_IMPORT_DESCRIPTOR *)(baseAddress + iatOffset);

#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("=== import descriptors:");
#endif

    while(iatOffset && importDesc->FirstThunk)
    {
      const char *dllName = (const char *)(baseAddress + importDesc->Name);

#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("found IAT for %s", dllName);
#endif

      DllHookset *hookset = NULL;

      for(auto it = DllHooks.begin(); it != DllHooks.end(); ++it)
        if(!_stricmp(it->first.c_str(), dllName))
          hookset = &it->second;

      if(hookset && importDesc->OriginalFirstThunk > 0)
      {
        IMAGE_THUNK_DATA *origFirst =
            (IMAGE_THUNK_DATA *)(baseAddress + importDesc->OriginalFirstThunk);
        IMAGE_THUNK_DATA *first = (IMAGE_THUNK_DATA *)(baseAddress + importDesc->FirstThunk);

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Hooking imports for %s", dllName);
#endif

        while(origFirst->u1.AddressOfData)
        {
          void **IATentry = (void **)&first->u1.AddressOfData;

          struct hook_find
          {
            bool operator()(const FunctionHook &a, const char *b)
            {
              return strcmp(a.function.c_str(), b) < 0;
            }
          };

#if ENABLED(RDOC_X64)
          if(IMAGE_SNAP_BY_ORDINAL64(origFirst->u1.AddressOfData))
#else
          if(IMAGE_SNAP_BY_ORDINAL32(origFirst->u1.AddressOfData))
#endif
          {
            // low bits of origFirst->u1.AddressOfData contain an ordinal
            WORD ordinal = IMAGE_ORDINAL64(origFirst->u1.AddressOfData);

#if ENABLED(VERBOSE_DEBUG_HOOK)
            RDCDEBUG("Found ordinal import %u", (uint32_t)ordinal);
#endif

            if(!hookset->OrdinalNames.empty())
            {
              if(ordinal >= hookset->OrdinalBase)
              {
                // rebase into OrdinalNames index
                DWORD nameIndex = ordinal - hookset->OrdinalBase;

                // it's perfectly valid to have more functions than names, we only
                // list those with names - so ignore any others
                if(nameIndex < hookset->OrdinalNames.size())
                {
                  const char *importName = (const char *)hookset->OrdinalNames[nameIndex].c_str();

#if ENABLED(VERBOSE_DEBUG_HOOK)
                  RDCDEBUG("Located ordinal %u as %s", (uint32_t)ordinal, importName);
#endif

                  auto found =
                      std::lower_bound(hookset->FunctionHooks.begin(), hookset->FunctionHooks.end(),
                                       importName, hook_find());

                  if(found != hookset->FunctionHooks.end() &&
                     !strcmp(found->function.c_str(), importName) && ownmodule != module)
                  {
                    bool already = false;
                    bool applied;
                    {
                      SCOPED_LOCK(lock);
                      applied = ApplyHook(*found, IATentry, already);
                    }

                    // if we failed, or if it's already set and we're not doing a missedOrdinals
                    // second pass, then just bail out immediately as we've already hooked this
                    // module and there's no point wasting time re-hooking nothing
                    if(!applied || (already && !missedOrdinals))
                    {
#if ENABLED(VERBOSE_DEBUG_HOOK)
                      RDCDEBUG("Stopping hooking module, %d %d %d", (int)applied, (int)already,
                               (int)missedOrdinals);
#endif
                      FreeLibrary(refcountModHandle);
                      return;
                    }
                  }
                }
              }
              else
              {
                RDCERR("Import ordinal is below ordinal base in %s importing module %s", modName,
                       dllName);
              }
            }
            else
            {
#if ENABLED(VERBOSE_DEBUG_HOOK)
              RDCDEBUG("missed ordinals, will try again");
#endif
              // the very first time we try to apply hooks, we might apply them to a module
              // before we've looked up the ordinal names for the one it's linking against.
              // Subsequent times we're only loading one new module - and since it can't
              // link to itself we will have all ordinal names loaded.
              //
              // Setting this flag causes us to do a second pass right at the start
              missedOrdinals = true;
            }

            // continue
            origFirst++;
            first++;
            continue;
          }

          IMAGE_IMPORT_BY_NAME *import =
              (IMAGE_IMPORT_BY_NAME *)(baseAddress + origFirst->u1.AddressOfData);

          const char *importName = (const char *)import->Name;

#if ENABLED(VERBOSE_DEBUG_HOOK)
          RDCDEBUG("Found normal import %s", importName);
#endif

          auto found = std::lower_bound(hookset->FunctionHooks.begin(),
                                        hookset->FunctionHooks.end(), importName, hook_find());

          if(found != hookset->FunctionHooks.end() &&
             !strcmp(found->function.c_str(), importName) && ownmodule != module)
          {
            bool already = false;
            bool applied;
            {
              SCOPED_LOCK(lock);
              applied = ApplyHook(*found, IATentry, already);
            }

            // if we failed, or if it's already set and we're not doing a missedOrdinals
            // second pass, then just bail out immediately as we've already hooked this
            // module and there's no point wasting time re-hooking nothing
            if(!applied || (already && !missedOrdinals))
            {
#if ENABLED(VERBOSE_DEBUG_HOOK)
              RDCDEBUG("Stopping hooking module, %d %d %d", (int)applied, (int)already,
                       (int)missedOrdinals);
#endif
              FreeLibrary(refcountModHandle);
              return;
            }
          }

          origFirst++;
          first++;
        }
      }
      else
      {
        if(hookset)
        {
#if ENABLED(VERBOSE_DEBUG_HOOK)
          RDCDEBUG("!! Invalid IAT found for %s! %u %u", dllName, importDesc->OriginalFirstThunk,
                   importDesc->FirstThunk);
#endif
        }
      }

      importDesc++;
    }

    FreeLibrary(refcountModHandle);
  }
};

static CachedHookData *s_HookData = NULL;

#ifdef UNICODE
#undef MODULEENTRY32
#undef Module32First
#undef Module32Next
#endif

static void ForAllModules(std::function<void(const MODULEENTRY32 &me32)> callback)
{
  HANDLE hModuleSnap = INVALID_HANDLE_VALUE;

  // up to 10 retries
  for(int i = 0; i < 10; i++)
  {
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

    if(hModuleSnap == INVALID_HANDLE_VALUE)
    {
      DWORD err = GetLastError();

      RDCWARN("CreateToolhelp32Snapshot() -> 0x%08x", err);

      // retry if error is ERROR_BAD_LENGTH
      if(err == ERROR_BAD_LENGTH)
        continue;
    }

    // didn't retry, or succeeded
    break;
  }

  if(hModuleSnap == INVALID_HANDLE_VALUE)
  {
    RDCERR("Couldn't create toolhelp dump of modules in process");
    return;
  }

  MODULEENTRY32 me32;
  RDCEraseEl(me32);
  me32.dwSize = sizeof(MODULEENTRY32);

  BOOL success = Module32First(hModuleSnap, &me32);

  if(success == FALSE)
  {
    DWORD err = GetLastError();

    RDCERR("Couldn't get first module in process: 0x%08x", err);
    CloseHandle(hModuleSnap);
    return;
  }

  do
  {
    callback(me32);
  } while(Module32Next(hModuleSnap, &me32));

  CloseHandle(hModuleSnap);
}

// A target that is packed and resolves its own imports can create graphics objects without ever
// calling a function we intercept, but it cannot avoid *loading* the runtime DLLs it needs. The
// process's module list is therefore ground truth for questions our hooks can't answer - most
// importantly "did the target really create a device": the vendor's user-mode D3D driver (e.g.
// nvwgf2umx.dll) and the Agility SDK's D3D12Core.dll only appear when a device was created.
//
// This polls independently of every hook and logs each module once, with its base and size.
static DWORD WINAPI ModuleTraceThread(LPVOID)
{
  std::set<HMODULE> seen;

  // ~3.5 minutes at 500ms. Longer than any target session we care about, and the thread exits on
  // its own if the process outlives it.
  for(int tick = 0; tick < 420; tick++)
  {
    ForAllModules([&seen](const MODULEENTRY32 &me32) {
      if(seen.find(me32.hModule) != seen.end())
        return;

      seen.insert(me32.hModule);

      // base and size are logged so that a later hook can tell whether a trampoline stub has to be
      // allocated close to this module (an export address table entry is only a 32-bit RVA).
      RDCLOG("MODTRACE %s base %p size %u", me32.szModule, me32.modBaseAddr,
             (uint32_t)me32.modBaseSize);
    });

    Sleep(500);
  }

  RDCLOG("MODTRACE finished, %u modules seen", (uint32_t)seen.size());

  return 0;
}

static void StartModuleTrace()
{
  HANDLE thread = CreateThread(NULL, 0, &ModuleTraceThread, NULL, 0, NULL);

  if(thread)
    CloseHandle(thread);
  else
    RDCLOG("MODTRACE couldn't start thread");
}

// ------------------------------------------------------------------------------------------------
// Export address table rewriting
//
// Patching the import tables of all loaded modules only works if the caller resolves its imports
// through the import table we patched. A packed target doesn't: it builds its own import table at
// runtime, so it never calls the LoadLibrary/GetProcAddress we intercept either. What it *cannot*
// avoid is taking the address of an entry point out of the target library's own export address
// table, however it looks it up. So we edit that instead - every export we hook is redirected to a
// stub that jumps to our hook, and it doesn't matter whether the address was obtained by
// GetProcAddress, by hand-walking the export table, or by anything else.
//
// That patch has to land before the caller resolves anything, and the only place to do it is
// inside the loader: on module load, with the loader lock held, before LoadLibrary returns.

struct ExportStubPage
{
  byte *page = NULL;
  size_t used = 0;
};

// Only ever held by the functions below. Nothing else takes this lock, and nothing takes it while
// waiting on the loader lock, so acquiring it from the loader notification can't deadlock.
static Threading::CriticalSection s_StubLock;
static std::map<HMODULE, ExportStubPage> s_StubPages;

static bool ExportTableHooksEnabled()
{
  // cached after the first call, so a target can't flip it mid-run
  static int cached = -1;

  if(cached < 0)
  {
    // only the first byte is needed, "0" disables
    char value[2] = {};
    DWORD len = GetEnvironmentVariableA("RT_EAT_HOOKS", value, ARRAY_COUNT(value));

    cached = (len == 1 && value[0] == '0') ? 0 : 1;
  }

  return cached == 1;
}

static void GetModuleHeaders(HMODULE module, byte *&base, PIMAGE_OPTIONAL_HEADER &optHeader)
{
  base = (byte *)module;
  optHeader = NULL;

  PIMAGE_DOS_HEADER dosheader = (PIMAGE_DOS_HEADER)base;

  if(dosheader->e_magic != 0x5a4d)
    return;

  char *PE00 = (char *)(base + dosheader->e_lfanew);
  PIMAGE_FILE_HEADER fileHeader = (PIMAGE_FILE_HEADER)(PE00 + 4);
  optHeader = (PIMAGE_OPTIONAL_HEADER)((BYTE *)fileHeader + sizeof(IMAGE_FILE_HEADER));
}

// EAT entries are 32-bit RVAs, so the stub has to sit above the module base within 4GB of it.
// VirtualAlloc with an explicit address fails instead of relocating, so we walk upwards from just
// past the image until we find a free page. In practice the first few probes land.
static byte *AllocStubPage(HMODULE module)
{
  byte *base = NULL;
  PIMAGE_OPTIONAL_HEADER optHeader = NULL;
  GetModuleHeaders(module, base, optHeader);

  if(optHeader == NULL)
    return NULL;

  const uint64_t allocGranularity = 0x10000;
  const uint64_t addressSpace = 0x100000000ull;

  uint64_t hint = (uint64_t)base + ((optHeader->SizeOfImage + allocGranularity - 1) &
                                    ~(allocGranularity - 1));

  for(int i = 0; i < 32768; i++)
  {
    void *page = VirtualAlloc((void *)hint, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if(page)
    {
      if((uint64_t)page > (uint64_t)base && ((uint64_t)page - (uint64_t)base) < addressSpace)
        return (byte *)page;

      VirtualFree(page, 0, MEM_RELEASE);
      RDCERR("Stub page at %p can't be reached from module %p by a 32-bit RVA", page, base);
      return NULL;
    }

    hint += allocGranularity;

    // once past 4GB an RVA can't address it any more
    if(hint - (uint64_t)base >= addressSpace)
      break;
  }

  RDCERR("Couldn't allocate a stub page within 4GB of module %p", base);

  return NULL;
}

// Is this address one of the stubs we've already installed for this module? HookAllModules runs
// again on every subsequent load, so the export pass has to recognise its own work instead of
// handing out a fresh stub each time.
static bool IsJumpStub(HMODULE module, void *address)
{
  SCOPED_LOCK(s_StubLock);

  auto sp = s_StubPages.find(module);

  if(sp == s_StubPages.end() || sp->second.page == NULL)
    return false;

  uintptr_t addr = (uintptr_t)address;
  uintptr_t first = (uintptr_t)sp->second.page;

  return addr >= first && addr < first + sp->second.used;
}

// 12 bytes: mov rax, <destination> ; jmp rax
static void *GetJumpStub(HMODULE module, void *destination)
{
  const size_t stubSize = 12;

  SCOPED_LOCK(s_StubLock);

  ExportStubPage &stubPage = s_StubPages[module];

  if(stubPage.page == NULL)
  {
    stubPage.page = AllocStubPage(module);

    if(stubPage.page == NULL)
      return NULL;
  }

  if(stubPage.used + stubSize > 4096)
  {
    RDCERR("Out of space for jump stubs for module %p", module);
    return NULL;
  }

  byte *stub = stubPage.page + stubPage.used;
  stubPage.used += stubSize;

  stub[0] = 0x48;
  stub[1] = 0xb8;
  memcpy(stub + 2, &destination, sizeof(destination));
  stub[10] = 0xff;
  stub[11] = 0xe0;

  FlushInstructionCache(GetCurrentProcess(), stub, stubSize);

  return stub;
}

static void PatchExportTable(const rdcstr &modName, HMODULE module)
{
  if(module == NULL || !s_HookData || !s_HookData->hookAll || !ExportTableHooksEnabled())
    return;

  auto hookset = s_HookData->DllHooks.find(modName);

  if(hookset == s_HookData->DllHooks.end() || hookset->second.FunctionHooks.empty())
    return;

  byte *base = NULL;
  PIMAGE_OPTIONAL_HEADER optHeader = NULL;
  GetModuleHeaders(module, base, optHeader);

  if(optHeader == NULL)
    return;

  DWORD dirRVA = optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

  if(dirRVA == 0)
    return;

  IMAGE_EXPORT_DIRECTORY *exportDesc = (IMAGE_EXPORT_DIRECTORY *)(base + dirRVA);
  DWORD *funcs = (DWORD *)(base + exportDesc->AddressOfFunctions);
  DWORD *names = (DWORD *)(base + exportDesc->AddressOfNames);
  WORD *ordinals = (WORD *)(base + exportDesc->AddressOfNameOrdinals);

  // an export whose RVA falls inside the export directory is a forwarder - the "RVA" is really a
  // string naming another module and its export. That can't be redirected with a jump stub, and
  // nothing we hook is forwarded, so leave those alone.
  DWORD dirEnd = dirRVA + optHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

  for(DWORD i = 0; i < exportDesc->NumberOfNames; i++)
  {
    const char *name = (const char *)(base + names[i]);

    FunctionHook search(name, NULL, NULL);
    auto found = std::lower_bound(hookset->second.FunctionHooks.begin(),
                                  hookset->second.FunctionHooks.end(), search);

    if(found == hookset->second.FunctionHooks.end() ||
       strcmp(found->function.c_str(), name) != 0)
      continue;

    WORD ordinal = ordinals[i];

    if(ordinal >= exportDesc->NumberOfFunctions)
      continue;

    DWORD &slot = funcs[ordinal];

    if(slot >= dirRVA && slot < dirEnd)
    {
      RDCLOG("EAT %s!%s is a forwarder, not patching", modName.c_str(), name);
      continue;
    }

    void *orig = base + slot;

    // already redirected by an earlier pass
    if(IsJumpStub(module, orig))
      continue;

    void *stub = GetJumpStub(module, found->hook);

    if(stub == NULL)
    {
      RDCERR("Couldn't get a jump stub for %s!%s", modName.c_str(), name);
      continue;
    }

    DWORD stubRVA = (DWORD)((uint64_t)stub - (uint64_t)base);

    // The original has to be recorded before the entry is overwritten - from here on this name
    // resolves to our stub for everyone, including our own GetProcAddress. Anything that reads
    // hook.orig afterwards has to find the real function already there.
    if(found->orig && *found->orig == NULL)
      *found->orig = orig;

    DWORD oldProtection = PAGE_EXECUTE;

    if(!VirtualProtect(&slot, sizeof(DWORD), PAGE_READWRITE, &oldProtection))
    {
      RDCERR("Failed to make the export entry for %s!%s writeable", modName.c_str(), name);
      continue;
    }

    slot = stubRVA;

    VirtualProtect(&slot, sizeof(DWORD), oldProtection, &oldProtection);

    RDCLOG("EAT patched %s!%s (%p) -> stub %p", modName.c_str(), name, orig, stub);
  }
}

typedef struct
{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} RDC_LDR_UNICODE_STRING;

typedef struct
{
  ULONG Flags;
  const RDC_LDR_UNICODE_STRING *FullDllName;
  const RDC_LDR_UNICODE_STRING *BaseDllName;
  PVOID DllBase;
  ULONG SizeOfImage;
} RDC_LDR_DLL_NOTIFICATION_DATA;

typedef VOID(NTAPI *PFN_LDR_DLL_NOTIFICATION_FUNCTION)(ULONG reason,
                                                       const RDC_LDR_DLL_NOTIFICATION_DATA *data,
                                                       PVOID context);
typedef LONG(NTAPI *PFN_LDR_REGISTER_DLL_NOTIFICATION)(ULONG reason,
                                                       PFN_LDR_DLL_NOTIFICATION_FUNCTION callback,
                                                       PVOID context, PVOID *cookie);

static const ULONG RDC_LDR_DLL_NOTIFICATION_REASON_LOADED = 1;

// Called on the loading thread with the loader lock held, once the image is mapped but before
// LoadLibrary returns to whoever asked for it. That window is the entire point: the caller cannot
// have resolved anything from the export table yet, so patching it here can't be raced - unlike
// everything else we do, which waits for a load we only find out about after the fact.
//
// For the same reason this must not call LoadLibrary or GetProcAddress on another module, and must
// not take a lock that anything else could hold while blocked on the loader lock. It only touches
// the module's export table and the private stub allocator.
static VOID NTAPI DllNotificationCallback(ULONG reason, const RDC_LDR_DLL_NOTIFICATION_DATA *data,
                                          PVOID context)
{
  if(reason != RDC_LDR_DLL_NOTIFICATION_REASON_LOADED || data == NULL || data->DllBase == NULL ||
     data->BaseDllName == NULL)
    return;

  if(!s_HookData || !s_HookData->hookAll || !ExportTableHooksEnabled())
    return;

  size_t len = data->BaseDllName->Length / sizeof(wchar_t);

  if(len == 0)
    return;

  rdcwstr wname(len);
  for(size_t i = 0; i < len; i++)
    wname[i] = data->BaseDllName->Buffer[i];

  rdcstr modName = strlower(StringFormat::Wide2UTF8(wname.c_str()));

  PatchExportTable(modName, (HMODULE)data->DllBase);
}

static void StartExportTableHooks()
{
  if(!ExportTableHooksEnabled())
  {
    RDCLOG("Export table hooks disabled by RT_EAT_HOOKS");
    return;
  }

  HMODULE ntdll = GetModuleHandleA("ntdll.dll");

  if(ntdll == NULL)
  {
    RDCERR("Couldn't find ntdll to register the dll load notification");
    return;
  }

  PFN_LDR_REGISTER_DLL_NOTIFICATION registerNotify =
      (PFN_LDR_REGISTER_DLL_NOTIFICATION)GetProcAddress(ntdll, "LdrRegisterDllNotification");

  if(registerNotify == NULL)
  {
    RDCERR("LdrRegisterDllNotification not present, target exports won't be hooked");
    return;
  }

  PVOID cookie = NULL;
  LONG status = registerNotify(0, &DllNotificationCallback, NULL, &cookie);

  if(status == 0)
    RDCLOG("Registered dll load notification, target export tables will be hooked");
  else
    RDCERR("LdrRegisterDllNotification failed with %ld, target exports won't be hooked", (long)status);
}

static void HookAllModules()
{
  if(!s_HookData->hookAll)
    return;

  ForAllModules([](const MODULEENTRY32 &me32) {
    s_HookData->ApplyHooks(me32.szModule, me32.hModule);

    // The load notification only covers libraries that appear after we registered it, so anything
    // already in the process needs its export table patched here too.
    PatchExportTable(strlower(rdcstr(me32.szModule)), me32.hModule);
  });

  // check if we're already in this section of code, and if so don't go in again.
  int32_t prev = Atomic::CmpExch32(&s_HookData->posthooking, 0, 1);

  if(prev != 0)
    return;

  // for all loaded modules, call callbacks now
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
  {
    if(it->second.module == NULL)
      continue;

    if(!it->second.hooksfetched)
    {
      it->second.hooksfetched = true;

      // fetch all function hooks here, if we didn't above (perhaps because this library was
      // late-loaded)
      for(FunctionHook &hook : it->second.FunctionHooks)
      {
        if(hook.orig && *hook.orig == NULL)
          *hook.orig = GetProcAddress(it->second.module, hook.function.c_str());
      }
    }

    // a non-empty callback list means we haven't been here for this library before, i.e. this is the
    // first time we've seen it loaded into the target. Libraries that only register function hooks
    // have no callback and aren't reported, e.g. the internal loader hooks in api-ms-win-core-*.
    const bool firstload = !it->second.Callbacks.empty();

    rdcarray<FunctionLoadCallback> callbacks;
    // don't call callbacks next time
    callbacks.swap(it->second.Callbacks);

    // if one of the libraries we hook is never reported here, then no entry point in it could ever
    // have been hooked - e.g. a missing d3d12.dll means anything creating a D3D12 device is not in
    // the process we're in.
    if(firstload)
      RDCLOG("Target loaded library '%s' (%p), entry points hooked", it->first.c_str(),
             it->second.module);

    for(FunctionLoadCallback cb : callbacks)
      if(cb)
        cb(it->second.module, it->first.c_str());
  }

  Atomic::CmpExch32(&s_HookData->posthooking, 1, 0);
}

static bool IsAPISet(const wchar_t *filename)
{
  if(wcschr(filename, L'/') != 0 || wcschr(filename, L'\\') != 0)
    return false;

  wchar_t match[] = L"api-ms-win";

  if(wcslen(filename) < ARRAY_COUNT(match) - 1)
    return false;

  for(size_t i = 0; i < ARRAY_COUNT(match) - 1; i++)
    if(towlower(filename[i]) != match[i])
      return false;

  return true;
}

static bool IsAPISet(const char *filename)
{
  size_t len = strlen(filename);
  rdcwstr wfn(len);

  // assume ASCII not UTF, just upcast plainly to wchar_t
  for(size_t i = 0; i < len; i++)
    wfn[i] = wchar_t(filename[i]);

  return IsAPISet(wfn.c_str());
}

HMODULE WINAPI Hooked_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE fileHandle, DWORD flags)
{
  bool dohook = true;

  if(s_HookData->libraryIntercept)
  {
    HMODULE ret = s_HookData->libraryIntercept(lpLibFileName, fileHandle, flags);
    if(ret)
      return ret;
    dohook = false;
  }

  if(flags == 0 && GetModuleHandleA(lpLibFileName))
    dohook = false;

  SetLastError(S_OK);

  // we can use the function naked, as when setting up the hook for LoadLibraryExA, our own module
  // was excluded from IAT patching
  HMODULE mod = LoadLibraryExA(lpLibFileName, fileHandle, flags);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("LoadLibraryA(%s)", lpLibFileName);
#endif

  DWORD err = GetLastError();

  if(dohook && mod && !IsAPISet(lpLibFileName))
    HookAllModules();

  SetLastError(err);

  return mod;
}

HMODULE WINAPI Hooked_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE fileHandle, DWORD flags)
{
  bool dohook = true;

  if(s_HookData->libraryIntercept)
  {
    HMODULE ret =
        s_HookData->libraryIntercept(StringFormat::Wide2UTF8(lpLibFileName), fileHandle, flags);
    if(ret)
      return ret;
    dohook = false;
  }

  DWORD flagsExcludingSearchOrders = flags;

  // if this is a pure "filename.dll" load, don't care about search-order flags since loaded DLLs are
  // always returned first regardless of the search order and so we can detect the DLL is already loaded
  if(wcschr(lpLibFileName, L'\\') == 0 && wcschr(lpLibFileName, L'/') == 0)
  {
    flagsExcludingSearchOrders &= ~(LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32 |
                                    LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_WITH_ALTERED_SEARCH_PATH);

#ifdef LOAD_LIBRARY_SAFE_CURRENT_DIRS
    flagsExcludingSearchOrders &= ~LOAD_LIBRARY_SAFE_CURRENT_DIRS;
#endif
  }

  // if there are no flags (possibly with search path flags excluded) and we already have the
  // library loaded, don't hook anything
  if(flagsExcludingSearchOrders == 0 && GetModuleHandleW(lpLibFileName))
    dohook = false;

  if(flags & (LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE))
    dohook = false;

  SetLastError(S_OK);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("LoadLibraryW(%ls)", lpLibFileName);
#endif

  // we can use the function naked, as when setting up the hook for LoadLibraryExA, our own module
  // was excluded from IAT patching
  HMODULE mod = LoadLibraryExW(lpLibFileName, fileHandle, flags);

  DWORD err = GetLastError();

  if(dohook && mod && !IsAPISet(lpLibFileName))
    HookAllModules();

  SetLastError(err);

  return mod;
}

HMODULE WINAPI Hooked_LoadLibraryA(LPCSTR lpLibFileName)
{
  return Hooked_LoadLibraryExA(lpLibFileName, NULL, 0);
}

HMODULE WINAPI Hooked_LoadLibraryW(LPCWSTR lpLibFileName)
{
  return Hooked_LoadLibraryExW(lpLibFileName, NULL, 0);
}

static bool OrdinalAsString(void *func)
{
  return uint64_t(func) <= 0xffff;
}

FARPROC WINAPI Hooked_GetProcAddress(HMODULE mod, const LPCSTR func)
{
  if(mod == NULL || func == NULL || mod == s_HookData->ownmodule)
    return GetProcAddress(mod, func);

#if ENABLED(VERBOSE_DEBUG_HOOK)
  if(OrdinalAsString((void *)func))
    RDCDEBUG("Hooked_GetProcAddress(%p, %p)", mod, func);
  else
    RDCDEBUG("Hooked_GetProcAddress(%p, %s)", mod, func);
#endif

  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
  {
    if(it->second.module == NULL)
    {
      it->second.module = GetModuleHandleA(it->first.c_str());
      if(it->second.module)
      {
        // fetch all function hooks here, since we want to fill out the original function pointer
        // even in case nothing imports from that function (which means it would not get filled
        // out through FunctionHook::ApplyHook)
        for(FunctionHook &hook : it->second.FunctionHooks)
        {
          if(hook.orig && *hook.orig == NULL)
            *hook.orig = GetProcAddress(it->second.module, hook.function.c_str());
        }

        it->second.FetchOrdinalNames();
      }
    }

    bool match = (mod == it->second.module);

    if(!match && !it->second.altmodules.empty())
    {
      for(size_t i = 0; !match && i < it->second.altmodules.size(); i++)
        match = (mod == it->second.altmodules[i]);
    }

    if(match)
    {
#if ENABLED(VERBOSE_DEBUG_HOOK)
      RDCDEBUG("Located module %s", it->first.c_str());
#endif

      LPCSTR searchFunc = func;

      if(OrdinalAsString((void *)func))
      {
#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Ordinal hook");
#endif

        uint32_t ordinal = (uint16_t)(uintptr_t(func) & 0xffff);

        if(ordinal < it->second.OrdinalBase)
        {
          RDCERR("Unexpected ordinal - lower than ordinalbase %u for %s",
                 (uint32_t)it->second.OrdinalBase, it->first.c_str());

          SetLastError(S_OK);
          return GetProcAddress(mod, func);
        }

        ordinal -= it->second.OrdinalBase;

        if(ordinal >= it->second.OrdinalNames.size())
        {
          RDCERR("Unexpected ordinal - higher than fetched ordinal names (%u) for %s",
                 (uint32_t)it->second.OrdinalNames.size(), it->first.c_str());

          SetLastError(S_OK);
          return GetProcAddress(mod, func);
        }

        searchFunc = it->second.OrdinalNames[ordinal].c_str();

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("found ordinal %s", searchFunc);
#endif
      }

      FunctionHook search(searchFunc, NULL, NULL);

      auto found =
          std::lower_bound(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end(), search);
      if(found != it->second.FunctionHooks.end() && !(search < *found))
      {
        FARPROC realfunc = GetProcAddress(mod, func);

        RDCLOG("GetProcAddress('%s') matched our hook for '%s', returning our entry point", searchFunc,
               it->first.c_str());

#if ENABLED(VERBOSE_DEBUG_HOOK)
        RDCDEBUG("Found hooked function, returning hook pointer %p", found->hook);
#endif

        SetLastError(S_OK);

        if(realfunc == NULL)
          return NULL;

        return (FARPROC)found->hook;
      }
    }
  }

  // the application asked for a function that we hook, but from a module we don't recognise as the
  // library that exports it - so it gets the real pointer and any call bypasses us entirely. Report
  // it, since this is otherwise invisible: e.g. D3D12CreateDevice resolved out of D3D12Core.dll.
  if(!OrdinalAsString((void *)func))
  {
    for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    {
      FunctionHook search(func, NULL, NULL);

      auto found =
          std::lower_bound(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end(), search);

      if(found != it->second.FunctionHooks.end() && !(search < *found))
      {
        char modname[MAX_PATH] = {};
        GetModuleFileNameA(mod, modname, MAX_PATH);

        RDCLOG("GetProcAddress('%s') requested from '%s' (%p) - we hook that function in '%s' (%p), "
               "so this call bypasses our hook",
               func, modname, mod, it->first.c_str(), it->second.module);
        break;
      }
    }
  }

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("No matching hook found, returning original");
#endif

  SetLastError(S_OK);

  return GetProcAddress(mod, func);
}
static void InitHookData()
{
  if(!s_HookData)
  {
    s_HookData = new CachedHookData;

    RDCASSERT(s_HookData->DllHooks.empty());
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryA", NULL, &Hooked_LoadLibraryA));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryW", NULL, &Hooked_LoadLibraryW));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryExA", NULL, &Hooked_LoadLibraryExA));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("LoadLibraryExW", NULL, &Hooked_LoadLibraryExW));
    s_HookData->DllHooks["kernel32.dll"].FunctionHooks.push_back(
        FunctionHook("GetProcAddress", NULL, &Hooked_GetProcAddress));

    for(const char *apiset :
        {"api-ms-win-core-libraryloader-l1-1-0.dll", "api-ms-win-core-libraryloader-l1-1-1.dll",
         "api-ms-win-core-libraryloader-l1-1-2.dll", "api-ms-win-core-libraryloader-l1-2-0.dll",
         "api-ms-win-core-libraryloader-l1-2-1.dll"})
    {
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryA", NULL, &Hooked_LoadLibraryA));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryW", NULL, &Hooked_LoadLibraryW));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryExA", NULL, &Hooked_LoadLibraryExA));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("LoadLibraryExW", NULL, &Hooked_LoadLibraryExW));
      s_HookData->DllHooks[apiset].FunctionHooks.push_back(
          FunctionHook("GetProcAddress", NULL, &Hooked_GetProcAddress));
    }

    GetModuleHandleEx(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCTSTR)&s_HookData, &s_HookData->ownmodule);
  }
}

void LibraryHooks::RegisterFunctionHook(const char *libraryName, const FunctionHook &hook)
{
  if(!_stricmp(libraryName, "kernel32.dll"))
  {
    if(hook.function == "LoadLibraryA" || hook.function == "LoadLibraryW" ||
       hook.function == "LoadLibraryExA" || hook.function == "LoadLibraryExW" ||
       hook.function == "GetProcAddress")
    {
      RDCERR("Cannot hook LoadLibrary* or GetProcAddress, as these are hooked internally");
      return;
    }
  }
  s_HookData->DllHooks[strlower(rdcstr(libraryName))].FunctionHooks.push_back(hook);
}

void LibraryHooks::RegisterLibraryHook(const char *libraryName, FunctionLoadCallback loadedCallback)
{
  s_HookData->DllHooks[strlower(rdcstr(libraryName))].Callbacks.push_back(loadedCallback);
}

void LibraryHooks::IgnoreLibrary(const char *libraryName)
{
  rdcstr lowername = libraryName;

  for(size_t i = 0; i < lowername.size(); i++)
    lowername[i] = (char)tolower(lowername[i]);

  s_HookData->ignores.insert(lowername);
}

void LibraryHooks::BeginHookRegistration()
{
  InitHookData();
}

// hook all functions for currently loaded modules.
// some of these hooks (as above) will hook LoadLibrary/GetProcAddress, to protect
void LibraryHooks::EndHookRegistration()
{
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

#if ENABLED(VERBOSE_DEBUG_HOOK)
  RDCDEBUG("Applying hooks");
#endif

  HookAllModules();

  if(s_HookData->missedOrdinals)
  {
#if ENABLED(VERBOSE_DEBUG_HOOK)
    RDCDEBUG("Missed ordinals - applying hooks again");
#endif

    // we need to do a second pass now that we know ordinal names to finally hook
    // some imports by ordinal only.
    HookAllModules();

    s_HookData->missedOrdinals = false;
  }

  // only trace when we're actually hooking the target, not for the manual-hooking (replay) path.
  // the trace is diagnostic only, it patches nothing.
  if(s_HookData->hookAll)
  {
    StartExportTableHooks();
    StartModuleTrace();
  }
}

void LibraryHooks::Refresh()
{
  // don't need to refresh on windows
}

void LibraryHooks::ReplayInitialise()
{
}

void LibraryHooks::RemoveHooks()
{
  LibraryHooks::RemoveHookCallbacks();

  for(auto it = s_InstalledHooks.begin(); it != s_InstalledHooks.end(); ++it)
  {
    DWORD oldProtection = PAGE_EXECUTE;

    void **IATentry = it->first;

    BOOL success = VirtualProtect(IATentry, sizeof(void *), PAGE_READWRITE, &oldProtection);
    if(!success)
    {
      RDCERR("Failed to make IAT entry writeable 0x%p", IATentry);
      continue;
    }

    *IATentry = it->second;

    success = VirtualProtect(IATentry, sizeof(void *), oldProtection, &oldProtection);
    if(!success)
    {
      RDCERR("Failed to restore IAT entry protection 0x%p", IATentry);
      continue;
    }
  }
}

bool LibraryHooks::Detect(const char *identifier)
{
  bool ret = false;
  ForAllModules([&ret, identifier](const MODULEENTRY32 &me32) {
    if(GetProcAddress(me32.hModule, identifier) != NULL)
      ret = true;
  });
  return ret;
}

void *LibraryHooks::GetOriginalFunction(HMODULE mod, const char *name)
{
  if(mod == NULL || name == NULL)
    return NULL;

  if(s_HookData)
  {
    char filename[MAX_PATH] = {};
    GetModuleFileNameA(mod, filename, MAX_PATH - 1);
    const char *slash = strrchr(filename, '\\');

    rdcstr basename = strlower(rdcstr(slash ? slash + 1 : filename));

    auto hookset = s_HookData->DllHooks.find(basename);

    if(hookset != s_HookData->DllHooks.end())
    {
      FunctionHook search(name, NULL, NULL);
      auto found = std::lower_bound(hookset->second.FunctionHooks.begin(),
                                    hookset->second.FunctionHooks.end(), search);

      if(found != hookset->second.FunctionHooks.end() &&
         strcmp(found->function.c_str(), name) == 0 && found->orig && *found->orig)
        return *found->orig;
    }
  }

  // either we don't hook this export (so the export table is untouched) or we haven't seen the
  // module yet - the real GetProcAddress is correct either way
  return (void *)GetProcAddress(mod, name);
}

void Win32_RegisterManualModuleHooking()
{
  InitHookData();

  s_HookData->hookAll = false;
}

void Win32_InterceptLibraryLoads(std::function<HMODULE(const rdcstr &, HANDLE, DWORD)> callback)
{
  s_HookData->libraryIntercept = callback;
}

void Win32_ManualHookModule(rdcstr modName, HMODULE module)
{
  for(auto it = s_HookData->DllHooks.begin(); it != s_HookData->DllHooks.end(); ++it)
    std::sort(it->second.FunctionHooks.begin(), it->second.FunctionHooks.end());

  modName = strlower(modName);

  s_HookData->DllHooks[modName].module = module;

  for(FunctionHook &hook : s_HookData->DllHooks[modName].FunctionHooks)
  {
    if(hook.orig)
      *hook.orig = GetProcAddress(module, hook.function.c_str());
  }

  s_HookData->ApplyHooks(modName.c_str(), module);
}

// android only hooking functions, not used on win32
ScopedSuppressHooking::ScopedSuppressHooking()
{
}

ScopedSuppressHooking::~ScopedSuppressHooking()
{
}
