// machine_id.cpp
#include "machine_id.h"
#include <string>
#include <vector>
#include <set>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <random>
#include <chrono>
#include <mutex>
#include <atomic>

// GmSSL 头文件
#include "gmssl/sha2.h"

// ============================================================================
// 平台特定头文件
// ============================================================================

#if defined(_WIN32) || defined(_WIN64)
#define PLATFORM_WINDOWS
#define _WIN32_DCOM
#include <windows.h>
#include <wbemidl.h>
#include <sddl.h>
#include <iphlpapi.h>
#include <winreg.h>
#include <comdef.h>

#ifndef __MINGW32__
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#endif
#elif defined(__linux__)
#define PLATFORM_LINUX
#include <unistd.h>
#include <fstream>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <cstring>
#include <netpacket/packet.h>
#elif defined(__APPLE__) && defined(__MACH__)
#define PLATFORM_MACOS
#include <unistd.h>
#include <fstream>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/storage/IOStorageProtocolCharacteristics.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if_dl.h>
#else
#error "Unsupported platform"
#endif

namespace MachineId {
namespace internal {

// ============================================================================
// 全局配置
// ============================================================================

static std::string g_persistentStoragePath;
static std::mutex g_mutex;

// ============================================================================
// 辅助函数
// ============================================================================

std::string Trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\n\r\f\v");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\n\rf\v");
    return str.substr(first, last - first + 1);
}

std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

// 真正的 SHA-256 使用 GmSSL
std::string SHA256(const std::string& input) {
    SHA256_CTX ctx;
    uint8_t digest[SHA256_DIGEST_SIZE];

    sha256_init(&ctx);
    sha256_update(&ctx, reinterpret_cast<const uint8_t*>(input.data()), input.size());
    sha256_finish(&ctx, digest);

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < SHA256_DIGEST_SIZE; ++i) {
        ss << std::setw(2) << static_cast<int>(digest[i]);
    }
    return ss.str();
}

std::string GenerateUUID() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 15);
    std::uniform_int_distribution<> dis2(8, 11);

    const char* hex = "0123456789abcdef";
    std::string uuid = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";

    for (size_t i = 0; i < uuid.length(); ++i) {
        if (uuid[i] == 'x') {
            uuid[i] = hex[dis(gen)];
        } else if (uuid[i] == 'y') {
            uuid[i] = hex[dis2(gen)];
        }
    }
    return uuid;
}

// 持久化存储 fallback ID - 修复变量重复声明问题
std::string GetPersistentFallbackId() {
    std::lock_guard<std::mutex> lock(g_mutex);

    std::string saved_id;

#if defined(PLATFORM_WINDOWS)
    // Windows 使用注册表
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\MachineId", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t buffer[256] = {0};
        DWORD bufferSize = sizeof(buffer);
        DWORD type = 0;
        if (RegQueryValueExW(hKey, L"HardwareId", nullptr, &type,
                             reinterpret_cast<LPBYTE>(buffer), &bufferSize) == ERROR_SUCCESS &&
            type == REG_SZ) {
            int len = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, nullptr, 0, nullptr, nullptr);
            if (len > 0) {
                saved_id.resize(len - 1);
                WideCharToMultiByte(CP_UTF8, 0, buffer, -1, &saved_id[0], len, nullptr, nullptr);
            }
        }
        RegCloseKey(hKey);
    }
#elif defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)
    // Unix 使用文件 - 读取
    std::string readPath = g_persistentStoragePath.empty() ?
                               "/var/lib/machine_id" : g_persistentStoragePath;
    std::ifstream readFile(readPath);
    if (readFile.is_open()) {
        std::getline(readFile, saved_id);
        saved_id = Trim(saved_id);
        readFile.close();
    }
#endif

    if (!saved_id.empty()) {
        return saved_id;
    }

    // 生成新 ID
    std::string new_id = "fallback-" + GenerateUUID();

    // 保存
#if defined(PLATFORM_WINDOWS)
    HKEY hKeyNew = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\MachineId", 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKeyNew, nullptr) == ERROR_SUCCESS) {
        int len = MultiByteToWideChar(CP_UTF8, 0, new_id.c_str(), -1, nullptr, 0);
        if (len > 0) {
            std::vector<wchar_t> wstr(len);
            MultiByteToWideChar(CP_UTF8, 0, new_id.c_str(), -1, wstr.data(), len);
            RegSetValueExW(hKeyNew, L"HardwareId", 0, REG_SZ,
                           reinterpret_cast<const BYTE*>(wstr.data()),
                           len * sizeof(wchar_t));
        }
        RegCloseKey(hKeyNew);
    }
#elif defined(PLATFORM_LINUX) || defined(PLATFORM_MACOS)
    // Unix 使用文件 - 写入（使用不同的变量名）
    std::string writePath = g_persistentStoragePath.empty() ?
                                "/var/lib/machine_id" : g_persistentStoragePath;
    std::ofstream writeFile(writePath);
    if (writeFile.is_open()) {
        writeFile << new_id;
        writeFile.close();
    }
#endif

    return new_id;
}

// 检查字符串是否看起来像有效的硬件ID
bool IsValidHardwareId(const std::string& str) {
    if (str.empty()) return false;
    if (str.length() < 4) return false;

    // 过滤常见的占位符
    std::string lower = ToLower(str);
    if (lower.find("to be filled") != std::string::npos) return false;
    if (lower.find("o.e.m") != std::string::npos) return false;
    if (lower.find("default") != std::string::npos) return false;
    if (lower.find("none") != std::string::npos) return false;
    if (lower.find("unknown") != std::string::npos) return false;
    if (lower.find("not available") != std::string::npos) return false;

    // 检查是否全是0
    if (str.find_first_not_of("0") == std::string::npos) return false;
    if (str.find_first_not_of("0:") == std::string::npos) return false;
    if (str.find_first_not_of("0-") == std::string::npos) return false;

    return true;
}

// ============================================================================
// Windows 实现
// ============================================================================

#if defined(PLATFORM_WINDOWS)

// RAII COM 初始化器
class COMInitializer {
public:
    COMInitializer() : initialized_(false) {
        HRESULT hres = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(hres)) {
            initialized_ = true;
            static std::atomic<bool> security_initialized{false};
            if (!security_initialized.exchange(true)) {
                CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                                     RPC_C_AUTHN_LEVEL_DEFAULT,
                                     RPC_C_IMP_LEVEL_IMPERSONATE,
                                     nullptr, EOAC_NONE, nullptr);
            }
        }
    }

    ~COMInitializer() {
        if (initialized_) {
            CoUninitialize();
        }
    }

    bool IsInitialized() const { return initialized_; }

private:
    bool initialized_;
};

std::string ReadRegistryString(HKEY root, const std::wstring& keyPath,
                               const std::wstring& valueName) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, keyPath.c_str(), 0, KEY_QUERY_VALUE, &hKey) != ERROR_SUCCESS) {
        return "";
    }

    wchar_t buffer[1024] = {0};
    DWORD bufferSize = sizeof(buffer);
    DWORD type = 0;

    LONG result = RegQueryValueExW(hKey, valueName.c_str(), nullptr, &type,
                                   reinterpret_cast<LPBYTE>(buffer), &bufferSize);
    RegCloseKey(hKey);

    if (result != ERROR_SUCCESS || type != REG_SZ) {
        return "";
    }

    int len = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";
    std::string result_str(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, buffer, -1, &result_str[0], len, nullptr, nullptr);
    return result_str;
}

std::string QueryWMI(const std::wstring& wmiClass, const std::wstring& property) {
    COMInitializer comInit;
    if (!comInit.IsInitialized()) return "";

    IWbemLocator* pLoc = nullptr;
    HRESULT hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                                    IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) return "";

    IWbemServices* pSvc = nullptr;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0,
                               0, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        return "";
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                             nullptr, RPC_C_AUTHN_LEVEL_CALL,
                             RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    IEnumWbemClassObject* pEnumerator = nullptr;
    std::wstring query = L"SELECT * FROM " + wmiClass;
    hres = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                           WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                           nullptr, &pEnumerator);

    std::string result;
    if (SUCCEEDED(hres) && pEnumerator) {
        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;
        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (uReturn == 0) break;

            VARIANT vtProp;
            hr = pclsObj->Get(property.c_str(), 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal) {
                int len = WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1,
                                              nullptr, 0, nullptr, nullptr);
                if (len > 0) {
                    result.resize(len - 1);
                    WideCharToMultiByte(CP_UTF8, 0, vtProp.bstrVal, -1,
                                        &result[0], len, nullptr, nullptr);
                }
                VariantClear(&vtProp);
                pclsObj->Release();
                break;
            }
            VariantClear(&vtProp);
            pclsObj->Release();
        }
        pEnumerator->Release();
    }

    pSvc->Release();
    pLoc->Release();

    return Trim(result);
}

std::string GetMacAddress() {
    std::string result;
    ULONG ulOutBufLen = 0;

    if (GetAdaptersInfo(nullptr, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        std::vector<IP_ADAPTER_INFO> buffer(ulOutBufLen / sizeof(IP_ADAPTER_INFO) + 1);
        PIP_ADAPTER_INFO pAdapterInfo = buffer.data();

        if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
            PIP_ADAPTER_INFO pAdapter = pAdapterInfo;

            std::vector<std::string> blacklist = {
                "Virtual", "VMware", "Hyper-V", "VirtualBox",
                "Bluetooth", "PPP", "VPN", "TAP", "Tunnel",
                "Loopback", "vEthernet", "Docker"
            };

            while (pAdapter) {
                std::string desc = pAdapter->Description;
                std::string lowerDesc = ToLower(desc);

                bool is_virtual = false;
                for (const auto& keyword : blacklist) {
                    if (lowerDesc.find(ToLower(keyword)) != std::string::npos) {
                        is_virtual = true;
                        break;
                    }
                }

                if (desc.find("虚拟") != std::string::npos ||
                    desc.find("蓝牙") != std::string::npos) {
                    is_virtual = true;
                }

                if (!is_virtual && pAdapter->AddressLength == 6) {
                    bool all_zero = true;
                    for (UINT i = 0; i < pAdapter->AddressLength; ++i) {
                        if (pAdapter->Address[i] != 0) {
                            all_zero = false;
                            break;
                        }
                    }

                    if (!all_zero) {
                        char mac[18];
                        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                                 pAdapter->Address[0], pAdapter->Address[1],
                                 pAdapter->Address[2], pAdapter->Address[3],
                                 pAdapter->Address[4], pAdapter->Address[5]);
                        result = mac;
                        break;
                    }
                }
                pAdapter = pAdapter->Next;
            }
        }
    }

    return result;
}

#endif // PLATFORM_WINDOWS

// ============================================================================
// Linux 实现
// ============================================================================

#if defined(PLATFORM_LINUX)

std::string ReadFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return "";
    std::string content;
    std::getline(file, content);
    return Trim(content);
}

std::string GetMacAddress() {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return "";

    std::string result;
    std::vector<std::string> blacklist = {
        "lo", "docker", "veth", "br-", "virbr",
        "lxc", "nflog", "nfqueue", "tun", "tap"
    };

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_PACKET) continue;

        std::string name = ifa->ifa_name;
        bool is_virtual = false;
        for (const auto& keyword : blacklist) {
            if (name.find(keyword) != std::string::npos) {
                is_virtual = true;
                break;
            }
        }
        if (is_virtual) continue;

        struct sockaddr_ll* sll = (struct sockaddr_ll*)ifa->ifa_addr;
        if (sll->sll_halen == 6) {
            bool all_zero = true;
            for (int i = 0; i < 6; ++i) {
                if (sll->sll_addr[i] != 0) {
                    all_zero = false;
                    break;
                }
            }

            if (!all_zero) {
                char mac[18];
                snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                         sll->sll_addr[0], sll->sll_addr[1],
                         sll->sll_addr[2], sll->sll_addr[3],
                         sll->sll_addr[4], sll->sll_addr[5]);
                result = mac;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return result;
}

std::string GetCPUInfo() {
    std::ifstream file("/proc/cpuinfo");
    if (!file.is_open()) return "";

    std::string line;
    while (std::getline(file, line)) {
        if (line.find("Serial") != std::string::npos) {
            size_t pos = line.find(':');
            if (pos != std::string::npos) {
                return Trim(line.substr(pos + 1));
            }
        }
    }
    return "";
}

bool IsInContainer() {
    std::ifstream dockerEnv("/.dockerenv");
    if (dockerEnv.good()) return true;

    std::ifstream podmanEnv("/run/.containerenv");
    if (podmanEnv.good()) return true;

    std::ifstream cgroup("/proc/1/cgroup");
    std::string line;
    while (std::getline(cgroup, line)) {
        if (line.find("docker") != std::string::npos ||
            line.find("kubepods") != std::string::npos ||
            line.find("kubelet") != std::string::npos) {
            return true;
        }
    }
    return false;
}

#endif // PLATFORM_LINUX

// ============================================================================
// macOS 实现
// ============================================================================

#if defined(PLATFORM_MACOS)

std::string GetIOKitProperty(const char* serviceName, CFStringRef propertyKey) {
    io_service_t service = IOServiceGetMatchingService(
        kIOMasterPortDefault,
        IOServiceMatching(serviceName));

    if (!service) return "";

    CFTypeRef property = IORegistryEntryCreateCFProperty(
        service, propertyKey, kCFAllocatorDefault, 0);
    IOObjectRelease(service);

    if (!property) return "";

    std::string result;
    if (CFGetTypeID(property) == CFStringGetTypeID()) {
        CFStringRef str = (CFStringRef)property;
        char buffer[256];
        if (CFStringGetCString(str, buffer, sizeof(buffer),
                               kCFStringEncodingUTF8)) {
            result = std::string(buffer);
        }
    }

    CFRelease(property);
    return result;
}

std::string GetMacAddress() {
    struct ifaddrs* ifaddr = nullptr;
    if (getifaddrs(&ifaddr) == -1) return "";

    std::string result;
    std::vector<std::string> blacklist = {
        "lo", "bridge", "vmnet", "utun", "awdl", "llw"
    };

    for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_LINK) continue;

        std::string name = ifa->ifa_name;
        bool is_virtual = false;
        for (const auto& keyword : blacklist) {
            if (name.find(keyword) != std::string::npos) {
                is_virtual = true;
                break;
            }
        }
        if (is_virtual) continue;

        struct sockaddr_dl* sdl = (struct sockaddr_dl*)ifa->ifa_addr;
        if (sdl->sdl_alen == 6) {
            unsigned char* mac = (unsigned char*)LLADDR(sdl);

            bool all_zero = true;
            for (int i = 0; i < 6; ++i) {
                if (mac[i] != 0) {
                    all_zero = false;
                    break;
                }
            }

            if (!all_zero) {
                char macStr[18];
                snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                result = macStr;
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return result;
}

#endif // PLATFORM_MACOS

// ============================================================================
// 核心采集函数（跨平台统一接口）
// ============================================================================

std::vector<std::string> CollectHardwareComponents() {
    std::vector<std::string> components;

#if defined(PLATFORM_WINDOWS)
    std::string guid = ReadRegistryString(
        HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Cryptography",
        L"MachineGuid");
    if (IsValidHardwareId(guid)) {
        components.push_back(guid);
    }

    std::string cpuId = QueryWMI(L"Win32_Processor", L"ProcessorId");
    if (IsValidHardwareId(cpuId)) {
        components.push_back(cpuId);
    }

    std::string boardSN = QueryWMI(L"Win32_BaseBoard", L"SerialNumber");
    if (IsValidHardwareId(boardSN)) {
        components.push_back(boardSN);
    }

    std::string diskSN = QueryWMI(L"Win32_PhysicalMedia", L"SerialNumber");
    if (IsValidHardwareId(diskSN)) {
        components.push_back(diskSN);
    }

    std::string mac = GetMacAddress();
    if (!mac.empty()) {
        components.push_back(mac);
    }

#elif defined(PLATFORM_LINUX)
    std::string machineId = ReadFile("/etc/machine-id");
    if (machineId.empty() || machineId == "uninitialized") {
        machineId = ReadFile("/var/lib/dbus/machine-id");
    }
    if (IsValidHardwareId(machineId)) {
        components.push_back(machineId);
    }

    if (IsInContainer()) {
        std::string hostId = ReadFile("/host/etc/machine-id");
        if (hostId.empty()) {
            hostId = ReadFile("/proc/1/root/etc/machine-id");
        }
        if (IsValidHardwareId(hostId)) {
            components.push_back("container-" + hostId);
        }
    }

    std::string productUUID = ReadFile("/sys/class/dmi/id/product_uuid");
    if (IsValidHardwareId(productUUID)) {
        components.push_back(productUUID);
    }

    std::string boardSN = ReadFile("/sys/class/dmi/id/board_serial");
    if (IsValidHardwareId(boardSN)) {
        components.push_back(boardSN);
    }

    std::string cpuId = GetCPUInfo();
    if (IsValidHardwareId(cpuId)) {
        components.push_back(cpuId);
    }

    for (const char* dev : {"sda", "nvme0n1", "hda", "vda"}) {
        std::string path = "/sys/block/" + std::string(dev) + "/device/serial";
        std::string serial = ReadFile(path);
        if (IsValidHardwareId(serial)) {
            components.push_back(serial);
            break;
        }
    }

    std::string mac = GetMacAddress();
    if (!mac.empty()) {
        components.push_back(mac);
    }

    long hostid = gethostid();
    if (hostid != -1) {
        std::stringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << hostid;
        std::string hostidStr = ss.str();
        if (IsValidHardwareId(hostidStr)) {
            components.push_back(hostidStr);
        }
    }

#elif defined(PLATFORM_MACOS)
    std::string uuid = GetIOKitProperty("IOPlatformExpertDevice", CFSTR("IOPlatformUUID"));
    if (IsValidHardwareId(uuid)) {
        components.push_back(uuid);
    }

    std::string boardSN = GetIOKitProperty("IOPlatformExpertDevice", CFSTR("board-id"));
    if (IsValidHardwareId(boardSN)) {
        components.push_back(boardSN);
    }

    io_iterator_t iter;
    if (IOServiceGetMatchingServices(kIOMasterPortDefault,
                                     IOServiceMatching("IOBlockStorageDevice"), &iter) == KERN_SUCCESS) {
        io_service_t service;
        while ((service = IOIteratorNext(iter)) != 0) {
            CFTypeRef property = IORegistryEntryCreateCFProperty(
                service, CFSTR("Serial Number"), kCFAllocatorDefault, 0);
            if (property) {
                if (CFGetTypeID(property) == CFStringGetTypeID()) {
                    char buffer[128];
                    if (CFStringGetCString((CFStringRef)property, buffer,
                                           sizeof(buffer), kCFStringEncodingUTF8)) {
                        std::string serial = std::string(buffer);
                        if (IsValidHardwareId(serial)) {
                            components.push_back(serial);
                        }
                        CFRelease(property);
                        IOObjectRelease(service);
                        break;
                    }
                }
                CFRelease(property);
            }
            IOObjectRelease(service);
        }
        IOObjectRelease(iter);
    }

    std::string mac = GetMacAddress();
    if (!mac.empty()) {
        components.push_back(mac);
    }

    std::string sysSN = GetIOKitProperty("IOPlatformExpertDevice", CFSTR("IOPlatformSerialNumber"));
    if (IsValidHardwareId(sysSN)) {
        components.push_back(sysSN);
    }
#endif

    return components;
}

} // namespace internal

// ============================================================================
// 公共接口实现
// ============================================================================

std::string GetHardwareId() {
    auto components = internal::CollectHardwareComponents();

    if (components.empty()) {
        return internal::GetPersistentFallbackId();
    }

    std::set<std::string> unique_components(components.begin(), components.end());

    std::string combined;
    for (const auto& comp : unique_components) {
        if (!combined.empty()) combined += "|";
        combined += comp;
    }

    return combined;
}

std::string GetHashedHardwareId() {
    std::string rawId = GetHardwareId();
    if (rawId.empty()) {
        return internal::GetPersistentFallbackId();
    }
    return internal::SHA256(rawId);
}

bool IsRunningInVM() {
#if defined(PLATFORM_WINDOWS)
    std::string manufacturer = internal::QueryWMI(L"Win32_ComputerSystem", L"Manufacturer");
    std::string model = internal::QueryWMI(L"Win32_ComputerSystem", L"Model");
    std::string combined = internal::ToLower(manufacturer + " " + model);
    if (combined.find("vmware") != std::string::npos ||
        combined.find("virtualbox") != std::string::npos ||
        combined.find("hyper-v") != std::string::npos ||
        combined.find("qemu") != std::string::npos ||
        combined.find("microsoft corporation") != std::string::npos) {
        return true;
    }

#elif defined(PLATFORM_LINUX)
    std::string sysVendor = internal::ReadFile("/sys/class/dmi/id/sys_vendor");
    std::string productName = internal::ReadFile("/sys/class/dmi/id/product_name");
    std::string combined = internal::ToLower(sysVendor + " " + productName);
    if (combined.find("vmware") != std::string::npos ||
        combined.find("virtualbox") != std::string::npos ||
        combined.find("qemu") != std::string::npos ||
        combined.find("kvm") != std::string::npos ||
        combined.find("microsoft") != std::string::npos) {
        return true;
    }

    std::ifstream cpuinfo("/proc/cpuinfo");
    std::string line;
    while (std::getline(cpuinfo, line)) {
        if (line.find("hypervisor") != std::string::npos) {
            return true;
        }
    }
#elif defined(PLATFORM_MACOS)
    std::string model = internal::GetIOKitProperty("IOPlatformExpertDevice", CFSTR("model"));
    std::string combined = internal::ToLower(model);
    if (combined.find("vmware") != std::string::npos ||
        combined.find("virtualbox") != std::string::npos) {
        return true;
    }
#endif
    return false;
}

bool IsValid() {
    auto components = internal::CollectHardwareComponents();

    int validCount = 0;
    for (const auto& comp : components) {
        if (internal::IsValidHardwareId(comp)) {
            validCount++;
        }
    }

    return validCount >= 2;
}

int GetComponentCount() {
    auto components = internal::CollectHardwareComponents();
    std::set<std::string> unique_components(components.begin(), components.end());
    return static_cast<int>(unique_components.size());
}

void SetPersistentStoragePath(const std::string& path) {
    std::lock_guard<std::mutex> lock(internal::g_mutex);
    internal::g_persistentStoragePath = path;
}

} // namespace MachineId
