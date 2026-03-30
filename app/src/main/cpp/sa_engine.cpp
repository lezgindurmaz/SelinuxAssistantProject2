#include <jni.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdlib>

static std::string trim(const std::string &s) {
    size_t start = s.find_first_not_of(" \n\r\t");
    size_t end = s.find_last_not_of(" \n\r\t");
    if (start == std::string::npos) return "";
    return s.substr(start, end - start + 1);
}

static bool fileExists(const std::string &path) {
    return access(path.c_str(), F_OK) == 0;
}

static std::string readFile(const std::string &path, size_t maxBytes = 1024 * 1024) {
    std::ifstream in(path, std::ios::in | std::ios::binary);
    if (!in) return "";
    std::ostringstream ss;
    char buf[4096];
    size_t total = 0;
    while (in.good() && total < maxBytes) {
        in.read(buf, sizeof(buf));
        std::streamsize got = in.gcount();
        if (got <= 0) break;
        ss.write(buf, got);
        total += static_cast<size_t>(got);
    }
    return ss.str();
}

static std::string getProp(const char *key) {
    char value[PROP_VALUE_MAX] = {0};
    __system_property_get(key, value);
    return std::string(value);
}

static std::vector<std::string> existingPaths(std::initializer_list<const char*> paths) {
    std::vector<std::string> out;
    for (const char* p : paths) {
        if (fileExists(p)) out.emplace_back(p);
    }
    return out;
}

static int statusFieldInt(const std::string &fieldName) {
    std::ifstream in("/proc/self/status");
    if (!in) return -1;

    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind(fieldName, 0) == 0) {
            std::string value = trim(line.substr(fieldName.size()));
            try { return std::stoi(value); } catch (...) { return -1; }
        }
    }
    return -1;
}

static int tracerPid() {
    return statusFieldInt("TracerPid:");
}

static int seccompMode() {
    return statusFieldInt("Seccomp:");
}

static bool selinuxEnforcing() {
    std::string value = trim(readFile("/sys/fs/selinux/enforce", 16));
    return value == "1";
}

static std::string selinuxContext() {
    return trim(readFile("/proc/self/attr/current", 512));
}

static std::vector<std::string> insecureProps() {
    std::vector<std::string> out;

    std::string dbg = getProp("ro.debuggable");
    if (dbg == "1") out.emplace_back("ro.debuggable=1");

    std::string secure = getProp("ro.secure");
    if (secure == "0") out.emplace_back("ro.secure=0");

    std::string tags = getProp("ro.build.tags");
    if (tags.find("test-keys") != std::string::npos) out.emplace_back("ro.build.tags=" + tags);

    std::string type = getProp("ro.build.type");
    if (type == "eng" || type == "userdebug") out.emplace_back("ro.build.type=" + type);

    std::string flashLocked = getProp("ro.boot.flash.locked");
    if (!flashLocked.empty() && flashLocked != "1") out.emplace_back("ro.boot.flash.locked=" + flashLocked);

    std::string vbmetaState = getProp("ro.boot.vbmeta.device_state");
    if (!vbmetaState.empty() && vbmetaState != "locked") out.emplace_back("ro.boot.vbmeta.device_state=" + vbmetaState);

    return out;
}

static std::vector<std::string> suspiciousMounts() {
    std::vector<std::string> out;
    std::ifstream in("/proc/mounts");
    if (!in) return out;

    std::string line;
    while (std::getline(in, line)) {
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        bool systemPartition =
                lower.find(" /system ") != std::string::npos ||
                lower.find(" /vendor ") != std::string::npos ||
                lower.find(" /product ") != std::string::npos ||
                lower.find(" /system_ext ") != std::string::npos;

        bool suspicious =
                lower.find("magisk") != std::string::npos ||
                lower.find("overlay") != std::string::npos ||
                lower.find("tmpfs") != std::string::npos;

        if (systemPartition && suspicious) {
            out.emplace_back(line);
            if (out.size() >= 12) break;
        }
    }
    return out;
}

static std::vector<std::string> suspiciousMaps() {
    std::vector<std::string> out;
    std::ifstream in("/proc/self/maps");
    if (!in) return out;

    std::string line;
    while (std::getline(in, line)) {
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

        if (lower.find("zygisk") != std::string::npos ||
            lower.find("magisk") != std::string::npos ||
            lower.find("riru") != std::string::npos ||
            lower.find("xposed") != std::string::npos ||
            lower.find("lsposed") != std::string::npos ||
            lower.find("edxposed") != std::string::npos ||
            lower.find("frida") != std::string::npos ||
            lower.find("substrate") != std::string::npos) {
            out.emplace_back(line);
            if (out.size() >= 12) break;
        }
    }
    return out;
}

static std::vector<std::string> envIndicators() {
    std::vector<std::string> out;
    const char* ldPreload = getenv("LD_PRELOAD");
    if (ldPreload && *ldPreload) out.emplace_back(std::string("LD_PRELOAD=") + ldPreload);

    const char* inject = getenv("DYLD_INSERT_LIBRARIES");
    if (inject && *inject) out.emplace_back(std::string("DYLD_INSERT_LIBRARIES=") + inject);

    return out;
}

static std::string jsonEscape(const std::string &s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '\"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    o << "\\u"
                      << std::hex << std::uppercase
                      << (int)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

static std::string toJsonArray(const std::vector<std::string> &items) {
    std::ostringstream o;
    o << "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) o << ",";
        o << "\"" << jsonEscape(items[i]) << "\"";
    }
    o << "]";
    return o.str();
}

extern "C"
JNIEXPORT jstring JNICALL
Java_com_selinuxassistant_guardx_engine_NativeBridge_runNativeChecks(
        JNIEnv *env,
        jobject /*thiz*/) {

    auto suPaths = existingPaths({
        "/system/bin/su",
        "/system/xbin/su",
        "/sbin/su",
        "/vendor/bin/su",
        "/su/bin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system_ext/bin/su"
    });

    auto rootArtifacts = existingPaths({
        "/sbin/.magisk",
        "/debug_ramdisk/.magisk",
        "/data/adb/magisk",
        "/data/adb/ksu",
        "/data/adb/modules",
        "/data/adb/riru",
        "/system/bin/.ext/.su",
        "/cache/.disable_magisk"
    });

    auto mounts = suspiciousMounts();
    auto maps = suspiciousMaps();
    auto props = insecureProps();
    auto envs = envIndicators();

    std::string nativeBridge = getProp("ro.dalvik.vm.native.bridge");
    std::string verifiedBootState = getProp("ro.boot.verifiedbootstate");

    std::ostringstream json;
    json << "{"
         << "\"tracerPid\":" << tracerPid() << ","
         << "\"seccompMode\":" << seccompMode() << ","
         << "\"selinuxEnforcing\":" << (selinuxEnforcing() ? "true" : "false") << ","
         << "\"selinuxContext\":\"" << jsonEscape(selinuxContext()) << "\","
         << "\"nativeBridge\":\"" << jsonEscape(nativeBridge) << "\","
         << "\"verifiedBootState\":\"" << jsonEscape(verifiedBootState) << "\","
         << "\"suPaths\":" << toJsonArray(suPaths) << ","
         << "\"rootArtifacts\":" << toJsonArray(rootArtifacts) << ","
         << "\"suspiciousMounts\":" << toJsonArray(mounts) << ","
         << "\"suspiciousMaps\":" << toJsonArray(maps) << ","
         << "\"envIndicators\":" << toJsonArray(envs) << ","
         << "\"insecureProps\":" << toJsonArray(props)
         << "}";

    std::string out = json.str();
    return env->NewStringUTF(out.c_str());
}