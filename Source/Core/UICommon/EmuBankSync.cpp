// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "UICommon/EmuBankSync.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <fmt/format.h>
#include <mbedtls/sha256.h>
#include <picojson.h>

#include "Common/CommonTypes.h"
#include "Common/Config/Config.h"
#include "Common/FileUtil.h"
#include "Common/HookableEvent.h"
#include "Common/HttpRequest.h"
#include "Common/IOFile.h"
#include "Common/JsonUtil.h"
#include "Common/Logging/Log.h"
#include "Common/Random.h"
#include "Common/StringUtil.h"
#include "Common/Thread.h"

#include "Core/Config/MainSettings.h"
#include "Core/Core.h"

namespace UICommon::EmuBank
{
namespace
{
using namespace std::chrono_literals;

constexpr std::chrono::seconds HTTP_TIMEOUT = 8s;
constexpr std::chrono::seconds HTTP_TOTAL_TIMEOUT = 60s;
constexpr std::chrono::seconds SYNC_OPERATION_TIMEOUT = 30s;
constexpr std::chrono::seconds LIVE_UPLOAD_DEBOUNCE = 2s;
constexpr std::chrono::milliseconds SAVE_EVENT_QUIET_PERIOD = 750ms;
constexpr u64 MAX_PAIRING_RESPONSE_SIZE = 256 * 1024;
constexpr u64 MAX_SAVE_SIZE = 64 * 1024 * 1024;
constexpr std::string_view ZERO_SHA256 =
    "0000000000000000000000000000000000000000000000000000000000000000";

enum class SyncMode
{
  Idle,
  Live,
  BeforeLaunch,
};

enum class UploadResult
{
  Success,
  Conflict,
  Failed,
};

struct Revision
{
  std::string id;
  std::string sha256;
  u64 size = 0;
};

struct Binding
{
  std::string id;
  std::string relative_path;
  std::string sync_mode;
  std::string status;
  std::optional<Revision> current_revision;
  std::optional<Revision> conflict_revision;
};

struct Manifest
{
  std::vector<Binding> bindings;
};

struct Connection
{
  std::string base_url;
  std::string device_id;
  std::string token;
};

struct LocalState
{
  std::string base_sha256;
  std::string revision_id;
  bool conflict_pending = false;
  std::string conflict_sha256;
  bool ancestor_invalidated = false;
};

struct FileSnapshot
{
  std::vector<u8> contents;
  std::string sha256;
};

struct PendingUpload
{
  std::string sha256;
  std::chrono::steady_clock::time_point first_seen;
};

struct PairingSession
{
  std::string base_url;
  std::string id;
  std::string claim_token;
  std::string local_secret;
  std::chrono::steady_clock::time_point expires_at;
  std::chrono::seconds interval;
};

struct SyncStats
{
  int bindings = 0;
  int current = 0;
  int uploaded = 0;
  int downloaded = 0;
  int deferred = 0;
  int conflicts = 0;
  int errors = 0;
};

std::string Trim(std::string_view value)
{
  return std::string{StripWhitespace(value)};
}

bool IsSha256(std::string_view value)
{
  return value.size() == 64 && std::ranges::all_of(value, [](char c) {
           return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
         });
}

bool IsSafeIdentifier(std::string_view value)
{
  if (value.empty() || value.size() > 128)
    return false;

  return std::ranges::all_of(value, [](const char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
  });
}

bool IsSafeSecret(std::string_view value)
{
  if (value.empty() || value.size() > 128)
    return false;

  return std::ranges::all_of(value, [](const char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
  });
}

bool IsSafePairingToken(std::string_view value)
{
  return value.size() == 43 && std::ranges::all_of(value, [](const char c) {
           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '_';
         });
}

Common::HttpRequest::ProgressCallback LimitTransfer(
    u64 max_download, u64 max_upload,
    std::optional<std::chrono::steady_clock::time_point> operation_deadline = std::nullopt)
{
  const auto deadline =
      operation_deadline.value_or(std::chrono::steady_clock::now() + HTTP_TOTAL_TIMEOUT);
  return [deadline, max_download, max_upload](s64 download_total, s64 download_now,
                                              s64 upload_total, s64 upload_now) {
    const auto within_limit = [](s64 value, u64 limit) {
      return value < 0 || static_cast<u64>(value) <= limit;
    };
    return std::chrono::steady_clock::now() <= deadline &&
           within_limit(download_total, max_download) && within_limit(download_now, max_download) &&
           within_limit(upload_total, max_upload) && within_limit(upload_now, max_upload);
  };
}

std::string CalculateSha256(std::span<const u8> bytes)
{
  std::array<u8, 32> digest{};
  if (mbedtls_sha256_ret(bytes.data(), bytes.size(), digest.data(), 0) != 0)
    return {};

  static constexpr char HEX[] = "0123456789abcdef";
  std::string result(digest.size() * 2, '\0');
  for (size_t i = 0; i < digest.size(); ++i)
  {
    result[i * 2] = HEX[digest[i] >> 4];
    result[i * 2 + 1] = HEX[digest[i] & 0xf];
  }
  return result;
}

std::string GenerateSecret()
{
  std::array<u8, 32> bytes{};
  Common::Random::Generate(bytes.data(), bytes.size());

  static constexpr char HEX[] = "0123456789abcdef";
  std::string result(bytes.size() * 2, '\0');
  for (size_t i = 0; i < bytes.size(); ++i)
  {
    result[i * 2] = HEX[bytes[i] >> 4];
    result[i * 2 + 1] = HEX[bytes[i] & 0xf];
  }
  return result;
}

std::optional<std::string> ObjectString(const picojson::object& object, std::string_view key)
{
  const auto it = object.find(std::string{key});
  if (it == object.end() || !it->second.is<std::string>())
    return std::nullopt;
  return it->second.get<std::string>();
}

const picojson::object* ObjectValue(const picojson::object& object, std::string_view key)
{
  const auto it = object.find(std::string{key});
  if (it == object.end() || !it->second.is<picojson::object>())
    return nullptr;
  return &it->second.get<picojson::object>();
}

std::optional<int> ObjectInteger(const picojson::object& object, std::string_view key)
{
  const auto it = object.find(std::string{key});
  if (it == object.end() || !it->second.is<double>())
    return std::nullopt;
  const double value = it->second.get<double>();
  if (value < static_cast<double>(std::numeric_limits<int>::min()) ||
      value > static_cast<double>(std::numeric_limits<int>::max()) || value != std::floor(value))
  {
    return std::nullopt;
  }
  return static_cast<int>(value);
}

const picojson::object* ParseJsonObject(std::span<const u8> body, picojson::value* storage)
{
  const std::string json{reinterpret_cast<const char*>(body.data()), body.size()};
  const std::string error = picojson::parse(*storage, json);
  if (!error.empty() || !storage->is<picojson::object>())
    return nullptr;
  return &storage->get<picojson::object>();
}

std::optional<std::string> NormalizeServerUrl(std::string server_url, bool allow_insecure,
                                              std::string* error)
{
  server_url = Trim(server_url);
  const size_t api_path = server_url.find("/api/v1/devices/");
  if (api_path != std::string::npos)
    server_url.erase(api_path);
  while (!server_url.empty() && server_url.back() == '/')
    server_url.pop_back();

  const bool https = server_url.starts_with("https://");
  const bool http = server_url.starts_with("http://");
  const bool has_unsafe_character = server_url.find_first_of("\\?#") != std::string::npos ||
                                    std::ranges::any_of(server_url, [](const char c) {
                                      const auto byte = static_cast<unsigned char>(c);
                                      return byte <= 0x20 || byte == 0x7f;
                                    });
  if ((!https && !http) || has_unsafe_character)
  {
    *error = "EmuBank server URL is invalid.";
    return std::nullopt;
  }
  if (http && !allow_insecure)
  {
    *error = "EmuBank blocked insecure HTTP. Use HTTPS or explicitly allow HTTP.";
    return std::nullopt;
  }

  const size_t host_offset = https ? 8 : 7;
  const size_t host_end = server_url.find('/', host_offset);
  const std::string_view host = std::string_view{server_url}.substr(
      host_offset, host_end == std::string::npos ? std::string::npos : host_end - host_offset);
  if (host.empty() || host.find('@') != std::string_view::npos)
  {
    *error = "EmuBank server URL is invalid.";
    return std::nullopt;
  }
  return server_url;
}

std::optional<Revision> ParseRevision(const picojson::value& value)
{
  if (!value.is<picojson::object>())
    return std::nullopt;

  const auto& object = value.get<picojson::object>();
  Revision revision;
  revision.id = ObjectString(object, "id").value_or("");
  revision.sha256 = ObjectString(object, "sha256").value_or("");
  Common::ToLower(&revision.sha256);

  const auto size_it = object.find("size_bytes");
  if (size_it == object.end() || !size_it->second.is<double>())
    return std::nullopt;
  const double size = size_it->second.get<double>();
  if (size < 1.0 || size > static_cast<double>(MAX_SAVE_SIZE) || size != std::floor(size))
    return std::nullopt;
  revision.size = static_cast<u64>(size);

  if (!IsSafeIdentifier(revision.id) || !IsSha256(revision.sha256))
    return std::nullopt;
  return revision;
}

std::optional<Manifest> ParseManifest(std::span<const u8> body)
{
  picojson::value root;
  const std::string json{reinterpret_cast<const char*>(body.data()), body.size()};
  const std::string error = picojson::parse(root, json);
  if (!error.empty() || !root.is<picojson::object>())
    return std::nullopt;

  const auto data = ObjectValue(root.get<picojson::object>(), "data");
  if (!data)
    return std::nullopt;

  const auto bindings_it = data->find("bindings");
  if (bindings_it == data->end() || !bindings_it->second.is<picojson::array>())
    return std::nullopt;

  Manifest manifest;
  for (const picojson::value& value : bindings_it->second.get<picojson::array>())
  {
    if (!value.is<picojson::object>())
      continue;

    const auto& object = value.get<picojson::object>();
    if (ObjectString(object, "driver").value_or("") != "dolphin")
      continue;

    Binding binding;
    binding.id = ObjectString(object, "id").value_or("");
    binding.relative_path = ObjectString(object, "relative_path").value_or("");
    binding.sync_mode = ObjectString(object, "sync_mode").value_or("two_way");
    binding.status = ObjectString(object, "status").value_or("");

    const auto revision_it = object.find("current_revision");
    if (revision_it != object.end())
      binding.current_revision = ParseRevision(revision_it->second);

    const auto conflict_revision_it = object.find("conflict_revision");
    if (conflict_revision_it != object.end())
      binding.conflict_revision = ParseRevision(conflict_revision_it->second);

    if (!IsSafeIdentifier(binding.id) || binding.relative_path.empty())
      continue;
    manifest.bindings.emplace_back(std::move(binding));
  }

  return manifest;
}

std::optional<Revision> ParseUploadRevision(std::span<const u8> body)
{
  picojson::value root;
  const std::string json{reinterpret_cast<const char*>(body.data()), body.size()};
  const std::string error = picojson::parse(root, json);
  if (!error.empty() || !root.is<picojson::object>())
    return std::nullopt;

  const auto data = ObjectValue(root.get<picojson::object>(), "data");
  if (!data)
    return std::nullopt;
  const auto revision_it = data->find("current_revision");
  if (revision_it == data->end())
    return std::nullopt;
  return ParseRevision(revision_it->second);
}

bool IsAllowedSaveName(std::string filename)
{
  Common::ToLower(&filename);
  const size_t dot = filename.rfind('.');
  const std::string extension = dot == std::string::npos ? filename : filename.substr(dot + 1);
  static const std::set<std::string, std::less<>> ALLOWED_EXTENSIONS = {
      "sav", "srm", "dsv", "dat", "gci", "bin", "raw", "main"};
  return ALLOWED_EXTENSIONS.contains(extension);
}

std::optional<std::string> ResolveSavePath(std::string relative_path)
{
  if (relative_path.empty() || relative_path.size() > 255 || relative_path.front() == '/' ||
      relative_path.front() == '\\')
  {
    return std::nullopt;
  }

  std::ranges::replace(relative_path, '\\', '/');
  std::vector<std::string> components;
  size_t offset = 0;
  while (offset <= relative_path.size())
  {
    const size_t separator = relative_path.find('/', offset);
    const size_t end = separator == std::string::npos ? relative_path.size() : separator;
    std::string component = relative_path.substr(offset, end - offset);
    if (component.empty() || component == "." || component == ".." ||
        component.find(':') != std::string::npos || std::ranges::any_of(component, [](char c) {
          const auto byte = static_cast<unsigned char>(c);
          return byte < 0x20 || byte == 0x7f;
        }))
    {
      return std::nullopt;
    }
    components.emplace_back(std::move(component));
    if (separator == std::string::npos)
      break;
    offset = separator + 1;
  }

  if (components.size() < 2 ||
      (!Common::CaseInsensitiveEquals(components.front(), "GC") &&
       !Common::CaseInsensitiveEquals(components.front(), "Wii")) ||
      !IsAllowedSaveName(components.back()))
  {
    return std::nullopt;
  }

  namespace fs = std::filesystem;
  std::error_code error;
  const bool is_gamecube = Common::CaseInsensitiveEquals(components.front(), "GC");
  const int root_index = is_gamecube ? D_GCUSER_IDX : D_WIIROOT_IDX;
  const fs::path root =
      fs::weakly_canonical(StringToPath(File::GetUserPath(root_index)), error);
  if (error)
    return std::nullopt;

  fs::path candidate = root;
  for (size_t index = 1; index < components.size(); ++index)
    candidate /= StringToPath(components[index]);
  candidate = fs::weakly_canonical(candidate, error);
  if (error)
    return std::nullopt;

  const fs::path resolved_relative = candidate.lexically_relative(root);
  if (resolved_relative.empty() || resolved_relative.is_absolute())
    return std::nullopt;
  for (const fs::path& component : resolved_relative)
  {
    if (component == "..")
      return std::nullopt;
  }

  return PathToString(candidate);
}

std::optional<FileSnapshot> ReadSaveFile(const std::string& path)
{
  namespace fs = std::filesystem;
  std::error_code error;
  const fs::path native_path = StringToPath(path);
  if (!fs::is_regular_file(native_path, error) || error)
    return std::nullopt;

  const u64 size_before = fs::file_size(native_path, error);
  if (error || size_before == 0 || size_before > MAX_SAVE_SIZE)
    return std::nullopt;
  const fs::file_time_type modified_before = fs::last_write_time(native_path, error);
  if (error)
    return std::nullopt;

  File::IOFile file(path, "rb", File::SharedAccess::Read);
  if (!file || file.GetSize() != size_before)
    return std::nullopt;

  FileSnapshot snapshot;
  snapshot.contents.resize(static_cast<size_t>(size_before));
  if (!file.ReadBytes(snapshot.contents.data(), snapshot.contents.size()))
    return std::nullopt;
  file.Close();

  const u64 size_after = fs::file_size(native_path, error);
  if (error || size_before != size_after ||
      fs::last_write_time(native_path, error) != modified_before || error)
  {
    return std::nullopt;
  }

  snapshot.sha256 = CalculateSha256(snapshot.contents);
  if (!IsSha256(snapshot.sha256))
    return std::nullopt;
  return snapshot;
}

bool WriteAtomically(const std::string& path, std::span<const u8> contents)
{
  if (!File::CreateFullPath(path))
    return false;

  const std::string temporary_path = File::GetTempFilenameForAtomicWrite(path);
  File::Delete(temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
  {
    File::IOFile file(temporary_path, "wb");
    if (!file || !file.WriteBytes(contents.data(), contents.size()) || !file.Flush())
    {
      File::Delete(temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
      return false;
    }
  }

  if (!File::MoveWithOverwrite(temporary_path, path))
  {
    File::Delete(temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
    return false;
  }
  return true;
}

class Manager final
{
public:
  Manager()
  {
    LoadState();
    m_state_changed_hook = Core::AddOnStateChangedCallback(
        [this](Core::State state) { OnEmulationStateChanged(state); });
    m_save_data_changed_hook = Core::AddOnSaveDataChangedCallback([this] { OnSaveDataChanged(); });
    m_savestate_loaded_hook =
        Core::AddOnSavestateLoadedCallback([this] { OnSavestateLoaded(); });
    m_config_changed_callback = Config::AddConfigChangedCallback([this] { Request(); });
    m_worker = std::thread([this] { WorkerLoop(); });
    Request();
  }

  ~Manager() { Shutdown(); }

  void Shutdown()
  {
    if (m_shutdown.exchange(true, std::memory_order_acq_rel))
      return;

    {
      std::lock_guard lock(m_wake_mutex);
      m_stop = true;
    }
    m_wake_condition.notify_all();
    m_sync_finished_condition.notify_all();

    m_state_changed_hook.reset();
    m_save_data_changed_hook.reset();
    m_savestate_loaded_hook.reset();
    Config::RemoveConfigChangedCallback(m_config_changed_callback);

    if (m_worker.joinable())
      m_worker.join();

    // A successful savestate load can race shutdown after it queues ancestor invalidation but
    // before the worker consumes it. Persist that safety marker even when cloud sync is disabled.
    {
      std::lock_guard operation_lock(m_sync_mutex);
      PersistPendingAncestorInvalidation();
    }

    {
      std::lock_guard operation_lock(m_pairing_operation_mutex);
      StopPairing();
      FinalizePairingLocked();
    }

    const bool run_final_sync = !m_emulation_active && Config::Get(Config::MAIN_EMUBANK_ENABLED);
    if (run_final_sync)
      SyncOnce(SyncMode::Idle);
  }

  void Request()
  {
    if (m_shutdown.load(std::memory_order_acquire))
      return;

    {
      std::lock_guard lock(m_wake_mutex);
      if (m_stop)
        return;
      m_sync_requested = true;
      ++m_requested_generation;
    }
    m_wake_condition.notify_all();
  }

  bool SyncAndWait(std::chrono::milliseconds timeout)
  {
    if (timeout <= 0ms || m_emulation_active || m_shutdown.load(std::memory_order_acquire))
      return false;

    std::unique_lock lock(m_wake_mutex);
    if (m_stop)
      return false;

    const u64 target_generation = ++m_requested_generation;
    m_sync_requested = true;
    m_wake_condition.notify_all();
    return m_sync_finished_condition.wait_for(lock, timeout,
                                              [this, target_generation] {
                                                return m_stop ||
                                                       m_completed_generation >= target_generation;
                                              }) &&
           !m_stop && m_completed_generation >= target_generation;
  }

  std::string Status() const
  {
    std::lock_guard lock(m_status_mutex);
    return m_status;
  }

  PairingStartResult BeginPairing(std::string server_url, std::string device_name,
                                  std::string platform)
  {
    std::lock_guard operation_lock(m_pairing_operation_mutex);
    if (m_shutdown.load(std::memory_order_acquire))
    {
      const std::string error = "EmuBank cloud sync is shutting down.";
      SetStatus(error);
      return {.approval_url = {}, .error = error};
    }

    std::string operation_error;
    {
      std::lock_guard lock(m_pairing_mutex);
      if (m_pairing_state == PairingState::Waiting)
        operation_error = "An EmuBank authorization request is already in progress.";
      else if (m_pairing_state == PairingState::Ready)
        operation_error = "EmuBank authorization is approved and waiting to be finalized.";
    }
    if (!operation_error.empty())
    {
      SetStatus(operation_error);
      return {.approval_url = {}, .error = std::move(operation_error)};
    }

    StopPairing();
    {
      std::lock_guard lock(m_pairing_mutex);
      m_pairing_state = PairingState::Waiting;
      m_pairing_approval_url.clear();
      m_pairing_token.clear();
      m_paired_device_name.clear();
      m_pairing_cancel = false;
    }
    SetStatus("Contacting EmuBank to start device authorization…");

    std::string validation_error;
    auto base_url =
        NormalizeServerUrl(std::move(server_url),
                           Config::Get(Config::MAIN_EMUBANK_ALLOW_INSECURE), &validation_error);
    if (!base_url)
      return FailPairing(std::move(validation_error));

    device_name = Trim(device_name);
    platform = Trim(platform);
    if (device_name.empty())
      device_name = "Dolphin";
    if (device_name.size() > 120)
      device_name.resize(120);
    if (platform.size() > 60)
      platform.resize(60);

    const std::string local_secret = GenerateSecret();
    const std::span<const u8> secret_bytes{reinterpret_cast<const u8*>(local_secret.data()),
                                           local_secret.size()};
    const std::string credential_hash = CalculateSha256(secret_bytes);
    if (!IsSha256(credential_hash))
      return FailPairing("Dolphin could not generate an EmuBank device credential.");

    const std::string body = picojson::value{
        picojson::object{
            {"device_name", picojson::value{device_name}},
            {"client_type", picojson::value{"dolphin"}},
            {"platform", picojson::value{platform}},
            {"credential_hash", picojson::value{credential_hash}},
            {"credential_hint", picojson::value{local_secret.substr(local_secret.size() - 6)}},
        }}.serialize();

    Common::HttpRequest request(HTTP_TIMEOUT,
                                LimitTransfer(MAX_PAIRING_RESPONSE_SIZE, body.size()));
    const Common::HttpRequest::Headers headers{{"Accept", "application/json"},
                                               {"Content-Type", "application/json"},
                                               {"X-EmuBank-Client", "dolphin"}};
    const auto response = request.Post(*base_url + "/api/v1/device-pairings/start", body, headers,
                                       Common::HttpRequest::AllowedReturnCodes::All);
    if (!response)
      return FailPairing("EmuBank could not be reached to start authorization.");
    if (request.GetLastResponseCode() != 201)
    {
      return FailPairing(fmt::format("EmuBank authorization could not start (HTTP {}).",
                                     request.GetLastResponseCode()));
    }

    picojson::value root;
    const picojson::object* object = ParseJsonObject(*response, &root);
    if (!object)
      return FailPairing("EmuBank returned an invalid authorization response.");

    PairingSession session;
    session.base_url = std::move(*base_url);
    session.id = ObjectString(*object, "id").value_or("");
    session.claim_token = ObjectString(*object, "claim_token").value_or("");
    session.local_secret = local_secret;
    const std::string approval_url = ObjectString(*object, "approval_url").value_or("");
    const int expires_in = ObjectInteger(*object, "expires_in").value_or(0);
    const int interval = ObjectInteger(*object, "interval").value_or(0);
    if (!IsSafeIdentifier(session.id) || !IsSafePairingToken(session.claim_token) ||
        approval_url.size() > 4096 || !approval_url.starts_with(session.base_url + "/") ||
        expires_in < 30 || expires_in > 15 * 60 || interval < 1 || interval > 30)
    {
      return FailPairing("EmuBank returned an invalid authorization response.");
    }
    session.expires_at = std::chrono::steady_clock::now() + std::chrono::seconds{expires_in};
    session.interval = std::chrono::seconds{interval};

    if (m_shutdown.load(std::memory_order_acquire))
      return FailPairing("EmuBank cloud sync is shutting down.");

    {
      std::lock_guard lock(m_pairing_mutex);
      m_pairing_approval_url = approval_url;
    }
    m_pairing_thread = std::thread(
        [this, session = std::move(session)]() mutable { PairingLoop(std::move(session)); });
    SetStatus("EmuBank is waiting for authorization in your browser.");
    return {.approval_url = approval_url, .error = {}};
  }

  PairingState GetPairingState() const
  {
    std::lock_guard lock(m_pairing_mutex);
    return m_pairing_state;
  }

  std::string GetPairingApprovalUrl() const
  {
    std::lock_guard lock(m_pairing_mutex);
    return m_pairing_approval_url;
  }

  bool FinalizePairing()
  {
    std::lock_guard operation_lock(m_pairing_operation_mutex);
    if (m_shutdown.load(std::memory_order_acquire))
      return false;
    return FinalizePairingLocked();
  }

private:
  bool FinalizePairingLocked()
  {
    std::string base_url;
    std::string token;
    std::string device_name;
    {
      std::lock_guard lock(m_pairing_mutex);
      if (m_pairing_state != PairingState::Ready)
        return false;
      base_url = m_pairing_base_url;
      token = m_pairing_token;
      device_name = m_paired_device_name;
      m_pairing_state = PairingState::Idle;
      m_pairing_approval_url.clear();
      m_pairing_base_url.clear();
      m_pairing_token.clear();
      m_paired_device_name.clear();
    }

    Config::ConfigChangeCallbackGuard guard;
    Config::SetBase(Config::MAIN_EMUBANK_SERVER_URL, base_url);
    Config::SetBase(Config::MAIN_EMUBANK_DEVICE_TOKEN, token);
    Config::SetBase(Config::MAIN_EMUBANK_ENABLED, true);
    Config::Save();
    SetStatus(fmt::format("EmuBank authorized{}; syncing device bindings…",
                          device_name.empty() ? "" : " as " + device_name));
    return true;
  }

  PairingStartResult FailPairing(std::string error)
  {
    {
      std::lock_guard lock(m_pairing_mutex);
      m_pairing_state = PairingState::Failed;
      m_pairing_approval_url.clear();
    }
    SetStatus(error);
    return {.approval_url = {}, .error = std::move(error)};
  }

  void StopPairing()
  {
    {
      std::lock_guard lock(m_pairing_mutex);
      m_pairing_cancel = true;
    }
    m_pairing_condition.notify_all();
    if (m_pairing_thread.joinable())
      m_pairing_thread.join();
  }

  bool IsPairingCancelled() const
  {
    std::lock_guard lock(m_pairing_mutex);
    return m_pairing_cancel;
  }

  void PairingLoop(PairingSession session)
  {
    Common::SetCurrentThreadName("EmuBank Pairing");
    const std::string claim_url = session.base_url + "/api/v1/device-pairings/claim";
    const Common::HttpRequest::Headers headers{{"Accept", "application/json"},
                                               {"Content-Type", "application/json"},
                                               {"X-EmuBank-Client", "dolphin"}};
    const std::string body =
        picojson::value{picojson::object{{"id", picojson::value{session.id}},
                                         {"claim_token", picojson::value{session.claim_token}}}}
            .serialize();

    while (std::chrono::steady_clock::now() < session.expires_at)
    {
      {
        std::unique_lock lock(m_pairing_mutex);
        if (m_pairing_condition.wait_for(lock, session.interval,
                                         [this] { return m_pairing_cancel; }))
        {
          return;
        }
      }

      Common::HttpRequest request(HTTP_TIMEOUT,
                                  LimitTransfer(MAX_PAIRING_RESPONSE_SIZE, body.size()));
      const auto response =
          request.Post(claim_url, body, headers, Common::HttpRequest::AllowedReturnCodes::All);
      if (IsPairingCancelled())
        return;
      if (!response)
        continue;
      if (request.GetLastResponseCode() == 202)
        continue;
      if (request.GetLastResponseCode() == 410)
      {
        FailPairing("EmuBank authorization expired. Start a new connection request.");
        return;
      }
      if (request.GetLastResponseCode() != 200)
      {
        FailPairing(
            fmt::format("EmuBank authorization failed (HTTP {}).", request.GetLastResponseCode()));
        return;
      }

      picojson::value root;
      const picojson::object* object = ParseJsonObject(*response, &root);
      const std::string status = object ? ObjectString(*object, "status").value_or("") : "";
      const std::string device_id = object ? ObjectString(*object, "device_id").value_or("") : "";
      const std::string device_name =
          object ? ObjectString(*object, "device_name").value_or("") : "";
      if (status != "approved" || !IsSafeIdentifier(device_id) || device_name.size() > 120)
      {
        FailPairing("EmuBank returned an invalid authorization result.");
        return;
      }

      const std::string token = device_id + "." + session.local_secret;
      const Connection connection{session.base_url, device_id, token};
      Common::HttpRequest ping_request(HTTP_TIMEOUT, LimitTransfer(MAX_PAIRING_RESPONSE_SIZE, 0));
      const auto ping =
          ping_request.Get(fmt::format("{}/api/v1/devices/{}/ping", session.base_url, device_id),
                           Headers(connection), Common::HttpRequest::AllowedReturnCodes::All);
      if (!ping || ping_request.GetLastResponseCode() != 200)
      {
        FailPairing("EmuBank approved the device, but credential verification failed.");
        return;
      }

      {
        std::lock_guard lock(m_pairing_mutex);
        if (m_pairing_cancel)
          return;
        m_pairing_base_url = session.base_url;
        m_pairing_token = token;
        m_paired_device_name = device_name;
        m_pairing_state = PairingState::Ready;
      }
      SetStatus("EmuBank authorization approved. Finishing connection…");
      return;
    }

    if (!IsPairingCancelled())
      FailPairing("EmuBank authorization expired. Start a new connection request.");
  }

  void OnSaveDataChanged()
  {
    {
      std::lock_guard lock(m_wake_mutex);
      m_save_sync_deadline = std::chrono::steady_clock::now() + SAVE_EVENT_QUIET_PERIOD;
    }
    m_wake_condition.notify_all();
  }

  void OnSavestateLoaded()
  {
    m_invalidate_ancestors_requested.store(true, std::memory_order_release);
    Request();
  }

  void OnEmulationStateChanged(Core::State state)
  {
    if (state == Core::State::Starting)
    {
      m_emulation_active = true;
      SyncOnce(SyncMode::BeforeLaunch);
    }
    else if (state == Core::State::Running || state == Core::State::Paused ||
             state == Core::State::Stopping)
    {
      m_emulation_active = true;
    }
    else if (state == Core::State::Uninitialized)
    {
      m_emulation_active = false;
      Request();
    }
  }

  void WorkerLoop()
  {
    Common::SetCurrentThreadName("EmuBank Sync");
    while (true)
    {
      const int interval = std::clamp(Config::Get(Config::MAIN_EMUBANK_SYNC_INTERVAL), 5, 300);
      const bool periodic_sync_enabled =
          Config::Get(Config::MAIN_EMUBANK_ENABLED) &&
          (!m_emulation_active || Config::Get(Config::MAIN_EMUBANK_LIVE_SYNC));
      const auto live_retry = periodic_sync_enabled ? TimeUntilPendingLiveUploadReady() :
                                                      std::optional<std::chrono::milliseconds>{};
      std::unique_lock lock(m_wake_mutex);
      bool should_sync = false;
      if (periodic_sync_enabled)
      {
        const bool save_sync_due =
            m_save_sync_deadline && std::chrono::steady_clock::now() >= *m_save_sync_deadline;
        if (m_sync_requested || save_sync_due)
        {
          should_sync = true;
        }
        else
        {
          auto wait_duration =
              std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds{interval});
          if (live_retry)
            wait_duration = std::min(wait_duration, *live_retry);
          if (m_save_sync_deadline)
          {
            const auto until_save_sync =
                std::max(1ms, std::chrono::duration_cast<std::chrono::milliseconds>(
                                  *m_save_sync_deadline - std::chrono::steady_clock::now()));
            wait_duration = std::min(wait_duration, until_save_sync);
          }
          const auto wait_result = m_wake_condition.wait_for(lock, wait_duration);
          const bool save_sync_now =
              m_save_sync_deadline && std::chrono::steady_clock::now() >= *m_save_sync_deadline;
          should_sync = m_sync_requested || wait_result == std::cv_status::timeout || save_sync_now;
        }
        if (m_save_sync_deadline && std::chrono::steady_clock::now() >= *m_save_sync_deadline)
          m_save_sync_deadline.reset();
      }
      else
      {
        m_wake_condition.wait(lock, [this] { return m_stop || m_sync_requested; });
        should_sync = m_sync_requested;
      }
      if (m_stop)
        return;
      if (!should_sync)
        continue;
      const u64 request_generation = m_requested_generation;
      m_sync_requested = false;
      lock.unlock();

      const SyncMode mode = m_emulation_active ? SyncMode::Live : SyncMode::Idle;
      if (mode != SyncMode::Live || Config::Get(Config::MAIN_EMUBANK_LIVE_SYNC) ||
          !Config::Get(Config::MAIN_EMUBANK_ENABLED))
      {
        SyncOnce(mode);
      }
      else
      {
        {
          std::lock_guard operation_lock(m_sync_mutex);
          PersistPendingAncestorInvalidation();
        }
        SetStatus("EmuBank live sync is disabled; the next sync runs after emulation stops.");
      }

      lock.lock();
      m_completed_generation = std::max(m_completed_generation, request_generation);
      lock.unlock();
      m_sync_finished_condition.notify_all();
    }
  }

  std::optional<std::chrono::milliseconds> TimeUntilPendingLiveUploadReady()
  {
    std::lock_guard operation_lock(m_sync_mutex);
    if (!m_emulation_active || m_pending_uploads.empty())
      return std::nullopt;

    const auto now = std::chrono::steady_clock::now();
    std::optional<std::chrono::milliseconds> shortest;
    for (const auto& [id, upload] : m_pending_uploads)
    {
      const auto ready_at = upload.first_seen + LIVE_UPLOAD_DEBOUNCE;
      if (ready_at <= now)
        return 1ms;
      const auto remaining =
          std::max(1ms, std::chrono::duration_cast<std::chrono::milliseconds>(ready_at - now));
      shortest = shortest ? std::min(*shortest, remaining) : remaining;
    }
    return shortest;
  }

  std::optional<Connection> GetConnection()
  {
    if (!Config::Get(Config::MAIN_EMUBANK_ENABLED))
    {
      SetStatus("EmuBank cloud sync is disabled.");
      return std::nullopt;
    }

    const std::string configured_url = Trim(Config::Get(Config::MAIN_EMUBANK_SERVER_URL));
    const std::string token = Trim(Config::Get(Config::MAIN_EMUBANK_DEVICE_TOKEN));
    if (configured_url.empty() || token.empty())
    {
      SetStatus("EmuBank needs a server URL and device token.");
      return std::nullopt;
    }

    std::string validation_error;
    auto base_url = NormalizeServerUrl(
        configured_url, Config::Get(Config::MAIN_EMUBANK_ALLOW_INSECURE), &validation_error);
    if (!base_url)
    {
      SetStatus(std::move(validation_error));
      return std::nullopt;
    }

    const size_t separator = token.find('.');
    const std::string device_id = token.substr(0, separator);
    const std::string_view secret = separator == std::string::npos ?
                                        std::string_view{} :
                                        std::string_view{token}.substr(separator + 1);
    if (!IsSafeIdentifier(device_id) || !IsSafeSecret(secret))
    {
      SetStatus("EmuBank device token is invalid.");
      return std::nullopt;
    }

    return Connection{std::move(*base_url), device_id, token};
  }

  Common::HttpRequest::Headers Headers(const Connection& connection) const
  {
    return {{"Accept", "application/json"},
            {"Authorization", "Bearer " + connection.token},
            {"X-EmuBank-Client", "dolphin"}};
  }

  std::string BindingUrl(const Connection& connection, const Binding& binding) const
  {
    return fmt::format("{}/api/v1/devices/{}/bindings/{}", connection.base_url,
                       connection.device_id, binding.id);
  }

  std::optional<Manifest> FetchManifest(const Connection& connection)
  {
    Common::HttpRequest request(HTTP_TIMEOUT, LimitTransfer(MAX_SAVE_SIZE, 0, m_sync_deadline));
    const std::string url =
        fmt::format("{}/api/v1/devices/{}/manifest", connection.base_url, connection.device_id);
    const auto response =
        request.Get(url, Headers(connection), Common::HttpRequest::AllowedReturnCodes::All);
    if (!response)
    {
      SetStatus("EmuBank server could not be reached.");
      return std::nullopt;
    }
    if (request.GetLastResponseCode() == 401)
    {
      SetStatus("EmuBank rejected the device token.");
      return std::nullopt;
    }
    if (request.GetLastResponseCode() != 200)
    {
      SetStatus(fmt::format("EmuBank manifest failed (HTTP {}).", request.GetLastResponseCode()));
      return std::nullopt;
    }

    auto manifest = ParseManifest(*response);
    if (!manifest)
      SetStatus("EmuBank returned an invalid device manifest.");
    return manifest;
  }

  bool Download(const Connection& connection, const Binding& binding, const Revision& revision,
                const std::string& path, SyncStats* stats, bool preserve_conflict = false)
  {
    Common::HttpRequest request(HTTP_TIMEOUT, LimitTransfer(MAX_SAVE_SIZE, 0, m_sync_deadline));
    const auto response =
        request.Get(BindingUrl(connection, binding) + "/download", Headers(connection),
                    Common::HttpRequest::AllowedReturnCodes::All);
    if (!response || request.GetLastResponseCode() != 200)
    {
      ERROR_LOG_FMT(CORE, "EmuBank: failed to download '{}' (HTTP {})", binding.relative_path,
                    request.GetLastResponseCode());
      ++stats->errors;
      return false;
    }

    Revision downloaded_revision;
    downloaded_revision.id = request.GetHeaderValue("X-EmuBank-Revision-Id");
    downloaded_revision.sha256 = request.GetHeaderValue("X-EmuBank-Sha256");
    Common::ToLower(&downloaded_revision.sha256);
    downloaded_revision.size = response->size();
    if (response->empty() || response->size() > MAX_SAVE_SIZE ||
        !IsSafeIdentifier(downloaded_revision.id) || !IsSha256(downloaded_revision.sha256) ||
        CalculateSha256(*response) != downloaded_revision.sha256)
    {
      ERROR_LOG_FMT(CORE, "EmuBank: rejected invalid download for '{}'", binding.relative_path);
      ++stats->errors;
      return false;
    }
    if (!WriteAtomically(path, *response))
    {
      ERROR_LOG_FMT(CORE, "EmuBank: failed to replace local save '{}'", binding.relative_path);
      ++stats->errors;
      return false;
    }

    std::string retained_conflict_sha256;
    if (preserve_conflict)
    {
      const auto state = m_state.find(binding.id);
      if (state != m_state.end())
        retained_conflict_sha256 = state->second.conflict_sha256;
      if (retained_conflict_sha256.empty() && binding.conflict_revision)
        retained_conflict_sha256 = binding.conflict_revision->sha256;
    }

    UpdateState(binding.id, downloaded_revision.sha256, downloaded_revision.id);
    if (preserve_conflict)
    {
      m_state[binding.id].conflict_pending = true;
      m_state[binding.id].conflict_sha256 = std::move(retained_conflict_sha256);
      m_state_dirty = true;
    }
    m_pending_uploads.erase(binding.id);
    ++stats->downloaded;
    INFO_LOG_FMT(CORE, "EmuBank: downloaded '{}' at revision {}", binding.relative_path,
                 downloaded_revision.id);
    if (revision.id != downloaded_revision.id)
    {
      INFO_LOG_FMT(CORE,
                   "EmuBank: '{}' advanced from manifest revision {} while syncing; installed "
                   "the response's newer current revision {}",
                   binding.relative_path, revision.id, downloaded_revision.id);
    }
    return true;
  }

  UploadResult Upload(const Connection& connection, const Binding& binding,
                      const FileSnapshot& snapshot, std::string_view expected_sha256,
                      SyncStats* stats)
  {
    // A savestate may finish loading while an older sync pass is still examining files. Let the
    // next pass persist per-binding invalidation before any post-load bytes can be uploaded against
    // the old common ancestor.
    if (m_invalidate_ancestors_requested.load(std::memory_order_acquire))
    {
      ++stats->deferred;
      return UploadResult::Failed;
    }

    auto headers = Headers(connection);
    headers["Content-Type"] = "application/octet-stream";
    headers["X-EmuBank-Base-Sha256"] = std::string{expected_sha256};
    headers["X-EmuBank-Filename"] =
        binding.relative_path.substr(binding.relative_path.find_last_of("/\\") + 1);

    Common::HttpRequest request(
        HTTP_TIMEOUT, LimitTransfer(MAX_SAVE_SIZE, snapshot.contents.size(), m_sync_deadline));
    const auto response = request.Post(BindingUrl(connection, binding), snapshot.contents, headers,
                                       Common::HttpRequest::AllowedReturnCodes::All);
    if (!response)
    {
      ++stats->errors;
      return UploadResult::Failed;
    }
    if (request.GetLastResponseCode() == 409)
    {
      ++stats->conflicts;
      m_pending_uploads.erase(binding.id);
      LocalState& state = m_state[binding.id];
      state.base_sha256 = expected_sha256 == ZERO_SHA256 ? "" : std::string{expected_sha256};
      state.revision_id.clear();
      state.conflict_pending = true;
      state.conflict_sha256 = snapshot.sha256;
      state.ancestor_invalidated = false;
      m_state_dirty = true;
      SaveState();
      WARN_LOG_FMT(CORE,
                   "EmuBank: '{}' changed locally and in the cloud; the local copy was retained "
                   "as a conflict revision",
                   binding.relative_path);
      return UploadResult::Conflict;
    }
    if (request.GetLastResponseCode() != 200)
    {
      ERROR_LOG_FMT(CORE, "EmuBank: failed to upload '{}' (HTTP {})", binding.relative_path,
                    request.GetLastResponseCode());
      ++stats->errors;
      return UploadResult::Failed;
    }

    const auto revision = ParseUploadRevision(*response);
    if (!revision || revision->sha256 != snapshot.sha256 ||
        revision->size != snapshot.contents.size())
    {
      ERROR_LOG_FMT(CORE, "EmuBank: upload response for '{}' was invalid", binding.relative_path);
      ++stats->errors;
      return UploadResult::Failed;
    }

    UpdateState(binding.id, snapshot.sha256, revision->id);
    m_pending_uploads.erase(binding.id);
    ++stats->uploaded;
    INFO_LOG_FMT(CORE, "EmuBank: uploaded '{}' as revision {}", binding.relative_path,
                 revision->id);
    return UploadResult::Success;
  }

  bool UploadAndRestoreCloudForLaunch(const Connection& connection, const Binding& binding,
                                      const FileSnapshot& snapshot,
                                      std::string_view expected_sha256, const Revision* cloud,
                                      const std::string& path, SyncMode mode, SyncStats* stats)
  {
    const UploadResult result = Upload(connection, binding, snapshot, expected_sha256, stats);
    if (result == UploadResult::Conflict && mode == SyncMode::BeforeLaunch && cloud != nullptr)
    {
      // The local copy is now retained as an immutable conflict revision, so installing the active
      // cloud revision cannot lose it and ensures the game opens EmuBank's latest selected save.
      Download(connection, binding, *cloud, path, stats, true);
    }
    return result == UploadResult::Success;
  }

  bool ReadyForLiveUpload(const Binding& binding, const FileSnapshot& snapshot, SyncMode mode,
                          SyncStats* stats)
  {
    if (mode != SyncMode::Live)
      return true;

    const auto now = std::chrono::steady_clock::now();
    auto [it, inserted] = m_pending_uploads.try_emplace(
        binding.id, PendingUpload{snapshot.sha256, std::chrono::steady_clock::now()});
    if (!inserted && it->second.sha256 != snapshot.sha256)
      it->second = {snapshot.sha256, now};
    if (inserted || now - it->second.first_seen < LIVE_UPLOAD_DEBOUNCE)
    {
      ++stats->deferred;
      return false;
    }
    return true;
  }

  void ProcessBinding(const Connection& connection, const Binding& binding, SyncMode mode,
                      SyncStats* stats)
  {
    ++stats->bindings;
    const bool server_conflict = binding.status == "conflict";
    if (binding.status != "active" && !server_conflict)
    {
      ++stats->deferred;
      return;
    }
    if (binding.sync_mode != "two_way" && binding.sync_mode != "upload_only" &&
        binding.sync_mode != "download_only")
    {
      ERROR_LOG_FMT(CORE, "EmuBank: refused unsupported sync mode '{}' for '{}'", binding.sync_mode,
                    binding.relative_path);
      ++stats->errors;
      return;
    }

    const auto path = ResolveSavePath(binding.relative_path);
    if (!path)
    {
      ERROR_LOG_FMT(CORE,
                    "EmuBank: refused unsafe or unsupported Dolphin save path '{}' (bindings "
                    "must be supported files below GC/ or Wii/)",
                    binding.relative_path);
      ++stats->errors;
      return;
    }

    const bool file_exists = File::IsFile(*path);
    const std::optional<FileSnapshot> local = file_exists ? ReadSaveFile(*path) : std::nullopt;
    if (file_exists && !local)
    {
      ++stats->deferred;
      return;
    }

    const bool can_upload = binding.sync_mode != "download_only";
    const bool can_download = binding.sync_mode != "upload_only";
    const bool downloads_open = mode != SyncMode::Live;

    auto state_it = m_state.find(binding.id);
    if (server_conflict)
    {
      ++stats->conflicts;
      if (!binding.current_revision)
        return;

      const Revision& cloud = *binding.current_revision;
      if (!local)
      {
        if (can_download && downloads_open)
          Download(connection, binding, cloud, *path, stats);
        else
          ++stats->deferred;
        return;
      }

      if (local->sha256 == cloud.sha256)
      {
        if (state_it != m_state.end() && state_it->second.ancestor_invalidated)
        {
          // The host file can still contain the pre-load bytes until the emulated card reaches its
          // next flush. Do not re-establish the old cloud hash as a common ancestor yet.
        }
        else if (state_it != m_state.end() && state_it->second.conflict_pending)
        {
          state_it->second.base_sha256 = cloud.sha256;
          state_it->second.revision_id = cloud.id;
          m_state_dirty = true;
        }
        else
        {
          UpdateState(binding.id, cloud.sha256, cloud.id);
        }
        m_pending_uploads.erase(binding.id);
        ++stats->current;
        return;
      }

      // Never act on a divergent file during somebody else's unresolved conflict. If this client
      // created the conflict, its retained revision hash proves when the current local bytes are
      // already backed up and when a later in-game save needs another guarded upload.
      if (state_it == m_state.end() || !state_it->second.conflict_pending)
        return;

      const bool local_is_retained = IsSha256(state_it->second.conflict_sha256) &&
                                     local->sha256 == state_it->second.conflict_sha256;
      const bool local_is_base =
          IsSha256(state_it->second.base_sha256) && local->sha256 == state_it->second.base_sha256;
      if (local_is_retained || local_is_base)
      {
        if (mode == SyncMode::BeforeLaunch && can_download)
          Download(connection, binding, cloud, *path, stats, true);
        else
          ++stats->deferred;
        return;
      }

      if (can_upload && ReadyForLiveUpload(binding, *local, mode, stats))
      {
        const std::string_view expected = state_it->second.ancestor_invalidated ?
                                              ZERO_SHA256 :
                                              (IsSha256(state_it->second.base_sha256) ?
                                                   state_it->second.base_sha256 :
                                                   ZERO_SHA256);
        UploadAndRestoreCloudForLaunch(connection, binding, *local, expected, &cloud, *path, mode,
                                       stats);
      }
      else if (!can_upload && mode == SyncMode::BeforeLaunch && can_download)
      {
        Download(connection, binding, cloud, *path, stats, true);
      }
      return;
    }

    if (!binding.current_revision)
    {
      if (local && can_upload && ReadyForLiveUpload(binding, *local, mode, stats))
        UploadAndRestoreCloudForLaunch(connection, binding, *local, ZERO_SHA256, nullptr, *path,
                                       mode, stats);
      else if (!local)
        ++stats->current;
      return;
    }

    const Revision& cloud = *binding.current_revision;
    if (local && local->sha256 == cloud.sha256)
    {
      if (state_it == m_state.end() || !state_it->second.ancestor_invalidated)
        UpdateState(binding.id, cloud.sha256, cloud.id);
      m_pending_uploads.erase(binding.id);
      ++stats->current;
      return;
    }

    // A savestate rewinds emulated memory independently of the host file. Until a normal upload or
    // download establishes a new base, any differing local bytes have unknown ancestry and must be
    // retained as a conflict rather than replacing the selected cloud revision.
    if (state_it != m_state.end() && state_it->second.ancestor_invalidated)
    {
      if (!local)
      {
        if (can_download && downloads_open)
          Download(connection, binding, cloud, *path, stats);
        else
          ++stats->deferred;
      }
      else if (can_upload && ReadyForLiveUpload(binding, *local, mode, stats))
      {
        UploadAndRestoreCloudForLaunch(connection, binding, *local, ZERO_SHA256, &cloud, *path,
                                       mode, stats);
      }
      else if (!can_upload && can_download && downloads_open)
      {
        Download(connection, binding, cloud, *path, stats);
      }
      else
      {
        ++stats->deferred;
      }
      return;
    }

    // Once the user resolves a conflict in EmuBank, an unchanged retained local copy can be safely
    // replaced by the selected revision. If the file changed again after the conflict was
    // retained, fall through to normal three-way comparison so that new progress is backed up.
    if (state_it != m_state.end() && state_it->second.conflict_pending)
    {
      const bool local_is_retained = local && IsSha256(state_it->second.conflict_sha256) &&
                                     local->sha256 == state_it->second.conflict_sha256;
      if (!local || local_is_retained)
      {
        if (can_download && downloads_open)
          Download(connection, binding, cloud, *path, stats);
        else
          ++stats->deferred;
        return;
      }
    }

    // A download-only binding explicitly makes EmuBank authoritative. Restore it whenever the
    // local copy differs, including on this installation's first sync when no common ancestor has
    // been recorded yet.
    if (!can_upload && can_download)
    {
      if (downloads_open)
        Download(connection, binding, cloud, *path, stats);
      else
        ++stats->deferred;
      return;
    }

    if (state_it == m_state.end() || !IsSha256(state_it->second.base_sha256))
    {
      if (!local)
      {
        if (can_download && downloads_open)
          Download(connection, binding, cloud, *path, stats);
        else
          ++stats->deferred;
        return;
      }

      // With no locally recorded common ancestor, never silently pick a winner. The server marks
      // a download when it begins streaming, so its last-synced marker alone cannot prove that
      // this installation received the complete file. Sending the zero hash makes EmuBank retain
      // the local file as a conflict revision without replacing the cloud copy.
      if (can_upload && ReadyForLiveUpload(binding, *local, mode, stats))
      {
        UploadAndRestoreCloudForLaunch(connection, binding, *local, ZERO_SHA256, &cloud, *path,
                                       mode, stats);
      }
      else if (!can_upload)
        ++stats->conflicts;
      return;
    }

    const std::string& base = state_it->second.base_sha256;
    if (!local)
    {
      if (can_download && downloads_open)
        Download(connection, binding, cloud, *path, stats);
      else
        ++stats->deferred;
      return;
    }

    const bool local_changed = local->sha256 != base;
    const bool cloud_changed = cloud.sha256 != base;
    if (local_changed && !cloud_changed)
    {
      if (can_upload && ReadyForLiveUpload(binding, *local, mode, stats))
      {
        UploadAndRestoreCloudForLaunch(connection, binding, *local, base, &cloud, *path, mode,
                                       stats);
      }
      else if (!can_upload)
        ++stats->deferred;
      return;
    }
    if (!local_changed && cloud_changed)
    {
      if (can_download && downloads_open)
        Download(connection, binding, cloud, *path, stats);
      else
        ++stats->deferred;
      return;
    }
    if (local_changed && cloud_changed)
    {
      if (can_upload && ReadyForLiveUpload(binding, *local, mode, stats))
      {
        UploadAndRestoreCloudForLaunch(connection, binding, *local, base, &cloud, *path, mode,
                                       stats);
      }
      else if (!can_upload)
        ++stats->conflicts;
      return;
    }

    ++stats->current;
  }

  // Caller holds m_sync_mutex. Returns whether a newly loaded savestate was consumed.
  bool PersistPendingAncestorInvalidation()
  {
    const bool invalidate_savestate_ancestors =
        m_invalidate_ancestors_requested.exchange(false, std::memory_order_acq_rel);
    if (invalidate_savestate_ancestors)
    {
      for (auto& entry : m_state)
      {
        LocalState& state = entry.second;
        if (!state.ancestor_invalidated)
        {
          state.ancestor_invalidated = true;
          m_state_dirty = true;
        }
      }
      m_pending_uploads.clear();

      // Persist before any network access. Offline shutdown after a savestate-derived host flush
      // must not allow the old common ancestor to be trusted on the next launch.
      if (m_state_dirty)
        SaveState();
    }
    return invalidate_savestate_ancestors;
  }

  void SyncOnce(SyncMode mode)
  {
    std::lock_guard operation_lock(m_sync_mutex);
    m_sync_deadline = std::chrono::steady_clock::now() + SYNC_OPERATION_TIMEOUT;
    const bool invalidate_savestate_ancestors = PersistPendingAncestorInvalidation();

    const auto connection = GetConnection();
    if (!connection)
      return;

    const auto manifest = FetchManifest(*connection);
    if (!manifest)
      return;

    if (m_state_server_url != connection->base_url || m_state_device_id != connection->device_id)
    {
      m_state.clear();
      m_pending_uploads.clear();
      m_state_server_url = connection->base_url;
      m_state_device_id = connection->device_id;
      m_state_dirty = true;
    }

    if (invalidate_savestate_ancestors)
    {
      // A load can race the very first manifest pass, before a binding has local state. Carry the
      // invalidation through that pass so an as-yet-unflushed host file cannot establish a trusted
      // ancestor for memory-card bytes restored from the savestate.
      for (const Binding& binding : manifest->bindings)
      {
        LocalState& state = m_state[binding.id];
        if (!state.ancestor_invalidated)
        {
          state.ancestor_invalidated = true;
          m_state_dirty = true;
        }
      }
      if (m_state_dirty)
        SaveState();
    }

    SyncStats stats;
    std::set<std::string, std::less<>> manifest_binding_ids;
    for (const Binding& binding : manifest->bindings)
      manifest_binding_ids.insert(binding.id);

    for (size_t index = 0; index < manifest->bindings.size(); ++index)
    {
      if (std::chrono::steady_clock::now() >= m_sync_deadline)
      {
        stats.deferred += static_cast<int>(manifest->bindings.size() - index);
        break;
      }
      const Binding& binding = manifest->bindings[index];
      ProcessBinding(*connection, binding, mode, &stats);
    }

    const size_t erased = std::erase_if(m_state, [&manifest_binding_ids](const auto& entry) {
      return !manifest_binding_ids.contains(entry.first);
    });
    m_state_dirty = m_state_dirty || erased != 0;
    if (m_state_dirty)
      SaveState();

    if (stats.bindings == 0)
    {
      SetStatus("EmuBank connected; no Dolphin save paths are bound to this device.");
    }
    else
    {
      std::string status = fmt::format("EmuBank connected: {} current, {} uploaded, {} downloaded",
                                       stats.current, stats.uploaded, stats.downloaded);
      if (stats.deferred)
        status += fmt::format(", {} deferred", stats.deferred);
      if (stats.conflicts)
        status += fmt::format(", {} conflict(s)", stats.conflicts);
      if (stats.errors)
        status += fmt::format(", {} error(s)", stats.errors);
      status += '.';
      SetStatus(std::move(status));
    }
  }

  void LoadState()
  {
    picojson::value root;
    std::string error;
    if (!JsonFromFile(StatePath(), &root, &error) || !root.is<picojson::object>())
      return;

    const auto& root_object = root.get<picojson::object>();
    m_state_server_url = ObjectString(root_object, "server_url").value_or("");
    m_state_device_id = ObjectString(root_object, "device_id").value_or("");
    const auto bindings = ObjectValue(root_object, "bindings");
    if (!bindings)
      return;

    for (const auto& [id, value] : *bindings)
    {
      if (!IsSafeIdentifier(id) || !value.is<picojson::object>())
        continue;
      const auto& object = value.get<picojson::object>();
      LocalState state{ObjectString(object, "base_sha256").value_or(""),
                       ObjectString(object, "revision_id").value_or(""),
                       ReadBoolFromJson(object, "conflict_pending").value_or(false),
                       ObjectString(object, "conflict_sha256").value_or(""),
                       ReadBoolFromJson(object, "ancestor_invalidated").value_or(false)};
      Common::ToLower(&state.base_sha256);
      Common::ToLower(&state.conflict_sha256);
      if (!IsSha256(state.conflict_sha256))
        state.conflict_sha256.clear();
      if ((IsSha256(state.base_sha256) && IsSafeIdentifier(state.revision_id)) ||
          state.conflict_pending || state.ancestor_invalidated)
        m_state.emplace(id, std::move(state));
    }
  }

  void UpdateState(const std::string& binding_id, const std::string& sha256,
                   const std::string& revision_id)
  {
    auto [it, inserted] =
        m_state.try_emplace(binding_id, LocalState{sha256, revision_id, false, {}, false});
    if (inserted)
    {
      m_state_dirty = true;
      return;
    }

    if (it->second.base_sha256 != sha256 || it->second.revision_id != revision_id ||
        it->second.conflict_pending || it->second.ancestor_invalidated)
    {
      it->second = {sha256, revision_id, false, {}, false};
      m_state_dirty = true;
    }
  }

  void SaveState()
  {
    picojson::object bindings;
    for (const auto& [id, state] : m_state)
    {
      bindings.emplace(id, picojson::value{picojson::object{
                               {"base_sha256", picojson::value{state.base_sha256}},
                               {"revision_id", picojson::value{state.revision_id}},
                               {"conflict_pending", picojson::value{state.conflict_pending}},
                               {"conflict_sha256", picojson::value{state.conflict_sha256}},
                               {"ancestor_invalidated",
                                picojson::value{state.ancestor_invalidated}}}});
    }

    const std::string json =
        picojson::value{picojson::object{{"version", picojson::value{1.0}},
                                         {"server_url", picojson::value{m_state_server_url}},
                                         {"device_id", picojson::value{m_state_device_id}},
                                         {"bindings", picojson::value{std::move(bindings)}}}}
            .serialize(true);
    const std::span<const u8> bytes{reinterpret_cast<const u8*>(json.data()), json.size()};
    if (WriteAtomically(StatePath(), bytes))
      m_state_dirty = false;
    else
      ERROR_LOG_FMT(CORE, "EmuBank: failed to save local sync state");
  }

  std::string StatePath() const
  {
    return File::GetUserPath(D_CONFIG_IDX) + "EmuBankSyncState.json";
  }

  void SetStatus(std::string status)
  {
    std::lock_guard lock(m_status_mutex);
    m_status = std::move(status);
  }

  mutable std::mutex m_status_mutex;
  std::string m_status = "EmuBank cloud sync is starting…";

  std::mutex m_wake_mutex;
  std::condition_variable m_wake_condition;
  std::condition_variable m_sync_finished_condition;
  std::atomic<bool> m_shutdown = false;
  bool m_sync_requested = false;
  bool m_stop = false;
  std::optional<std::chrono::steady_clock::time_point> m_save_sync_deadline;
  u64 m_requested_generation = 0;
  u64 m_completed_generation = 0;
  std::thread m_worker;

  std::mutex m_sync_mutex;
  std::chrono::steady_clock::time_point m_sync_deadline{};
  std::atomic<bool> m_emulation_active = false;
  // Set on the CPU thread after a successful savestate load and consumed by the sync worker. The
  // callback never waits for an in-flight network operation.
  std::atomic<bool> m_invalidate_ancestors_requested = false;
  std::string m_state_server_url;
  std::string m_state_device_id;
  std::map<std::string, LocalState, std::less<>> m_state;
  std::map<std::string, PendingUpload, std::less<>> m_pending_uploads;
  bool m_state_dirty = false;

  mutable std::mutex m_pairing_mutex;
  std::mutex m_pairing_operation_mutex;
  std::condition_variable m_pairing_condition;
  std::thread m_pairing_thread;
  PairingState m_pairing_state = PairingState::Idle;
  bool m_pairing_cancel = false;
  std::string m_pairing_approval_url;
  std::string m_pairing_base_url;
  std::string m_pairing_token;
  std::string m_paired_device_name;

  Common::EventHook m_state_changed_hook;
  Common::EventHook m_save_data_changed_hook;
  Common::EventHook m_savestate_loaded_hook;
  Config::ConfigChangedCallbackID m_config_changed_callback;
};

std::mutex s_manager_mutex;
std::shared_ptr<Manager> s_manager;
}  // namespace

void Init()
{
  std::lock_guard lock(s_manager_mutex);
  if (!s_manager)
    s_manager = std::make_shared<Manager>();
}

void Shutdown()
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = std::move(s_manager);
  }
  if (manager)
    manager->Shutdown();
}

PairingStartResult BeginPairing(std::string server_url, std::string device_name,
                                std::string platform)
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  if (!manager)
    return {.approval_url = {}, .error = "EmuBank cloud sync is not running."};
  return manager->BeginPairing(std::move(server_url), std::move(device_name), std::move(platform));
}

PairingState GetPairingState()
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  return manager ? manager->GetPairingState() : PairingState::Idle;
}

std::string GetPairingApprovalUrl()
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  return manager ? manager->GetPairingApprovalUrl() : std::string{};
}

bool FinalizePairing()
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  return manager && manager->FinalizePairing();
}

void RequestSync()
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  if (manager)
    manager->Request();
}

bool SyncAndWait(std::chrono::milliseconds timeout)
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  return manager && manager->SyncAndWait(timeout);
}

std::string GetStatus()
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  return manager ? manager->Status() : "EmuBank cloud sync is not running.";
}
}  // namespace UICommon::EmuBank
