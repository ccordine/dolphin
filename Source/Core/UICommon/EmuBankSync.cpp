// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "UICommon/EmuBankSync.h"
#include "UICommon/EmuBankSyncPolicy.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <future>
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

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <stdio.h>
#endif
#if defined(__linux__)
#include <sys/syscall.h>
#endif
#endif

#include <fmt/format.h>
#include <mbedtls/sha256.h>
#include <picojson.h>

#include "Common/CommonTypes.h"
#include "Common/Config/Config.h"
#include "Common/DirectIOFile.h"
#include "Common/FileUtil.h"
#include "Common/HookableEvent.h"
#include "Common/HttpRequest.h"
#include "Common/IOFile.h"
#include "Common/JsonUtil.h"
#include "Common/Logging/Log.h"
#include "Common/Random.h"
#include "Common/ScopeGuard.h"
#include "Common/StringUtil.h"
#include "Common/Thread.h"

#include "Core/Config/MainSettings.h"
#include "Core/ConfigManager.h"
#include "Core/Core.h"
#include "Core/HW/EXI/EXI.h"
#include "Core/HW/EXI/EXI_Device.h"
#include "Core/HW/GCMemcard/GCMemcard.h"
#include "Core/HW/GCMemcard/GCMemcardDirectory.h"
#include "Core/Host.h"
#include "Core/System.h"

#include "DiscIO/Enums.h"

#include "VideoCommon/OnScreenDisplay.h"

namespace UICommon::EmuBank
{
namespace
{
using namespace std::chrono_literals;

constexpr std::chrono::seconds HTTP_TIMEOUT = 8s;
constexpr std::chrono::seconds HTTP_TOTAL_TIMEOUT = 60s;
constexpr std::chrono::seconds SYNC_OPERATION_TIMEOUT = 30s;
constexpr std::chrono::seconds BEFORE_LAUNCH_OPERATION_TIMEOUT = 12s;
constexpr std::chrono::seconds SAVE_EVENT_QUIET_PERIOD = 2s;
constexpr u64 MAX_PAIRING_RESPONSE_SIZE = 256 * 1024;
constexpr u64 MAX_BINDING_RESOLUTION_RESPONSE_SIZE = 256 * 1024;
constexpr u64 MAX_MANIFEST_RESPONSE_SIZE = 2 * 1024 * 1024;
constexpr size_t MAX_MANIFEST_BINDINGS = 512;
constexpr size_t MAX_RECOVERY_BLOCKS = 512;
constexpr size_t MAX_DURABLE_STATE_BINDINGS = 4096;
constexpr size_t MAX_PROCESS_LOCK_DIRECTORIES = MAX_RECOVERY_BLOCKS + 3;
constexpr size_t MAX_PROCESS_LOCK_STABILIZATION_ATTEMPTS = 4;
constexpr u64 MAX_DURABLE_STATE_FILE_SIZE = 32 * 1024 * 1024;
constexpr u64 MAX_RECOVERY_JOURNAL_FILE_SIZE = 8 * 1024 * 1024;
constexpr u64 MAX_SAVE_SIZE = 64 * 1024 * 1024;
constexpr size_t CONFIRMATION_READ_CHUNK_SIZE = 1024 * 1024;
constexpr std::string_view ZERO_SHA256 =
    "0000000000000000000000000000000000000000000000000000000000000000";

enum class SyncMode
{
  Idle,
  Live,
  BeforeLaunch,
};

enum class RequestPriority
{
  Automatic,
  Immediate,
  UserInitiated,
};

enum class UploadResult
{
  Success,
  Conflict,
  Failed,
};

enum class OsdTone
{
  Progress,
  Success,
  Warning,
  Error,
};

struct ConfirmationBudget
{
  std::chrono::steady_clock::time_point deadline;
  const std::atomic<bool>* cancellation = nullptr;
  const std::atomic<bool>* shutdown = nullptr;

  bool Expired() const
  {
    return std::chrono::steady_clock::now() >= deadline ||
           (cancellation && cancellation->load(std::memory_order_acquire)) ||
           (shutdown && shutdown->load(std::memory_order_acquire));
  }
};

void DisplaySyncMessage(std::string message, u32 milliseconds, OsdTone tone = OsdTone::Progress)
{
  if (!Core::IsRunningOrStarting(Core::System::GetInstance()))
    return;

  // Keep the same conservative character policy as Core::DisplayMessage while using one typed
  // slot so successive EmuBank phases replace each other instead of flooding the OSD.
  std::erase_if(message, [](char character) { return !Common::IsPrintableCharacter(character); });
  if (message.empty())
    return;

  u32 color = OSD::Color::CYAN;
  switch (tone)
  {
  case OsdTone::Success:
    color = OSD::Color::GREEN;
    break;
  case OsdTone::Warning:
    color = OSD::Color::YELLOW;
    break;
  case OsdTone::Error:
    color = OSD::Color::RED;
    break;
  case OsdTone::Progress:
    break;
  }
  OSD::AddTypedMessage(OSD::MessageType::EmuBank, std::move(message), milliseconds, color);
}

struct Revision
{
  std::string id;
  std::string sha256;
  u64 size = 0;
  std::optional<std::chrono::system_clock::time_point> created_at;
};

struct Binding
{
  std::string id;
  std::string relative_path;
  std::string game_id;
  std::string sync_mode;
  std::string status;
  std::optional<Revision> current_revision;
  std::optional<Revision> conflict_revision;
  bool explicit_download_pending = false;
};

struct Manifest
{
  std::vector<Binding> bindings;
  std::optional<std::chrono::system_clock::time_point> server_time;
  std::chrono::steady_clock::time_point received_at;
};

struct Connection
{
  std::string base_url;
  std::string device_id;
  std::string token;
  std::string gamecube_save_root;
  std::string wii_save_root;

  bool operator==(const Connection&) const = default;
};

struct SyncConfig
{
  bool enabled = false;
  std::string server_url;
  std::string device_token;
  bool allow_insecure = false;
  bool live_sync = false;
  int interval = 0;
  std::string wii_save_root_setting;

  bool operator==(const SyncConfig&) const = default;
};

struct LocalState
{
  std::string base_sha256;
  std::string revision_id;
  bool conflict_pending = false;
  std::string conflict_sha256;
  bool ancestor_invalidated = false;
  std::string explicit_revision_id;
  std::string explicit_sha256;
  bool explicit_local_present = false;
  std::string explicit_local_sha256;
  std::string rejected_explicit_revision_id;
  std::string rejected_explicit_sha256;
  std::string relative_path;
  std::string canonical_path;
};

struct RecoveryBlock
{
  std::string relative_path;
  std::string canonical_path;
  std::string required_sha256;
  bool cloud_reinstall_allowed = false;

  bool operator==(const RecoveryBlock&) const = default;
};

struct FileSnapshot
{
  std::vector<u8> contents;
  std::string sha256;
  std::filesystem::file_time_type modified_at;
};

struct GameIdentity
{
  std::string platform;
  std::string game_id;
  std::string title;
  std::string region;
  u16 revision = 0;

  bool operator==(const GameIdentity&) const = default;
};

struct LocalSaveCandidate
{
  std::string absolute_path;
  std::string relative_path;
  FileSnapshot snapshot;
};

struct SaveLocation
{
  std::string absolute_directory;
  std::string relative_directory;
  std::vector<LocalSaveCandidate> files;
};

enum class ResolveDisposition
{
  Resolved,
  ActionRequired,
  RetryableFailure,
};

struct ResolveResult
{
  ResolveDisposition disposition = ResolveDisposition::RetryableFailure;
  std::optional<Binding> binding;
  std::string status;
  std::string match_method;
  double match_confidence = 0.0;
  std::string next_action;
  std::string message;
  std::optional<std::string> reported_local_sha256;
};

struct PendingUpload
{
  std::string sha256;
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
  bool retry_needed = false;
  bool abort_reconciliation = false;
};

struct ActiveGameResolution
{
  struct DownloadAuthorization
  {
    std::string relative_path;
    Revision revision;
    std::optional<std::string> expected_local_sha256;
    bool explicit_selection = false;
  };

  struct PendingCompletion
  {
    u64 token = 0;
    std::set<std::string, std::less<>> binding_ids;
  };

  std::string notice;
  std::set<std::string, std::less<>> priority_paths;
  std::string priority_game_id;
  std::map<std::string, DownloadAuthorization, std::less<>> download_authorizations;
  std::set<std::string, std::less<>> blocked_binding_ids;
  std::set<std::string, std::less<>> resolved_binding_ids;
  std::vector<PendingCompletion> pending_completions;
  bool retry_needed = false;
};

struct PendingGameResolution
{
  u64 token = 0;
  GameIdentity game;
};

const ActiveGameResolution::DownloadAuthorization*
FindMatchingDownloadAuthorization(const ActiveGameResolution& resolution, const Binding& binding,
                                  const std::optional<FileSnapshot>& local)
{
  const auto authorization = resolution.download_authorizations.find(binding.id);
  if (authorization == resolution.download_authorizations.end() || !binding.current_revision)
    return nullptr;

  const Revision& expected = authorization->second.revision;
  const Revision& actual = *binding.current_revision;
  const bool local_matches =
      Policy::ResolverLocalMatches(authorization->second.expected_local_sha256.has_value(),
                                   authorization->second.expected_local_sha256.value_or(""),
                                   local.has_value(), local ? local->sha256 : "");
  if (!local_matches || authorization->second.relative_path != binding.relative_path ||
      expected.id != actual.id || expected.sha256 != actual.sha256 || expected.size != actual.size)
  {
    return nullptr;
  }
  return &authorization->second;
}

std::string Trim(std::string_view value)
{
  return std::string{StripWhitespace(value)};
}

std::optional<std::chrono::system_clock::time_point> ParseIso8601(std::string_view value)
{
  const auto digits = [value](size_t offset, size_t count) -> std::optional<int> {
    if (offset + count > value.size())
      return std::nullopt;

    int result = 0;
    for (size_t index = offset; index < offset + count; ++index)
    {
      if (value[index] < '0' || value[index] > '9')
        return std::nullopt;
      result = result * 10 + value[index] - '0';
    }
    return result;
  };

  if (value.size() < 20 || value[4] != '-' || value[7] != '-' || value[10] != 'T' ||
      value[13] != ':' || value[16] != ':')
  {
    return std::nullopt;
  }

  const auto year_value = digits(0, 4);
  const auto month_value = digits(5, 2);
  const auto day_value = digits(8, 2);
  const auto hour_value = digits(11, 2);
  const auto minute_value = digits(14, 2);
  const auto second_value = digits(17, 2);
  if (!year_value || !month_value || !day_value || !hour_value || !minute_value || !second_value ||
      *hour_value > 23 || *minute_value > 59 || *second_value > 59)
  {
    return std::nullopt;
  }

  const std::chrono::year_month_day date{std::chrono::year{*year_value},
                                         std::chrono::month{static_cast<unsigned>(*month_value)},
                                         std::chrono::day{static_cast<unsigned>(*day_value)}};
  if (!date.ok())
    return std::nullopt;

  size_t position = 19;
  std::chrono::nanoseconds fraction{};
  if (position < value.size() && value[position] == '.')
  {
    ++position;
    const size_t fraction_start = position;
    s64 nanoseconds = 0;
    size_t fraction_digits = 0;
    while (position < value.size() && value[position] >= '0' && value[position] <= '9')
    {
      if (fraction_digits < 9)
        nanoseconds = nanoseconds * 10 + value[position] - '0';
      ++fraction_digits;
      ++position;
    }
    if (position == fraction_start || fraction_digits > 9)
      return std::nullopt;
    for (; fraction_digits < 9; ++fraction_digits)
      nanoseconds *= 10;
    fraction = std::chrono::nanoseconds{nanoseconds};
  }

  std::chrono::minutes utc_offset{};
  if (position < value.size() && value[position] == 'Z')
  {
    ++position;
  }
  else if (position + 6 == value.size() && (value[position] == '+' || value[position] == '-') &&
           value[position + 3] == ':')
  {
    const auto offset_hours = digits(position + 1, 2);
    const auto offset_minutes = digits(position + 4, 2);
    if (!offset_hours || !offset_minutes || *offset_hours > 23 || *offset_minutes > 59)
      return std::nullopt;
    utc_offset = std::chrono::hours{*offset_hours} + std::chrono::minutes{*offset_minutes};
    if (value[position] == '-')
      utc_offset = -utc_offset;
    position += 6;
  }
  else
  {
    return std::nullopt;
  }
  if (position != value.size())
    return std::nullopt;

  const auto local_time = std::chrono::sys_days{date} + std::chrono::hours{*hour_value} +
                          std::chrono::minutes{*minute_value} +
                          std::chrono::seconds{*second_value} + fraction;
  return std::chrono::time_point_cast<std::chrono::system_clock::duration>(local_time - utc_offset);
}

SyncConfig ReadSyncConfig()
{
  return {
      .enabled = Config::Get(Config::MAIN_EMUBANK_ENABLED),
      .server_url = Config::Get(Config::MAIN_EMUBANK_SERVER_URL),
      .device_token = Config::Get(Config::MAIN_EMUBANK_DEVICE_TOKEN),
      .allow_insecure = Config::Get(Config::MAIN_EMUBANK_ALLOW_INSECURE),
      .live_sync = Config::Get(Config::MAIN_EMUBANK_LIVE_SYNC),
      .interval = Config::Get(Config::MAIN_EMUBANK_SYNC_INTERVAL),
      .wii_save_root_setting = Config::Get(Config::MAIN_FS_PATH),
  };
}

std::string BindingDisplayName(std::string_view relative_path)
{
  const size_t separator = relative_path.find_last_of("/\\");
  return std::string{relative_path.substr(separator == std::string_view::npos ? 0 : separator + 1)};
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

bool IsDolphinGameId(std::string_view value)
{
  return value.size() == 6 && std::ranges::all_of(value, [](const char c) {
           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
         });
}

bool IsSafeGameIdentifier(std::string_view value)
{
  return value.size() >= 4 && value.size() <= 40 && std::ranges::all_of(value, [](const char c) {
           return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
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
    std::optional<std::chrono::steady_clock::time_point> operation_deadline = std::nullopt,
    const std::atomic<bool>* cancel_when_set = nullptr,
    const std::atomic<bool>* second_cancel_when_set = nullptr)
{
  const auto deadline =
      operation_deadline.value_or(std::chrono::steady_clock::now() + HTTP_TOTAL_TIMEOUT);
  return [deadline, max_download, max_upload, cancel_when_set, second_cancel_when_set](
             s64 download_total, s64 download_now, s64 upload_total, s64 upload_now) {
    const auto within_limit = [](s64 value, u64 limit) {
      return value < 0 || static_cast<u64>(value) <= limit;
    };
    return (!cancel_when_set || !cancel_when_set->load(std::memory_order_acquire)) &&
           (!second_cancel_when_set || !second_cancel_when_set->load(std::memory_order_acquire)) &&
           std::chrono::steady_clock::now() <= deadline &&
           within_limit(download_total, max_download) && within_limit(download_now, max_download) &&
           within_limit(upload_total, max_upload) && within_limit(upload_now, max_upload);
  };
}

std::chrono::milliseconds HttpTimeoutUntil(std::chrono::steady_clock::time_point deadline)
{
  const auto remaining = std::max(1ms, std::chrono::duration_cast<std::chrono::milliseconds>(
                                           deadline - std::chrono::steady_clock::now()));
  return std::min(std::chrono::duration_cast<std::chrono::milliseconds>(HTTP_TIMEOUT), remaining);
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

std::string CalculateSha256(std::string_view value)
{
  return CalculateSha256(
      std::span<const u8>{reinterpret_cast<const u8*>(value.data()), value.size()});
}

std::string MakeBoundedSiblingPath(std::string_view path, std::string_view prefix,
                                   std::string_view token, bool bind_to_path)
{
  const std::filesystem::path native_path = StringToPath(path);
  std::string filename{prefix};
  if (bind_to_path)
    filename += CalculateSha256(path) + "-";
  filename += token;
  return PathToString(native_path.parent_path() / StringToPath(filename));
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

std::optional<double> ObjectNumber(const picojson::object& object, std::string_view key)
{
  const auto it = object.find(std::string{key});
  if (it == object.end() || !it->second.is<double>())
    return std::nullopt;
  return it->second.get<double>();
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
  if (const auto created_at = ObjectString(object, "created_at"))
    revision.created_at = ParseIso8601(*created_at);
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

std::optional<Binding> ParseBinding(const picojson::value& value)
{
  if (!value.is<picojson::object>())
    return std::nullopt;

  const auto& object = value.get<picojson::object>();
  if (ObjectString(object, "driver").value_or("") != "dolphin")
    return std::nullopt;

  Binding binding;
  binding.id = ObjectString(object, "id").value_or("");
  binding.relative_path = ObjectString(object, "relative_path").value_or("");
  binding.game_id = ObjectString(object, "game_id").value_or("");
  binding.sync_mode = ObjectString(object, "sync_mode").value_or("two_way");
  binding.status = ObjectString(object, "status").value_or("");

  const auto revision_it = object.find("current_revision");
  if (revision_it != object.end() && !revision_it->second.is<picojson::null>())
  {
    binding.current_revision = ParseRevision(revision_it->second);
    if (!binding.current_revision)
      return std::nullopt;
  }

  // The resolver uses this authenticated binding metadata to distinguish a deliberate web
  // revision selection from its ordinary known-hash download heuristic. Require the pending
  // record to identify the exact current revision and hash before it can override local recency.
  const picojson::object* const metadata = ObjectValue(object, "metadata");
  const picojson::object* const reconciliation =
      metadata ? ObjectValue(*metadata, "reconciliation") : nullptr;
  const picojson::object* const pending =
      reconciliation ? ObjectValue(*reconciliation, "pending") : nullptr;
  if (pending && binding.current_revision)
  {
    std::string pending_sha256 = ObjectString(*pending, "sha256").value_or("");
    Common::ToLower(&pending_sha256);
    binding.explicit_download_pending = Policy::ExplicitDownloadMatches(
        ObjectString(*pending, "action").value_or(""),
        ObjectString(*pending, "revision_id").value_or(""), pending_sha256,
        binding.current_revision->id, binding.current_revision->sha256);
  }

  const auto conflict_revision_it = object.find("conflict_revision");
  if (conflict_revision_it != object.end() && !conflict_revision_it->second.is<picojson::null>())
  {
    binding.conflict_revision = ParseRevision(conflict_revision_it->second);
    if (!binding.conflict_revision)
      return std::nullopt;
  }

  if (!IsSafeIdentifier(binding.id) || binding.relative_path.empty() ||
      (!binding.game_id.empty() && !IsSafeGameIdentifier(binding.game_id)))
  {
    return std::nullopt;
  }
  return binding;
}

std::optional<std::string> ResolveSavePath(const std::string& relative_path,
                                           std::string_view gamecube_root,
                                           std::string_view wii_root);

std::string CanonicalPathKey(std::string path)
{
  return path;
}

std::string CanonicalAliasComparisonPath(std::string_view input)
{
  std::string path{input};
#if defined(_WIN32)
  std::ranges::replace(path, '\\', '/');
  if (path.size() >= 8 && Policy::AsciiCaseInsensitiveEquals(path.substr(0, 8), "//?/UNC/"))
  {
    path = "//" + path.substr(8);
  }
  else if (path.size() >= 7 && path.starts_with("//?/") &&
           ((path[4] >= 'A' && path[4] <= 'Z') || (path[4] >= 'a' && path[4] <= 'z')) &&
           path[5] == ':' && path[6] == '/')
  {
    path.erase(0, 4);
  }
#endif
  return path;
}

bool IsSafeCanonicalPathForSync(std::string_view input)
{
  if (input.empty() || input.size() > 4096 || !Policy::IsWellFormedUtf8(input) ||
      std::ranges::any_of(input, [](const char value) {
        const auto byte = static_cast<unsigned char>(value);
        return byte < 0x20 || byte == 0x7f;
      }))
  {
    return false;
  }

#if defined(_WIN32)
  const std::string path = CanonicalAliasComparisonPath(input);
  size_t offset = 0;
  if (path.size() >= 3 &&
      ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) &&
      path[1] == ':' && path[2] == '/')
  {
    offset = 3;
  }
  else if (path.starts_with("//"))
  {
    offset = 2;
  }
  else
  {
    return false;
  }

  size_t component_count = 0;
  while (offset <= path.size())
  {
    const size_t separator = path.find('/', offset);
    const size_t end = separator == std::string::npos ? path.size() : separator;
    const std::string_view component{path.data() + offset, end - offset};
    if (!Policy::IsPortablePathComponent(component))
      return false;
    ++component_count;
    if (separator == std::string::npos)
      break;
    offset = separator + 1;
  }
  // UNC paths need both a server and share before the ordinary path components. A drive path has
  // no such minimum, but every save candidate itself contributes at least one component.
  if (path.starts_with("//") && component_count < 3)
    return false;
#endif
  return true;
}

struct FileIdentity
{
  u64 volume = 0;
#if defined(_WIN32)
  // Treat the filesystem's full identifier as opaque bytes. Its only required operations are
  // equality and a stable total order shared by cooperating processes.
  std::wstring namespace_id;
  std::array<u8, 16> file{};
#else
  u64 file = 0;
#endif

  bool operator==(const FileIdentity&) const = default;
};

bool FileIdentitiesMayAlias(const FileIdentity& left, const FileIdentity& right)
{
#if defined(_WIN32)
  // A path-specific namespace discriminator prevents colliding SMB objects or cloned volumes from
  // being merged for lock ownership. Equal filesystem-issued IDs still prove that two save paths
  // may be hard links, however, so endpoint validation must conservatively reject that pair even
  // when their exact lock namespaces differ.
  return left.volume == right.volume && left.file == right.file;
#else
  return left == right;
#endif
}

enum class FileIdentityLookupResult
{
  Exists,
  Missing,
  Failed,
};

#if defined(_WIN32)
std::optional<std::wstring> FinalPathForHandle(HANDLE handle, DWORD volume_name_flag)
{
  constexpr DWORD MAX_FINAL_PATH_LENGTH = 32768;
  const DWORD required =
      GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | volume_name_flag);
  if (required == 0 || required > MAX_FINAL_PATH_LENGTH)
    return std::nullopt;

  std::vector<wchar_t> path(required);
  const DWORD written = GetFinalPathNameByHandleW(handle, path.data(), required,
                                                  FILE_NAME_NORMALIZED | volume_name_flag);
  if (written == 0 || written >= required)
    return std::nullopt;
  return std::wstring{path.data(), written};
}

std::optional<std::wstring> NamespaceForHandle(HANDLE handle)
{
  // A mounted volume GUID is assigned by Mount Manager and can refer to only one volume, so it
  // distinguishes simultaneously mounted filesystem clones whose on-disk volume/file IDs match.
  // Keep only the volume prefix so hard links on that volume retain equal identities.
  if (const auto guid_path = FinalPathForHandle(handle, VOLUME_NAME_GUID))
  {
    constexpr std::wstring_view prefix = L"\\\\?\\Volume{";
    const size_t volume_end = guid_path->find(L"}\\", prefix.size());
    if (guid_path->starts_with(prefix) && volume_end != std::wstring::npos)
      return L"G:" + guid_path->substr(0, volume_end + 2);
  }

  // Network shares have no volume GUID path. Their normalized final path is deliberately
  // path-specific: an SMB share can multiplex filesystems whose reported IDs collide. Genuine
  // aliases normally resolve to the same final path; any driver which cannot prove that fails
  // closed instead of merging distinct roots.
  if (auto final_path = FinalPathForHandle(handle, VOLUME_NAME_DOS);
      final_path && final_path->starts_with(L"\\\\?\\UNC\\"))
  {
    return L"P:" + std::move(*final_path);
  }
  return std::nullopt;
}

std::optional<FileIdentity> IdentityForHandle(HANDLE handle)
{
  FILE_ID_INFO information{};
  if (GetFileInformationByHandleEx(handle, FileIdInfo, &information, sizeof(information)) == FALSE)
    return std::nullopt;
  const std::span<const u8> file_id{information.FileId.Identifier};
  if (std::ranges::all_of(file_id, [](u8 byte) { return byte == 0; }) ||
      std::ranges::all_of(file_id, [](u8 byte) { return byte == 0xff; }))
  {
    return std::nullopt;
  }
  std::optional<std::wstring> namespace_id = NamespaceForHandle(handle);
  if (!namespace_id)
    return std::nullopt;
  FileIdentity identity{.volume = information.VolumeSerialNumber};
  identity.namespace_id = std::move(*namespace_id);
  static_assert(sizeof(identity.file) == sizeof(information.FileId.Identifier));
  std::memcpy(identity.file.data(), information.FileId.Identifier, sizeof(identity.file));
  return identity;
}

std::optional<std::string> ReadSha256FromLockedHandle(HANDLE handle,
                                                      const ConfirmationBudget* budget = nullptr)
{
  BY_HANDLE_FILE_INFORMATION information{};
  if (GetFileInformationByHandle(handle, &information) == FALSE ||
      (information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) !=
          0)
  {
    return std::nullopt;
  }
  const u64 size = (static_cast<u64>(information.nFileSizeHigh) << 32) | information.nFileSizeLow;
  if (size == 0 || size > MAX_SAVE_SIZE)
    return std::nullopt;

  LARGE_INTEGER beginning{};
  if (SetFilePointerEx(handle, beginning, nullptr, FILE_BEGIN) == FALSE)
    return std::nullopt;
  std::vector<u8> contents(static_cast<size_t>(size));
  size_t offset = 0;
  while (offset < contents.size())
  {
    if (budget && budget->Expired())
      return std::nullopt;
    const DWORD requested = static_cast<DWORD>(std::min<size_t>(
        contents.size() - offset,
        std::min<size_t>(CONFIRMATION_READ_CHUNK_SIZE, std::numeric_limits<DWORD>::max())));
    DWORD received = 0;
    if (ReadFile(handle, contents.data() + offset, requested, &received, nullptr) == FALSE ||
        received != requested)
    {
      return std::nullopt;
    }
    offset += received;
  }

  BY_HANDLE_FILE_INFORMATION information_after{};
  if (GetFileInformationByHandle(handle, &information_after) == FALSE ||
      information_after.nFileSizeHigh != information.nFileSizeHigh ||
      information_after.nFileSizeLow != information.nFileSizeLow)
  {
    return std::nullopt;
  }
  return CalculateSha256(contents);
}
#else
struct FileMutationStamp
{
  FileIdentity identity;
  u64 size = 0;
  s64 modification_seconds = 0;
  s64 modification_nanoseconds = 0;
  s64 change_seconds = 0;
  s64 change_nanoseconds = 0;

  bool operator==(const FileMutationStamp&) const = default;
};

FileIdentityLookupResult LookupFileMutationStamp(const std::filesystem::path& path,
                                                 FileMutationStamp* stamp)
{
  struct stat information{};
  // Confirmation is about the canonical directory entry itself, not a body reached through a
  // leaf symlink. Following that link could clear a recovery quarantine while Core would later
  // open an alias which ordinary save-path validation correctly rejects.
  if (::lstat(path.c_str(), &information) != 0)
  {
    return errno == ENOENT ? FileIdentityLookupResult::Missing : FileIdentityLookupResult::Failed;
  }
  if (!S_ISREG(information.st_mode) || information.st_size < 0)
    return FileIdentityLookupResult::Failed;

  stamp->identity =
      FileIdentity{static_cast<u64>(information.st_dev), static_cast<u64>(information.st_ino)};
  stamp->size = static_cast<u64>(information.st_size);
#if defined(__APPLE__)
  stamp->modification_seconds = static_cast<s64>(information.st_mtimespec.tv_sec);
  stamp->modification_nanoseconds = static_cast<s64>(information.st_mtimespec.tv_nsec);
  stamp->change_seconds = static_cast<s64>(information.st_ctimespec.tv_sec);
  stamp->change_nanoseconds = static_cast<s64>(information.st_ctimespec.tv_nsec);
#else
  stamp->modification_seconds = static_cast<s64>(information.st_mtim.tv_sec);
  stamp->modification_nanoseconds = static_cast<s64>(information.st_mtim.tv_nsec);
  stamp->change_seconds = static_cast<s64>(information.st_ctim.tv_sec);
  stamp->change_nanoseconds = static_cast<s64>(information.st_ctim.tv_nsec);
#endif
  return FileIdentityLookupResult::Exists;
}
#endif

FileIdentityLookupResult LookupFileIdentity(const std::filesystem::path& path,
                                            FileIdentity* identity)
{
#if defined(_WIN32)
  const HANDLE handle = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                                    OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
  if (handle == INVALID_HANDLE_VALUE)
  {
    const DWORD error = GetLastError();
    if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
      return FileIdentityLookupResult::Failed;

    // A dangling reparse point is not an ordinary absent component: two spellings may converge
    // once its target returns. Refuse to use lexical distinction as ownership proof in that case.
    const HANDLE reparse_handle = CreateFileW(
        path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (reparse_handle != INVALID_HANDLE_VALUE)
    {
      CloseHandle(reparse_handle);
      return FileIdentityLookupResult::Failed;
    }
    const DWORD reparse_error = GetLastError();
    return reparse_error == ERROR_FILE_NOT_FOUND || reparse_error == ERROR_PATH_NOT_FOUND ?
               FileIdentityLookupResult::Missing :
               FileIdentityLookupResult::Failed;
  }
  const std::optional<FileIdentity> found_identity = IdentityForHandle(handle);
  CloseHandle(handle);
  if (!found_identity)
    return FileIdentityLookupResult::Failed;
  *identity = *found_identity;
#else
  struct stat information{};
  if (::stat(path.c_str(), &information) != 0)
  {
    if (errno != ENOENT)
      return FileIdentityLookupResult::Failed;
    struct stat link_information{};
    if (lstat(path.c_str(), &link_information) == 0)
      return FileIdentityLookupResult::Failed;
    return errno == ENOENT ? FileIdentityLookupResult::Missing : FileIdentityLookupResult::Failed;
  }
  identity->volume = static_cast<u64>(information.st_dev);
  identity->file = static_cast<u64>(information.st_ino);
#endif
  return FileIdentityLookupResult::Exists;
}

struct CanonicalPathAliasInfo
{
  std::filesystem::path comparison_path;
  std::optional<FileIdentity> nearest_existing_identity;
  std::vector<std::string> unresolved_suffix;
  bool safe = false;
  bool lookup_succeeded = false;
};

CanonicalPathAliasInfo InspectCanonicalPathForAliases(
    std::string_view input,
    std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt)
{
  namespace fs = std::filesystem;
  CanonicalPathAliasInfo result;
  if (!IsSafeCanonicalPathForSync(input))
    return result;

  result.comparison_path = StringToPath(CanonicalAliasComparisonPath(input)).lexically_normal();
  if (!result.comparison_path.is_absolute())
    return result;

  fs::path inspected = result.comparison_path;
  std::vector<std::string> reversed_suffix;
  while (true)
  {
    if (deadline && std::chrono::steady_clock::now() >= *deadline)
    {
      result.safe = true;
      return result;
    }
    FileIdentity identity;
    switch (LookupFileIdentity(inspected, &identity))
    {
    case FileIdentityLookupResult::Exists:
      std::ranges::reverse(reversed_suffix);
      result.nearest_existing_identity = identity;
      result.unresolved_suffix = std::move(reversed_suffix);
      result.safe = true;
      result.lookup_succeeded = true;
      return result;
    case FileIdentityLookupResult::Failed:
      result.safe = true;
      return result;
    case FileIdentityLookupResult::Missing:
      break;
    }

    const fs::path parent = inspected.parent_path();
    if (parent.empty() || parent == inspected)
    {
      result.safe = true;
      return result;
    }
    reversed_suffix.emplace_back(PathToString(inspected.filename()));
    inspected = parent;
  }
}

bool PathComponentSequencesMayAlias(std::span<const std::string> left,
                                    std::span<const std::string> right)
{
  return Policy::PathTargetComponentSequencesMayConflict(left, right);
}

bool LexicalCanonicalPathsMayAlias(const std::filesystem::path& left,
                                   const std::filesystem::path& right)
{
  auto left_component = left.begin();
  auto right_component = right.begin();
  while (left_component != left.end() && right_component != right.end())
  {
    if (Policy::PathComponentsDefinitelyDistinct(PathToString(*left_component),
                                                 PathToString(*right_component)))
    {
      return false;
    }
    ++left_component;
    ++right_component;
  }

  // Every target is a file, so an alias-compatible equality or prefix relationship is unsafe. A
  // prefix pair could never coexist as two regular files: one target would have to be the other's
  // parent directory.
  return true;
}

bool CanonicalPathAliasInfosMayAlias(const CanonicalPathAliasInfo& left,
                                     const CanonicalPathAliasInfo& right)
{
  if (!left.safe || !right.safe || !left.lookup_succeeded || !right.lookup_succeeded)
    return true;

  // Existing hard links share the target identity. For missing leaves, filesystem-equivalent
  // ancestors plus an alias-compatible unresolved suffix identify the same future directory
  // entry even when bind mounts, mapped drives, or reparse views have different spellings.
  if (left.nearest_existing_identity && right.nearest_existing_identity &&
      FileIdentitiesMayAlias(*left.nearest_existing_identity, *right.nearest_existing_identity) &&
      PathComponentSequencesMayAlias(left.unresolved_suffix, right.unresolved_suffix))
  {
    return true;
  }

  return LexicalCanonicalPathsMayAlias(left.comparison_path, right.comparison_path);
}

bool CanonicalPathAliasInfoMatchesSnapshot(const CanonicalPathAliasInfo& expected,
                                           const CanonicalPathAliasInfo& current)
{
  return expected.safe && current.safe && expected.lookup_succeeded && current.lookup_succeeded &&
         expected.comparison_path == current.comparison_path &&
         expected.nearest_existing_identity == current.nearest_existing_identity &&
         expected.unresolved_suffix == current.unresolved_suffix;
}

std::string RecoveryPathKey(std::string path)
{
#if defined(_WIN32)
  path = CanonicalAliasComparisonPath(path);
  Common::ToLower(&path);
#endif
  return path;
}

std::string RelativePathKey(std::string path)
{
  std::ranges::replace(path, '\\', '/');
#if defined(_WIN32)
  Common::ToLower(&path);
#endif
  return path;
}

std::optional<Manifest> ParseManifest(std::span<const u8> body,
                                      std::chrono::steady_clock::time_point deadline,
                                      std::string_view gamecube_root, std::string_view wii_root)
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
  if (bindings_it == data->end() || !bindings_it->second.is<picojson::array>() ||
      bindings_it->second.get<picojson::array>().size() > MAX_MANIFEST_BINDINGS)
    return std::nullopt;

  Manifest manifest;
  if (const auto server_time = ObjectString(*data, "server_time"))
    manifest.server_time = ParseIso8601(*server_time);
  manifest.received_at = std::chrono::steady_clock::now();
  std::set<std::string, std::less<>> binding_ids;
  std::vector<CanonicalPathAliasInfo> canonical_paths;
  canonical_paths.reserve(bindings_it->second.get<picojson::array>().size());
  for (const picojson::value& value : bindings_it->second.get<picojson::array>())
  {
    if (std::chrono::steady_clock::now() >= deadline)
      return std::nullopt;
    if (!value.is<picojson::object>())
      return std::nullopt;
    const std::string driver = ObjectString(value.get<picojson::object>(), "driver").value_or("");
    if (driver != "dolphin")
      continue;
    auto binding = ParseBinding(value);
    if (!binding)
      return std::nullopt;
    auto canonical_path = ResolveSavePath(binding->relative_path, gamecube_root, wii_root);
    if (!canonical_path || !binding_ids.insert(binding->id).second)
      return std::nullopt;
    CanonicalPathAliasInfo alias_info = InspectCanonicalPathForAliases(*canonical_path, deadline);
    if (!alias_info.safe || !alias_info.lookup_succeeded)
      return std::nullopt;
    // One manifest action owns one local file. Treat Unicode components as potentially aliased
    // unless some aligned all-ASCII component proves the paths distinct. This is conservative on
    // case-sensitive hosts but remains safe on case-folding or normalization-aware volumes.
    if (std::ranges::any_of(canonical_paths, [&](const CanonicalPathAliasInfo& existing_path) {
          return CanonicalPathAliasInfosMayAlias(existing_path, alias_info);
        }))
    {
      return std::nullopt;
    }
    canonical_paths.emplace_back(std::move(alias_info));
    manifest.bindings.emplace_back(std::move(*binding));
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

std::optional<std::vector<std::string>> ParseSavePathComponents(std::string relative_path)
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
    if (!Policy::IsPortablePathComponent(component))
      return std::nullopt;
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

  return components;
}

bool IsSafeRecoveryCanonicalPath(const std::string& relative_path,
                                 const std::string& canonical_path)
{
  namespace fs = std::filesystem;
  const auto components = ParseSavePathComponents(relative_path);
  if (!components || !IsSafeCanonicalPathForSync(canonical_path))
    return false;

  const fs::path native_path = StringToPath(canonical_path);
  if (!native_path.is_absolute() || native_path.lexically_normal() != native_path)
    return false;

  auto path_component = native_path.end();
  for (size_t index = components->size(); index-- > 1;)
  {
    if (path_component == native_path.begin())
      return false;
    --path_component;
#if defined(_WIN32)
    if (!Common::CaseInsensitiveEquals(PathToString(*path_component), (*components)[index]))
#else
    if (*path_component != StringToPath((*components)[index]))
#endif
      return false;
  }
  return true;
}

std::optional<std::string> ResolveSavePath(const std::string& relative_path,
                                           std::string_view gamecube_root,
                                           std::string_view wii_root)
{
  const auto parsed_components = ParseSavePathComponents(relative_path);
  if (!parsed_components)
    return std::nullopt;
  const std::vector<std::string>& components = *parsed_components;

  namespace fs = std::filesystem;
  std::error_code error;
  const bool is_gamecube = Common::CaseInsensitiveEquals(components.front(), "GC");
  const std::string_view configured_root = is_gamecube ? gamecube_root : wii_root;
  const fs::path root = fs::weakly_canonical(StringToPath(configured_root), error);
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

  std::string result = PathToString(candidate);
  if (!IsSafeCanonicalPathForSync(result))
    return std::nullopt;
  return result;
}

struct RelativeSavePathAliasInfo
{
  std::vector<std::string> components;
  std::optional<CanonicalPathAliasInfo> root;
  std::optional<CanonicalPathAliasInfo> canonical;
  bool safe = false;
};

RelativeSavePathAliasInfo InspectRelativeSavePathForAliases(
    std::string_view path, std::string_view gamecube_root, std::string_view wii_root,
    std::optional<std::chrono::steady_clock::time_point> deadline = std::nullopt)
{
  RelativeSavePathAliasInfo result;
  auto components = ParseSavePathComponents(std::string{path});
  if (!components)
    return result;
  result.components = std::move(*components);
  result.safe = true;
  namespace fs = std::filesystem;
  std::error_code root_error;
  const bool is_gamecube = Common::CaseInsensitiveEquals(result.components.front(), "GC");
  const fs::path configured_root =
      fs::weakly_canonical(StringToPath(is_gamecube ? gamecube_root : wii_root), root_error);
  if (!root_error)
    result.root = InspectCanonicalPathForAliases(PathToString(configured_root), deadline);
  if (const auto resolved = ResolveSavePath(std::string{path}, gamecube_root, wii_root))
    result.canonical = InspectCanonicalPathForAliases(*resolved, deadline);
  return result;
}

bool RelativeSavePathAliasInfosMayAlias(const RelativeSavePathAliasInfo& left,
                                        const RelativeSavePathAliasInfo& right)
{
  if (!left.safe || !right.safe)
    return true;
  if (PathComponentSequencesMayAlias(left.components, right.components))
    return true;
  if (!left.root || !right.root || !left.canonical || !right.canonical)
  {
    // GC/ and Wii/ are logical root selectors, not necessarily distinct filesystem components.
    // If either configured root cannot be resolved, no component-only comparison can prove that a
    // savestate path selector is independent of a binding.
    return true;
  }
  if (CanonicalPathAliasInfosMayAlias(*left.root, *right.root) &&
      PathComponentSequencesMayAlias(std::span{left.components}.subspan(1),
                                     std::span{right.components}.subspan(1)))
  {
    return true;
  }
  return CanonicalPathAliasInfosMayAlias(*left.canonical, *right.canonical);
}

std::optional<FileSnapshot> ReadSaveFile(const std::string& path,
                                         const ConfirmationBudget* budget = nullptr)
{
  if (budget && budget->Expired())
    return std::nullopt;
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
  size_t offset = 0;
  while (offset < snapshot.contents.size())
  {
    if (budget && budget->Expired())
      return std::nullopt;
    const size_t requested =
        std::min(CONFIRMATION_READ_CHUNK_SIZE, snapshot.contents.size() - offset);
    if (!file.ReadBytes(snapshot.contents.data() + offset, requested))
      return std::nullopt;
    offset += requested;
  }
  file.Close();

  if (budget && budget->Expired())
    return std::nullopt;

  const u64 size_after = fs::file_size(native_path, error);
  if (error || size_before != size_after ||
      fs::last_write_time(native_path, error) != modified_before || error)
  {
    return std::nullopt;
  }

  snapshot.sha256 = CalculateSha256(snapshot.contents);
  if (!IsSha256(snapshot.sha256))
    return std::nullopt;
  snapshot.modified_at = modified_before;
  return snapshot;
}

Policy::SaveRecency CompareSaveRecency(const FileSnapshot& local, const Revision& cloud,
                                       const Manifest& manifest)
{
  if (!cloud.created_at || !manifest.server_time)
    return Policy::SaveRecency::Unknown;

  const auto local_age = std::filesystem::file_time_type::clock::now() - local.modified_at;
  const auto cloud_age_at_manifest = *manifest.server_time - *cloud.created_at;
  const auto elapsed_since_manifest = std::chrono::steady_clock::now() - manifest.received_at;
  if (local_age < decltype(local_age)::zero() ||
      cloud_age_at_manifest < decltype(cloud_age_at_manifest)::zero())
  {
    return Policy::SaveRecency::Unknown;
  }

  return Policy::CompareAges(std::chrono::duration_cast<std::chrono::seconds>(local_age),
                             std::chrono::duration_cast<std::chrono::seconds>(
                                 cloud_age_at_manifest + elapsed_since_manifest));
}

std::optional<std::string> MakeGameCubeRelativePath(const std::string& absolute_path,
                                                    std::string_view gamecube_root)
{
  namespace fs = std::filesystem;
  std::error_code error;
  const fs::path root = fs::weakly_canonical(StringToPath(gamecube_root), error);
  if (error)
    return std::nullopt;

  const fs::path candidate = fs::weakly_canonical(StringToPath(absolute_path), error);
  if (error)
    return std::nullopt;

  const fs::path relative = candidate.lexically_relative(root);
  if (relative.empty() || relative.is_absolute())
    return std::nullopt;
  for (const fs::path& component : relative)
  {
    const std::string name = PathToString(component);
    if (!Policy::IsPortablePathComponent(name))
      return std::nullopt;
  }

  std::string result = "GC/" + PathToString(relative);
  std::ranges::replace(result, '\\', '/');
  if (result.size() > 255)
    return std::nullopt;
  return result;
}

bool ValidateGciContents(std::span<const u8> contents, std::string_view game_id = {})
{
  if (contents.size() < Memcard::DENTRY_SIZE)
    return false;

  Memcard::DEntry entry;
  std::memcpy(&entry, contents.data(), sizeof(entry));
  const u16 block_count = entry.m_block_count;
  if (block_count == 0 || block_count > 2043 ||
      contents.size() !=
          Memcard::DENTRY_SIZE + static_cast<size_t>(block_count) * Memcard::BLOCK_SIZE)
  {
    return false;
  }

  if (game_id.empty())
    return true;
  if (!IsDolphinGameId(game_id))
    return false;

  return std::equal(entry.m_gamecode.begin(), entry.m_gamecode.end(), game_id.begin()) &&
         std::equal(entry.m_makercode.begin(), entry.m_makercode.end(), game_id.begin() + 4);
}

std::optional<GameIdentity> CaptureGameCubeIdentity()
{
  const Core::System& system = Core::System::GetInstance();
  if (system.IsWii() || system.IsTriforce())
    return std::nullopt;

  const SConfig& config = SConfig::GetInstance();
  GameIdentity game;
  game.platform = "gamecube";
  game.game_id = config.GetGameID();
  Common::ToUpper(&game.game_id);
  if (!IsDolphinGameId(game.game_id))
    return std::nullopt;

  game.title = Trim(config.GetTitleName());
  if (game.title.empty())
    game.title = Trim(config.GetTitleDescription());
  if (game.title.empty())
    game.title = game.game_id;
  game.region = Config::GetDirectoryForRegion(Config::ToGameCubeRegion(config.m_region));
  game.revision = config.GetRevision();
  return game;
}

std::set<std::string, std::less<>> CaptureConfiguredLaunchSavePaths(std::string_view gamecube_root)
{
  std::set<std::string, std::less<>> paths;
  const Core::System& system = Core::System::GetInstance();
  if (system.IsWii())
    return paths;

  const SConfig& config = SConfig::GetInstance();
  for (const ExpansionInterface::Slot slot : ExpansionInterface::MEMCARD_SLOTS)
  {
    if (Config::Get(Config::GetInfoForEXIDevice(slot)) !=
        ExpansionInterface::EXIDeviceType::MemoryCard)
    {
      continue;
    }
    const auto relative_path =
        MakeGameCubeRelativePath(Config::GetMemcardPath(slot, config.m_region), gamecube_root);
    if (relative_path)
      paths.insert(RelativePathKey(*relative_path));
  }
  return paths;
}

std::optional<std::vector<SaveLocation>>
DiscoverGameCubeGciSaves(const GameIdentity& game, std::chrono::steady_clock::time_point deadline,
                         std::string_view gamecube_root, std::string_view wii_root)
{
  namespace fs = std::filesystem;
  std::vector<SaveLocation> locations;
  std::set<std::string, std::less<>> seen_directories;
  const SConfig& config = SConfig::GetInstance();

  for (const ExpansionInterface::Slot slot : ExpansionInterface::MEMCARD_SLOTS)
  {
    if (std::chrono::steady_clock::now() >= deadline)
      return std::nullopt;

    if (Config::Get(Config::GetInfoForEXIDevice(slot)) !=
        ExpansionInterface::EXIDeviceType::MemoryCardFolder)
    {
      continue;
    }

    SaveLocation location;
    location.absolute_directory = Config::GetGCIFolderPath(slot, config.m_region);
    const auto relative_directory =
        MakeGameCubeRelativePath(location.absolute_directory, gamecube_root);
    if (!relative_directory || !seen_directories.insert(*relative_directory).second)
      continue;
    location.relative_directory = *relative_directory;

    std::error_code error;
    const fs::path directory =
        fs::weakly_canonical(StringToPath(location.absolute_directory), error);
    if (error)
      continue;

    const std::vector<std::string> filenames =
        GCMemcardDirectory::GetFileNamesForGameID(location.absolute_directory, game.game_id);
    if (std::chrono::steady_clock::now() >= deadline)
      return std::nullopt;

    for (const std::string& filename : filenames)
    {
      if (std::chrono::steady_clock::now() >= deadline)
        return std::nullopt;

      const fs::path candidate = fs::weakly_canonical(StringToPath(filename), error);
      if (error || candidate.parent_path() != directory)
        continue;

      const auto relative_path = MakeGameCubeRelativePath(filename, gamecube_root);
      auto snapshot = ReadSaveFile(filename);
      if (std::chrono::steady_clock::now() >= deadline)
        return std::nullopt;
      if (!relative_path || !snapshot || !ValidateGciContents(snapshot->contents, game.game_id) ||
          !ResolveSavePath(*relative_path, gamecube_root, wii_root))
      {
        continue;
      }

      location.files.emplace_back(
          LocalSaveCandidate{filename, *relative_path, std::move(*snapshot)});
    }
    locations.emplace_back(std::move(location));
  }

  return locations;
}

enum class NamespaceCommitResult
{
  Failed,
  Durable,
  CommittedNotDurable,
};

#if !defined(_WIN32)
bool SyncDirectory(const std::filesystem::path& native_path)
{
  const std::string path = PathToString(native_path.empty() ? StringToPath(".") : native_path);
  int flags = O_RDONLY;
#ifdef O_DIRECTORY
  flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  const int directory = open(path.c_str(), flags);
  if (directory < 0)
  {
    WARN_LOG_FMT(CORE, "EmuBank: could not open '{}' for directory sync: {}", path,
                 std::strerror(errno));
    return false;
  }
  const bool synced = fsync(directory) == 0;
  if (!synced)
  {
    WARN_LOG_FMT(CORE, "EmuBank: could not sync directory '{}': {}", path, std::strerror(errno));
  }
  if (close(directory) != 0)
  {
    WARN_LOG_FMT(CORE, "EmuBank: could not close synced directory '{}': {}", path,
                 std::strerror(errno));
    return false;
  }
  return synced;
}
#endif

bool PrepareParentDirectory(const std::string& path)
{
#if defined(_WIN32)
  // The write-through publication that follows makes the completed path durable. Newly created
  // but otherwise empty topology is not itself safety-critical if publication later fails.
  return File::CreateFullPath(path);
#else
  namespace fs = std::filesystem;
  const fs::path parent = StringToPath(path).parent_path();
  std::vector<fs::path> directories_to_sync;
  fs::path current = parent;
  while (!current.empty())
  {
    std::error_code error;
    const fs::file_status status = fs::status(current, error);
    if (status.type() == fs::file_type::not_found)
    {
      directories_to_sync.emplace_back(current);
    }
    else if (error || !fs::is_directory(status))
    {
      return false;
    }
    else
    {
      // If children are about to be created, their first existing ancestor must also be flushed so
      // its new child entry is durable. An already-existing target parent needs no pre-write flush.
      if (!directories_to_sync.empty())
        directories_to_sync.emplace_back(current);
      break;
    }
    if (current == current.parent_path())
      break;
    current = current.parent_path();
  }

  if (!File::CreateFullPath(path))
    return false;
  return std::ranges::all_of(directories_to_sync, SyncDirectory);
#endif
}

bool FlushFileData(const std::string& path)
{
  File::DirectIOFile file(path, File::AccessMode::ReadAndWrite, File::OpenMode::Existing);
  if (!file.IsOpen())
    return false;
  const bool flushed = file.Flush();
  const bool closed = file.Close();
  if (!flushed || !closed)
    return false;
#if defined(__APPLE__)
  // Darwin's fsync does not necessarily issue a drive-cache flush. F_FULLFSYNC is the strongest
  // public primitive for making the file body survive sudden power loss; directory fsync below
  // still supplies the separate namespace-ordering guarantee.
  int flags = O_RDWR;
#ifdef O_CLOEXEC
  flags |= O_CLOEXEC;
#endif
  const int descriptor = open(path.c_str(), flags);
  if (descriptor < 0)
    return false;
  const bool fully_flushed = fcntl(descriptor, F_FULLFSYNC) == 0;
  const bool descriptor_closed = close(descriptor) == 0;
  return fully_flushed && descriptor_closed;
#else
  return true;
#endif
}

#if !defined(_WIN32)
bool SyncRenamedDirectories(const std::string& source, const std::string& destination)
{
  const std::filesystem::path source_parent = StringToPath(source).parent_path();
  const std::filesystem::path destination_parent = StringToPath(destination).parent_path();
  if (source_parent == destination_parent)
    return SyncDirectory(source_parent);

  // Make the new name durable before making removal of the old name durable. If the destination
  // flush fails, leave the source namespace unflushed: flushing only the source could make the
  // removal of the sole old name durable while the new name remains vulnerable to power loss.
  if (!SyncDirectory(destination_parent))
    return false;
  return SyncDirectory(source_parent);
}
#endif

bool SyncParentDirectory(const std::string& path, std::string_view durability_token = {},
                         const ConfirmationBudget* budget = nullptr)
{
#if defined(_WIN32)
  if (!IsSha256(durability_token) || (budget && budget->Expired()))
    return false;

  // Windows has no public directory-fsync API. Republish this exact inode through two
  // MOVEFILE_WRITE_THROUGH operations so the canonical directory entry itself, including a
  // manual recovery made outside Dolphin, is part of a completed write-through rename. The
  // hash-bound sibling is derivable from the caller's write-ahead recovery record, so a failed
  // return move never strands the only body at an unknown random name.
  const std::string durability_path =
      MakeBoundedSiblingPath(path, ".emubank-durability-", durability_token, true);
  const bool canonical_is_file = File::IsFile(path);
  const bool durability_is_file = File::IsFile(durability_path);
  if (canonical_is_file == durability_is_file || (!canonical_is_file && File::Exists(path)) ||
      (!durability_is_file && File::Exists(durability_path)))
  {
    return false;
  }

  const std::string& initial_path = canonical_is_file ? path : durability_path;
  const DWORD initial_attributes = GetFileAttributesW(UTF8ToWString(initial_path).c_str());
  if (initial_attributes == INVALID_FILE_ATTRIBUTES ||
      (initial_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
  {
    return false;
  }
  const HANDLE handle =
      CreateFileW(UTF8ToWString(initial_path).c_str(), GENERIC_READ | GENERIC_WRITE,
                  FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                  FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN |
                      FILE_FLAG_WRITE_THROUGH,
                  nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    return false;
  Common::ScopeGuard close_handle{[handle] { CloseHandle(handle); }};

  // Denying FILE_SHARE_WRITE makes this a real no-writer interval, including writers which opened
  // the inode before confirmation began. Read and flush through that same handle so Windows'
  // deferred last-write timestamp updates cannot make an unflushed rewrite look stable.
  const std::optional<FileIdentity> locked_identity = IdentityForHandle(handle);
  const std::optional<std::string> locked_sha256 = ReadSha256FromLockedHandle(handle, budget);
  if (!locked_identity || !locked_sha256 || *locked_sha256 != durability_token ||
      FlushFileBuffers(handle) == FALSE)
  {
    return false;
  }

  FileIdentity named_identity;
  if (LookupFileIdentity(StringToPath(initial_path), &named_identity) !=
          FileIdentityLookupResult::Exists ||
      named_identity != *locked_identity)
  {
    return false;
  }

  if (budget && budget->Expired())
    return false;
  if (durability_is_file)
  {
    if (File::Exists(path) || MoveFileExW(UTF8ToWString(durability_path).c_str(),
                                          UTF8ToWString(path).c_str(), MOVEFILE_WRITE_THROUGH) == 0)
    {
      return false;
    }
  }
  else
  {
    if (File::Exists(durability_path) ||
        MoveFileExW(UTF8ToWString(path).c_str(), UTF8ToWString(durability_path).c_str(),
                    MOVEFILE_WRITE_THROUGH) == 0)
    {
      return false;
    }
    if (MoveFileExW(UTF8ToWString(durability_path).c_str(), UTF8ToWString(path).c_str(),
                    MOVEFILE_WRITE_THROUGH) == 0)
    {
      ERROR_LOG_FMT(CORE,
                    "EmuBank: retained the hash-bound recovery body at '{}' after a failed "
                    "durable namespace restore",
                    durability_path);
      return false;
    }
  }

  const std::optional<std::string> restored_sha256 = ReadSha256FromLockedHandle(handle, budget);
  if (!restored_sha256 || *restored_sha256 != durability_token || FlushFileBuffers(handle) == FALSE)
  {
    return false;
  }

  // The handle must allow FILE_SHARE_DELETE for the write-through moves. Re-resolve the visible
  // name after the final data flush so an external rename/replacement cannot make us confirm the
  // old locked inode while a different body owns the canonical pathname.
  const HANDLE final_name_handle = CreateFileW(
      UTF8ToWString(path).c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (final_name_handle == INVALID_HANDLE_VALUE)
    return false;
  Common::ScopeGuard close_final_name_handle{
      [final_name_handle] { CloseHandle(final_name_handle); }};
  BY_HANDLE_FILE_INFORMATION final_information{};
  const std::optional<FileIdentity> final_identity = IdentityForHandle(final_name_handle);
  return GetFileInformationByHandle(final_name_handle, &final_information) != FALSE &&
         (final_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
         final_identity && *final_identity == *locked_identity;
#else
  (void)durability_token;
  if (budget && budget->Expired())
    return false;
  return SyncDirectory(StringToPath(path).parent_path());
#endif
}

bool DurablyConfirmFileAtPath(const std::string& path, std::string_view expected_sha256,
                              const ConfirmationBudget* budget = nullptr)
{
  if (!IsSha256(expected_sha256) || (budget && budget->Expired()))
    return false;

#if defined(_WIN32)
  // SyncParentDirectory both restores an interrupted hash-bound sibling and holds a native handle
  // which excludes same-inode writers across the exact-body read, data flush, write-through
  // namespace publication, and final exact-body check.
  return SyncParentDirectory(path, expected_sha256, budget);
#else
  const auto confirm_stable_body = [&](const std::optional<FileMutationStamp>& required_stamp)
      -> std::optional<FileMutationStamp> {
    FileMutationStamp stamp_before;
    if (LookupFileMutationStamp(StringToPath(path), &stamp_before) !=
            FileIdentityLookupResult::Exists ||
        (required_stamp && stamp_before != *required_stamp))
    {
      return std::nullopt;
    }
    const auto file = ReadSaveFile(path, budget);
    FileMutationStamp stamp_after;
    if (!file || file->sha256 != expected_sha256 ||
        LookupFileMutationStamp(StringToPath(path), &stamp_after) !=
            FileIdentityLookupResult::Exists ||
        stamp_after != stamp_before)
    {
      return std::nullopt;
    }
    return stamp_after;
  };

  const std::optional<FileMutationStamp> stamp = confirm_stable_body(std::nullopt);
  if (!stamp || (budget && budget->Expired()) || !FlushFileData(path) ||
      !confirm_stable_body(stamp) || (budget && budget->Expired()) || !FlushFileData(path) ||
      !confirm_stable_body(stamp) || (budget && budget->Expired()) ||
      !SyncParentDirectory(path, {}, budget))
  {
    return false;
  }
  // The identity, size, modification time, and inode-change time must still match the hash sampled
  // before the final file flush. A same-inode writer which rewrites the expected bytes after that
  // flush therefore cannot make an unflushed body look durably confirmed.
  return confirm_stable_body(stamp).has_value();
#endif
}

bool DurablyConfirmExistingFileData(const std::string& path, std::string_view expected_sha256)
{
  if (!IsSha256(expected_sha256))
    return false;

#if defined(_WIN32)
  const HANDLE handle = CreateFileW(UTF8ToWString(path).c_str(), GENERIC_READ | GENERIC_WRITE,
                                    FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT |
                                        FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_WRITE_THROUGH,
                                    nullptr);
  if (handle == INVALID_HANDLE_VALUE)
    return false;
  Common::ScopeGuard close_handle{[handle] { CloseHandle(handle); }};
  const std::optional<FileIdentity> locked_identity = IdentityForHandle(handle);
  const std::optional<std::string> before_flush = ReadSha256FromLockedHandle(handle);
  if (!locked_identity || !before_flush || *before_flush != expected_sha256 ||
      FlushFileBuffers(handle) == FALSE)
  {
    return false;
  }
  const std::optional<std::string> after_flush = ReadSha256FromLockedHandle(handle);
  if (!after_flush || *after_flush != expected_sha256)
    return false;

  const HANDLE final_name_handle = CreateFileW(
      UTF8ToWString(path).c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (final_name_handle == INVALID_HANDLE_VALUE)
    return false;
  Common::ScopeGuard close_final_name_handle{
      [final_name_handle] { CloseHandle(final_name_handle); }};
  BY_HANDLE_FILE_INFORMATION final_information{};
  const std::optional<FileIdentity> final_identity = IdentityForHandle(final_name_handle);
  return GetFileInformationByHandle(final_name_handle, &final_information) != FALSE &&
         (final_information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
         final_identity && *final_identity == *locked_identity;
#else
  const auto stable_body = [&]() -> std::optional<FileMutationStamp> {
    FileMutationStamp before;
    if (LookupFileMutationStamp(StringToPath(path), &before) != FileIdentityLookupResult::Exists)
      return std::nullopt;
    const auto file = ReadSaveFile(path);
    FileMutationStamp after;
    if (!file || file->sha256 != expected_sha256 ||
        LookupFileMutationStamp(StringToPath(path), &after) != FileIdentityLookupResult::Exists ||
        after != before)
    {
      return std::nullopt;
    }
    return after;
  };
  const std::optional<FileMutationStamp> before_flush = stable_body();
  if (!before_flush || !FlushFileData(path))
    return false;
  const std::optional<FileMutationStamp> after_flush = stable_body();
  return after_flush && *after_flush == *before_flush;
#endif
}

std::optional<std::string> PrepareAtomicWrite(const std::string& path, std::span<const u8> contents)
{
  if (!PrepareParentDirectory(path))
    return std::nullopt;

  // The stock helper returns a deterministic .xxx name. Add a random suffix and create it
  // exclusively so two Dolphin processes can never delete, replace, or publish one another's
  // prepared body. Crash leftovers are intentionally not reused.
  const std::string temporary_path =
      MakeBoundedSiblingPath(path, ".emubank-write-", GenerateSecret(), false);
  File::DirectIOFile file(temporary_path, File::AccessMode::Write, File::OpenMode::Create);
  bool prepared = file.IsOpen() && file.Write(contents) && file.Flush() && file.Close();
#if defined(__APPLE__)
  // Prepare the exact inode with the same full-cache guarantee used for canonical recovery before
  // publishing it into the durable namespace transaction.
  prepared = prepared && FlushFileData(temporary_path);
#endif
  if (!prepared)
  {
    File::Delete(temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
    return std::nullopt;
  }
  return temporary_path;
}

bool CommitPreparedAtomicWrite(const std::string& temporary_path, const std::string& path)
{
#if defined(_WIN32)
  if (MoveFileExW(UTF8ToWString(temporary_path).c_str(), UTF8ToWString(path).c_str(),
                  MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0)
  {
    File::Delete(temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
    return false;
  }
  return FlushFileData(path);
#else
  // File::MoveWithOverwrite currently reports true even on failure. Rename through the checked
  // open-handle API so state/backup durability is never inferred from a failed namespace commit.
  File::DirectIOFile temporary_file(temporary_path, File::AccessMode::ReadAndWrite,
                                    File::OpenMode::Existing);
  if (!temporary_file.IsOpen() || !File::Rename(temporary_file, temporary_path, path))
  {
    File::Delete(temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
    return false;
  }
  return SyncRenamedDirectories(temporary_path, path);
#endif
}

// Atomically swap two existing directory entries when the host provides renameat2. Unlike an
// overwrite rename, an intervening writer's file is moved to temporary_path rather than destroyed.
struct AtomicExchangeResult
{
  NamespaceCommitResult commit = NamespaceCommitResult::Failed;
  std::string displaced_path;
};

NamespaceCommitResult PublishPreparedFileWithoutOverwrite(const std::string& source,
                                                          const std::string& destination);

AtomicExchangeResult ExchangeFilesAtomically(const std::string& temporary_path,
                                             const std::string& path,
                                             std::string_view displacement_token)
{
#if defined(_WIN32)
  // ReplaceFile atomically gives the actually displaced inode its own name, including in the face
  // of a concurrent writer. Some documented failure states may leave the canonical name absent,
  // so every non-failure result remains covered by the caller's write-ahead recovery record.
  const std::string backup_path = temporary_path + ".displaced-" + GenerateSecret();
  if (ReplaceFileW(UTF8ToWString(path).c_str(), UTF8ToWString(temporary_path).c_str(),
                   UTF8ToWString(backup_path).c_str(), 0, nullptr, nullptr) == 0)
  {
    if (File::IsFile(backup_path))
      return {NamespaceCommitResult::CommittedNotDurable, backup_path};
    return {NamespaceCommitResult::Failed, temporary_path};
  }

  if (!FlushFileData(path) || !FlushFileData(backup_path))
    return {NamespaceCommitResult::CommittedNotDurable, backup_path};

  // REPLACEFILE_WRITE_THROUGH is unsupported. Establish namespace durability explicitly by
  // moving the new canonical inode through the now-vacant prepared name and back, with each rename
  // write-through. A crash/failure in the brief absent-name interval leaves both bodies named and
  // the durable recovery veto armed.
  if (MoveFileExW(UTF8ToWString(path).c_str(), UTF8ToWString(temporary_path).c_str(),
                  MOVEFILE_WRITE_THROUGH) == 0)
  {
    return {NamespaceCommitResult::CommittedNotDurable, backup_path};
  }
  if (MoveFileExW(UTF8ToWString(temporary_path).c_str(), UTF8ToWString(path).c_str(),
                  MOVEFILE_WRITE_THROUGH) == 0)
  {
    return {NamespaceCommitResult::CommittedNotDurable, backup_path};
  }
  if (MoveFileExW(UTF8ToWString(backup_path).c_str(), UTF8ToWString(temporary_path).c_str(),
                  MOVEFILE_WRITE_THROUGH) == 0)
  {
    return {NamespaceCommitResult::CommittedNotDurable, backup_path};
  }
  if (!FlushFileData(path) || !FlushFileData(temporary_path))
    return {NamespaceCommitResult::CommittedNotDurable, temporary_path};
  return {NamespaceCommitResult::Durable, temporary_path};
#elif defined(__linux__) && defined(SYS_renameat2)
  constexpr unsigned int RENAME_EXCHANGE_FLAG = 2;
  if (syscall(SYS_renameat2, AT_FDCWD, temporary_path.c_str(), AT_FDCWD, path.c_str(),
              RENAME_EXCHANGE_FLAG) != 0)
  {
#if defined(ANDROID)
    // Android's supported external-storage FUSE implementations may reject RENAME_EXCHANGE. Core
    // is stopped, the install/process locks exclude other Dolphin writers, and the durable
    // recovery record already contains this hash-bound displaced name. Publish the replacement
    // with the no-overwrite helper so an unrelated file that appears in the brief gap is retained.
    if (!IsSha256(displacement_token) || !File::IsFile(temporary_path))
      return {NamespaceCommitResult::Failed, temporary_path};
    const std::string displaced_path =
        MakeBoundedSiblingPath(path, ".emubank-displaced-", displacement_token, true);
    if (File::Exists(displaced_path))
      return {NamespaceCommitResult::Failed, temporary_path};
    std::error_code move_error;
    std::filesystem::rename(StringToPath(path), StringToPath(displaced_path), move_error);
    if (move_error)
      return {NamespaceCommitResult::Failed, temporary_path};

    const NamespaceCommitResult publication =
        PublishPreparedFileWithoutOverwrite(temporary_path, path);
    if (publication == NamespaceCommitResult::Durable)
    {
      // NOREPLACE rename consumes the source; hard-link/exclusive-copy fallbacks do not. The
      // caller owns any residue because this source can be a concurrently written local inode
      // during exchange-back, not merely a disposable prepared cloud body.
      return {NamespaceCommitResult::Durable, displaced_path};
    }
    if (publication == NamespaceCommitResult::Failed && !File::Exists(path))
    {
      move_error.clear();
      std::filesystem::rename(StringToPath(displaced_path), StringToPath(path), move_error);
      if (!move_error && SyncRenamedDirectories(displaced_path, path))
        return {NamespaceCommitResult::Failed, temporary_path};
    }
    return {NamespaceCommitResult::CommittedNotDurable, displaced_path};
#else
    return {NamespaceCommitResult::Failed, temporary_path};
#endif
  }
  return {SyncRenamedDirectories(temporary_path, path) ? NamespaceCommitResult::Durable :
                                                         NamespaceCommitResult::CommittedNotDurable,
          temporary_path};
#elif defined(__APPLE__) && defined(RENAME_SWAP)
  if (renamex_np(temporary_path.c_str(), path.c_str(), RENAME_SWAP) != 0)
    return {NamespaceCommitResult::Failed, temporary_path};
  return {SyncRenamedDirectories(temporary_path, path) ? NamespaceCommitResult::Durable :
                                                         NamespaceCommitResult::CommittedNotDurable,
          temporary_path};
#else
  return {NamespaceCommitResult::Failed, temporary_path};
#endif
}

#if !defined(_WIN32)
NamespaceCommitResult CreateHardLinkWithoutOverwrite(const std::string& source,
                                                     const std::string& destination)
{
  std::error_code error;
  std::filesystem::create_hard_link(StringToPath(source), StringToPath(destination), error);
  if (error)
    return NamespaceCommitResult::Failed;
  return SyncParentDirectory(destination) ? NamespaceCommitResult::Durable :
                                            NamespaceCommitResult::CommittedNotDurable;
}
#endif

NamespaceCommitResult PublishPreparedFileWithoutOverwrite(const std::string& source,
                                                          const std::string& destination)
{
#if defined(_WIN32)
  return MoveFileExW(UTF8ToWString(source).c_str(), UTF8ToWString(destination).c_str(),
                     MOVEFILE_WRITE_THROUGH) != 0 ?
             NamespaceCommitResult::Durable :
             NamespaceCommitResult::Failed;
#else
#if defined(__linux__) && defined(SYS_renameat2)
  constexpr unsigned int RENAME_NOREPLACE_FLAG = 1;
  if (syscall(SYS_renameat2, AT_FDCWD, source.c_str(), AT_FDCWD, destination.c_str(),
              RENAME_NOREPLACE_FLAG) == 0)
  {
    return SyncRenamedDirectories(source, destination) ? NamespaceCommitResult::Durable :
                                                         NamespaceCommitResult::CommittedNotDurable;
  }
#elif defined(__APPLE__) && defined(RENAME_EXCL)
  if (renamex_np(source.c_str(), destination.c_str(), RENAME_EXCL) == 0)
  {
    return SyncRenamedDirectories(source, destination) ? NamespaceCommitResult::Durable :
                                                         NamespaceCommitResult::CommittedNotDurable;
  }
#endif
  // Some older kernels lack no-replace rename. A same-filesystem hard link provides equivalent
  // publication semantics where supported; current Android storage normally takes the renameat2
  // path above because it need not implement hard links.
  const NamespaceCommitResult hard_link_result =
      CreateHardLinkWithoutOverwrite(source, destination);
  if (hard_link_result != NamespaceCommitResult::Failed)
    return hard_link_result;
#if defined(ANDROID)
  // Android 7-era external-storage FUSE implements neither renameat2(NOREPLACE) nor hard links.
  // Exclusive creation still prevents overwriting a file that appeared after the absence check.
  // The prearmed recovery journal makes a crash-visible partial file fail closed and retryable
  // after it is removed/restored, while the launch gate keeps Core from observing it mid-copy.
  const auto prepared = ReadSaveFile(source);
  if (!prepared)
    return NamespaceCommitResult::Failed;
  File::DirectIOFile destination_file(destination, File::AccessMode::Write, File::OpenMode::Create);
  if (!destination_file.IsOpen())
    return NamespaceCommitResult::Failed;
  if (!destination_file.Write(prepared->contents) || !destination_file.Flush() ||
      !destination_file.Close())
  {
    return NamespaceCommitResult::CommittedNotDurable;
  }
  // O_EXCL protects creation only; another writer can open the visible inode while this copy is
  // in progress. Do not report a durable publication until repeated flush/hash/identity checks
  // establish a stable expected body at the canonical name.
  return DurablyConfirmFileAtPath(destination, prepared->sha256) ?
             NamespaceCommitResult::Durable :
             NamespaceCommitResult::CommittedNotDurable;
#else
  return NamespaceCommitResult::Failed;
#endif
#endif
}

NamespaceCommitResult RenameDurably(const std::string& source, const std::string& destination)
{
#if defined(_WIN32)
  return MoveFileExW(UTF8ToWString(source).c_str(), UTF8ToWString(destination).c_str(),
                     MOVEFILE_WRITE_THROUGH) != 0 ?
             NamespaceCommitResult::Durable :
             NamespaceCommitResult::Failed;
#else
  std::error_code error;
  std::filesystem::rename(StringToPath(source), StringToPath(destination), error);
  if (error)
    return NamespaceCommitResult::Failed;
  return SyncRenamedDirectories(source, destination) ? NamespaceCommitResult::Durable :
                                                       NamespaceCommitResult::CommittedNotDurable;
#endif
}

bool WriteAtomically(const std::string& path, std::span<const u8> contents)
{
  const auto temporary_path = PrepareAtomicWrite(path, contents);
  return temporary_path && CommitPreparedAtomicWrite(*temporary_path, path);
}

constexpr std::string_view SAVESTATE_INVALIDATION_PREFIX = "EmuBankSavestateInvalidation-";
constexpr std::string_view SAVESTATE_INVALIDATION_SUFFIX = ".pending";

std::optional<std::vector<std::string>> FindSavestateInvalidationMarkers()
{
  namespace fs = std::filesystem;
  std::vector<std::string> markers;
  std::error_code error;
  fs::directory_iterator iterator(StringToPath(File::GetUserPath(D_CONFIG_IDX)), error);
  if (error)
    return std::nullopt;
  const fs::directory_iterator end;
  while (iterator != end)
  {
    const fs::directory_entry& entry = *iterator;
    const std::string filename = PathToString(entry.path().filename());
    const bool is_regular_file = entry.is_regular_file(error);
    if (error)
      return std::nullopt;
    if (is_regular_file && filename.starts_with(SAVESTATE_INVALIDATION_PREFIX) &&
        filename.ends_with(SAVESTATE_INVALIDATION_SUFFIX))
    {
      const std::string_view token =
          std::string_view{filename}.substr(SAVESTATE_INVALIDATION_PREFIX.size(), 64);
      if (filename.size() ==
              SAVESTATE_INVALIDATION_PREFIX.size() + 64 + SAVESTATE_INVALIDATION_SUFFIX.size() &&
          IsSha256(token))
      {
        markers.emplace_back(PathToString(entry.path()));
      }
    }
    iterator.increment(error);
    if (error)
      return std::nullopt;
  }
  std::ranges::sort(markers);
  return markers;
}

bool CreateSavestateInvalidationMarker()
{
  const std::string path = File::GetUserPath(D_CONFIG_IDX) +
                           std::string{SAVESTATE_INVALIDATION_PREFIX} + GenerateSecret() +
                           std::string{SAVESTATE_INVALIDATION_SUFFIX};
  constexpr std::array<u8, 1> CONTENTS{1};
  // Atomic publication gives Windows a write-through namespace operation and POSIX a parent
  // fsync. A failed post-rename flush deliberately leaves the marker behind and rejects the load.
  return WriteAtomically(path, CONTENTS);
}

bool ConsumeSavestateInvalidationMarker(const std::string& path)
{
  const std::string consumed_path = path + ".consumed-" + GenerateSecret();
  if (RenameDurably(path, consumed_path) != NamespaceCommitResult::Durable)
    return false;

  // The durable rename already removed the name scanned as an active marker. Deleting the ignored
  // consumed name is best-effort; a crash residue cannot weaken ancestor invalidation.
  File::Delete(consumed_path, File::IfAbsentBehavior::NoConsoleWarning);
  return true;
}

bool PreserveLocalBackup(const Binding& binding, const FileSnapshot& snapshot)
{
  const std::string backup_path = File::GetUserPath(D_CONFIG_IDX) + "EmuBankBackups/" + binding.id +
                                  "/" + snapshot.sha256 + ".save";
  if (File::IsFile(backup_path))
  {
    const auto existing = ReadSaveFile(backup_path);
    return existing && existing->sha256 == snapshot.sha256 &&
           DurablyConfirmExistingFileData(backup_path, snapshot.sha256);
  }
  return WriteAtomically(backup_path, snapshot.contents);
}

bool PreserveDisplacedLocal(const Binding& binding, const std::string& displaced_path)
{
  if (!FlushFileData(displaced_path))
  {
    WARN_LOG_FMT(CORE, "EmuBank: could not flush retained local '{}'", binding.relative_path);
    return false;
  }

  const std::string backup_path = File::GetUserPath(D_CONFIG_IDX) + "EmuBankBackups/" + binding.id +
                                  "/retained-" + GenerateSecret() + ".save";
  if (PrepareParentDirectory(backup_path))
  {
    const NamespaceCommitResult moved = RenameDurably(displaced_path, backup_path);
    if (moved == NamespaceCommitResult::Durable)
    {
      INFO_LOG_FMT(CORE, "EmuBank: retained the displaced local '{}' at '{}'",
                   binding.relative_path, backup_path);
      return true;
    }
    if (moved == NamespaceCommitResult::CommittedNotDurable)
      return false;
  }

  // Rehome a failed backup-tree move under a short, unique sibling name. A same-directory rename
  // does not require hard-link support and keeps an open writer attached to the retained inode.
  std::string retained_path = displaced_path;
  const std::filesystem::path displaced_native = StringToPath(displaced_path);
  const std::string sibling_path = PathToString(
      displaced_native.parent_path() / StringToPath(".emubank-retained-" + GenerateSecret()));
  const NamespaceCommitResult sibling_move = RenameDurably(displaced_path, sibling_path);
  if (sibling_move != NamespaceCommitResult::Failed)
  {
    retained_path = sibling_path;
  }

  // Never delete this entry on a backup-move failure. It may be the inode a concurrent editor is
  // still writing, and its suffix keeps it out of GCI save discovery.
  WARN_LOG_FMT(CORE, "EmuBank: retained the displaced local '{}' beside the save at '{}'",
               binding.relative_path, retained_path);
  return sibling_move == NamespaceCommitResult::Durable;
}

// A process keeps these advisory locks for the lifetime of its EmuBank manager once it first syncs
// or loads a savestate. Locking both Config and every exact resolved save-root directory prevents
// profiles which deliberately share that directory from opening it concurrently.
class InterprocessSyncLock final
{
public:
  explicit InterprocessSyncLock(std::string path) : m_path(std::move(path)) {}

  ~InterprocessSyncLock()
  {
    if (!m_locked)
    {
#if defined(_WIN32)
      if (m_file != INVALID_HANDLE_VALUE)
        CloseHandle(m_file);
#else
      ReleaseDirectoryLock();
#endif
      return;
    }
#if defined(_WIN32)
    OVERLAPPED overlapped{};
    if (UnlockFileEx(m_file, 0, std::numeric_limits<DWORD>::max(),
                     std::numeric_limits<DWORD>::max(), &overlapped) == 0)
    {
      WARN_LOG_FMT(CORE, "EmuBank: could not release the interprocess save lock (error {})",
                   GetLastError());
    }
    CloseHandle(m_file);
#else
    if (flock(m_file.GetHandle(), LOCK_UN) != 0)
    {
      WARN_LOG_FMT(CORE, "EmuBank: could not release the interprocess save lock: {}",
                   std::strerror(errno));
    }
    ReleaseDirectoryLock();
#endif
  }

  InterprocessSyncLock(const InterprocessSyncLock&) = delete;
  InterprocessSyncLock& operator=(const InterprocessSyncLock&) = delete;

  const std::optional<FileIdentity>& DirectoryIdentity() const { return m_directory_identity; }

  bool StillOwnsConfiguredDirectory() const
  {
    if (!m_locked || !m_directory_identity)
      return false;
    FileIdentity current_identity;
    if (LookupFileIdentity(m_parent_path, &current_identity) != FileIdentityLookupResult::Exists ||
        current_identity != *m_directory_identity)
    {
      return false;
    }
#if defined(_WIN32)
    if (!m_file_identity)
      return false;
    const HANDLE named_handle = CreateFileW(
        UTF8ToWString(m_path).c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    if (named_handle == INVALID_HANDLE_VALUE)
      return false;
    Common::ScopeGuard close_named_handle{[named_handle] { CloseHandle(named_handle); }};
    BY_HANDLE_FILE_INFORMATION information{};
    const std::optional<FileIdentity> named_identity = IdentityForHandle(named_handle);
    return GetFileInformationByHandle(named_handle, &information) != FALSE &&
           (information.dwFileAttributes &
            (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) ==
               0 &&
           named_identity && *named_identity == *m_file_identity;
#else
    return true;
#endif
  }

  bool TryLockUntil(std::chrono::steady_clock::time_point deadline)
  {
    if (!File::CreateFullPath(m_path))
      return false;

    m_parent_path = StringToPath(m_path).parent_path();

#if defined(_WIN32)
    FileIdentity directory_identity;
    if (LookupFileIdentity(m_parent_path, &directory_identity) != FileIdentityLookupResult::Exists)
    {
      return false;
    }
    m_directory_identity = directory_identity;
    // DirectIOFile deliberately grants FILE_SHARE_DELETE, which would let a cleaner rename this
    // pathname and let another Dolphin lock a newly created file. Keep a dedicated handle whose
    // sharing mode permits peer lockers but denies deletion/rename for our entire lifetime. Open
    // the leaf itself so a pre-existing reparse point cannot redirect LockFileEx elsewhere.
    m_file = CreateFileW(
        UTF8ToWString(m_path).c_str(), GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (m_file == INVALID_HANDLE_VALUE)
      return false;
    BY_HANDLE_FILE_INFORMATION lock_information{};
    m_file_identity = IdentityForHandle(m_file);
    if (GetFileInformationByHandle(m_file, &lock_information) == FALSE || !m_file_identity ||
        (lock_information.dwFileAttributes &
         (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) != 0)
    {
      return false;
    }
#else
    // Keep a cooperative lock on the stable config directory as well as the visible lock file.
    // POSIX permits an unrelated cleaner to unlink a locked pathname; the directory lock prevents
    // a second Dolphin from acquiring a newly created lock-file inode after such an unlink.
    int directory_flags = O_RDONLY;
#ifdef O_DIRECTORY
    directory_flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    directory_flags |= O_CLOEXEC;
#endif
    m_directory = open(PathToString(m_parent_path).c_str(), directory_flags);
    if (m_directory < 0)
      return false;
    struct stat directory_information{};
    if (fstat(m_directory, &directory_information) != 0)
      return false;
    m_directory_identity = FileIdentity{static_cast<u64>(directory_information.st_dev),
                                        static_cast<u64>(directory_information.st_ino)};
    if (!m_file.Open(m_path, File::AccessMode::ReadAndWrite, File::OpenMode::Always))
      return false;
#endif

    while (std::chrono::steady_clock::now() < deadline)
    {
#if defined(_WIN32)
      OVERLAPPED overlapped{};
      if (LockFileEx(m_file, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
                     std::numeric_limits<DWORD>::max(), std::numeric_limits<DWORD>::max(),
                     &overlapped) != 0)
      {
        m_locked = true;
        return StillOwnsConfiguredDirectory();
      }
      const DWORD error = GetLastError();
      if (error != ERROR_LOCK_VIOLATION && error != ERROR_IO_PENDING)
        return false;
#else
      if (!m_directory_locked)
      {
        if (flock(m_directory, LOCK_EX | LOCK_NB) == 0)
        {
          m_directory_locked = true;
        }
        else if (errno != EWOULDBLOCK && errno != EINTR)
        {
          return false;
        }
      }
      if (m_directory_locked && flock(m_file.GetHandle(), LOCK_EX | LOCK_NB) == 0)
      {
        m_locked = true;
        return StillOwnsConfiguredDirectory();
      }
      if (m_directory_locked && errno != EWOULDBLOCK && errno != EINTR)
        return false;
#endif
      const auto remaining = deadline - std::chrono::steady_clock::now();
      if (remaining <= std::chrono::steady_clock::duration::zero())
        break;
      std::this_thread::sleep_for(
          std::min(25ms, std::chrono::duration_cast<std::chrono::milliseconds>(remaining)));
    }
    return false;
  }

private:
#if !defined(_WIN32)
  void ReleaseDirectoryLock()
  {
    if (m_directory_locked && flock(m_directory, LOCK_UN) != 0)
    {
      WARN_LOG_FMT(CORE, "EmuBank: could not release the interprocess directory lock: {}",
                   std::strerror(errno));
    }
    m_directory_locked = false;
    if (m_directory >= 0)
      close(std::exchange(m_directory, -1));
  }
#endif

  std::string m_path;
  std::filesystem::path m_parent_path;
  std::optional<FileIdentity> m_directory_identity;
#if defined(_WIN32)
  HANDLE m_file = INVALID_HANDLE_VALUE;
  std::optional<FileIdentity> m_file_identity;
#else
  File::DirectIOFile m_file;
  int m_directory = -1;
  bool m_directory_locked = false;
#endif
  bool m_locked = false;
};

struct ProcessLockDirectoryCandidate
{
  FileIdentity identity;
  std::filesystem::path canonical_path;
  std::vector<std::filesystem::path> configured_paths;
};

struct ProcessLockDirectoryAlias
{
  std::filesystem::path configured_path;
  FileIdentity identity;
};

// Savestate admission and completion are paired callbacks, but manager shutdown can remove the
// completion hook from another thread. std::timed_mutex cannot legally transfer ownership across
// those threads, so use a one-slot gate whose release is deliberately thread-independent.
class CrossThreadTimedGate final
{
public:
  void lock()
  {
    std::unique_lock lock(m_mutex);
    m_condition.wait(lock, [this] { return !m_locked; });
    m_locked = true;
  }

  bool try_lock_until(const std::chrono::steady_clock::time_point deadline)
  {
    std::unique_lock lock(m_mutex);
    if (!m_condition.wait_until(lock, deadline, [this] { return !m_locked; }))
      return false;
    m_locked = true;
    return true;
  }

  void unlock()
  {
    {
      std::lock_guard lock(m_mutex);
      m_locked = false;
    }
    m_condition.notify_one();
  }

private:
  std::mutex m_mutex;
  std::condition_variable m_condition;
  bool m_locked = false;
};

class Manager final
{
public:
  Manager()
      : m_config_root(File::GetUserPath(D_CONFIG_IDX)),
        m_gamecube_save_root(File::GetUserPath(D_GCUSER_IDX)),
        m_effective_wii_save_root(File::GetUserPath(D_WIIROOT_IDX))
  {
    ReloadDurableState();
    m_last_sync_config = ReadSyncConfig();
    m_before_boot_hook = Core::AddOnBeforeBootCallback([this] { OnBeforeBoot(); });
    m_boot_attempt_finished_hook = Core::AddOnBootAttemptFinishedCallback(
        [this](bool started) { OnBootAttemptFinished(started); });
    m_state_changed_hook = Core::AddOnStateChangedCallback(
        [this](Core::State state) { OnEmulationStateChanged(state); });
    m_save_data_changed_hook = Core::AddOnSaveDataChangedCallback([this] { OnSaveDataChanged(); });
    m_before_savestate_load_hook =
        Core::AddOnBeforeSavestateLoadCallback([this] { OnBeforeSavestateLoad(); });
    m_savestate_load_finished_hook = Core::AddOnSavestateLoadFinishedCallback(
        [this](bool loaded) { OnSavestateLoadFinished(loaded); });
    m_config_changed_callback = Config::AddConfigChangedCallback([this] { OnConfigChanged(); });
    m_worker = std::thread([this] { WorkerLoop(); });
    if (Config::Get(Config::MAIN_EMUBANK_ENABLED))
      Request();
    else
      SetStatus("EmuBank cloud sync is disabled.");
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

    m_before_boot_hook.reset();
    m_boot_attempt_finished_hook.reset();
    m_state_changed_hook.reset();
    m_save_data_changed_hook.reset();
    m_before_savestate_load_hook.reset();
    m_savestate_load_finished_hook.reset();
    const bool abandoned_savestate_load = m_savestate_sync_gate.has_value();
    // Shutdown may remove the matching finished hook while a state load is between its two
    // notifications. Release the transfer-safe local gate before joining; an already admitted
    // worker rechecks m_shutdown after acquisition and cannot inspect the partial load.
    m_savestate_sync_gate.reset();
    if (m_worker.joinable())
      m_worker.join();
    std::thread prelaunch_thread;
    {
      std::lock_guard lock(m_prelaunch_thread_mutex);
      if (m_prelaunch_thread.joinable())
        prelaunch_thread = std::move(m_prelaunch_thread);
    }
    if (prelaunch_thread.joinable())
      prelaunch_thread.join();

    // A successful savestate load can race shutdown after it queues ancestor invalidation but
    // before the worker consumes it. Persist that safety marker even when cloud sync is disabled.
    if (!m_process_locks.empty())
    {
      std::lock_guard operation_lock(m_sync_mutex);
      PersistPendingAncestorInvalidation();
    }

    {
      std::lock_guard operation_lock(m_pairing_operation_mutex);
      StopPairing();
      FinalizePairingLocked();
    }

    bool stopped_pass_already_attempted = false;
    {
      std::lock_guard lock(m_wake_mutex);
      const u64 final_generation = m_final_sync_generation.load(std::memory_order_acquire);
      stopped_pass_already_attempted =
          final_generation != 0 &&
          m_last_attempted_generation.load(std::memory_order_acquire) >= final_generation;
    }
    // State::Uninitialized already queues one immediate stopped pass. Do not repeat the entire
    // manifest/hash cycle during manager teardown after that generation was attempted.
    const bool run_final_sync = !m_emulation_active && Config::Get(Config::MAIN_EMUBANK_ENABLED) &&
                                !stopped_pass_already_attempted && !abandoned_savestate_load;
    if (run_final_sync)
      SyncOnce(SyncMode::Idle, std::nullopt, true, true);

    // Keep root/config cancellation active through the explicit final pass. Request() is already
    // inert after m_shutdown is set, while the callback still serializes a concurrent settings
    // change with the final namespace publication.
    Config::RemoveConfigChangedCallback(m_config_changed_callback);
  }

  u64 Request(RequestPriority priority = RequestPriority::Automatic)
  {
    if (m_shutdown.load(std::memory_order_acquire))
      return 0;

    u64 generation = 0;
    {
      std::lock_guard lock(m_wake_mutex);
      if (m_stop)
        return 0;
      m_sync_requested = true;
      if (priority != RequestPriority::Automatic)
      {
        m_immediate_sync_requested = true;
      }
      else if (!m_automatic_request_time)
      {
        m_automatic_request_time = std::chrono::steady_clock::now();
      }
      generation = ++m_requested_generation;
    }
    if (priority == RequestPriority::UserInitiated)
      SetStatus("EmuBank sync queued…");
    m_wake_condition.notify_all();
    return generation;
  }

  bool IsSyncing() const { return m_is_syncing.load(std::memory_order_acquire); }

  bool SyncAndWait(std::chrono::milliseconds timeout)
  {
    if (timeout <= 0ms || m_emulation_active || m_shutdown.load(std::memory_order_acquire))
      return false;

    std::unique_lock lock(m_wake_mutex);
    if (m_stop)
      return false;

    // State::Uninitialized always records the generation for this game's final pass. Wait for that
    // pass even if it completed before Android reached this function; do not turn a fast shutdown
    // into a second complete manifest/hash pass.
    u64 target_generation = m_final_sync_generation.load(std::memory_order_acquire);
    target_generation = std::max(target_generation, m_requested_generation);
    if (target_generation == 0)
    {
      target_generation = ++m_requested_generation;
      m_sync_requested = true;
      m_wake_condition.notify_all();
    }
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
    auto base_url = NormalizeServerUrl(
        std::move(server_url), Config::Get(Config::MAIN_EMUBANK_ALLOW_INSECURE), &validation_error);
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
            {"capabilities", picojson::value{picojson::array{
                                 picojson::value{"save_sync"}, picojson::value{"binding_discovery"},
                                 picojson::value{"library_onboarding"}}}},
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

    {
      // Keep the callback guard outside the install-lock scope. Its deferred callback may acquire
      // that same lock, while the credential publication itself must share one linear order with
      // a download's final connection check and canonical namespace commit.
      Config::ConfigChangeCallbackGuard guard;
      {
        std::lock_guard install_lock(m_save_install_mutex);
        m_config_changed_during_sync.store(true, std::memory_order_release);
        Config::SetBase(Config::MAIN_EMUBANK_SERVER_URL, base_url);
        Config::SetBase(Config::MAIN_EMUBANK_DEVICE_TOKEN, token);
        Config::SetBase(Config::MAIN_EMUBANK_ENABLED, true);
        Config::Save();
        {
          std::lock_guard lock(m_config_snapshot_mutex);
          m_last_sync_config = ReadSyncConfig();
        }
      }
    }
    SetStatus(fmt::format("EmuBank authorized{}; syncing device bindings…",
                          device_name.empty() ? "" : " as " + device_name));
    Request(RequestPriority::Immediate);
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
      const Connection connection{session.base_url, device_id, token, m_gamecube_save_root,
                                  EffectiveWiiSaveRoot()};
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
      ++m_save_event_generation;
      m_save_sync_deadline = std::chrono::steady_clock::now() + SAVE_EVENT_QUIET_PERIOD;
    }
    m_wake_condition.notify_all();
  }

  void OnBeforeSavestateLoad()
  {
    const bool invalidation_was_already_requested =
        m_invalidate_ancestors_requested.exchange(true, std::memory_order_acq_rel);
    const auto deadline = std::chrono::steady_clock::now() + BEFORE_LAUNCH_OPERATION_TIMEOUT;
    std::unique_lock sync_gate(m_sync_mutex, std::defer_lock);
    if (!sync_gate.try_lock_until(deadline) || !EnsureProcessLock(deadline))
    {
      // Only undo our own request when no durable state or marker operation was attempted.
      if (!sync_gate.owns_lock() && !invalidation_was_already_requested)
        m_invalidate_ancestors_requested.store(false, std::memory_order_release);
      Core::RequestSavestateLoadCancellation();
      SetStatus("EmuBank canceled the savestate load because its durable save-safety gate could "
                "not be acquired. Close other Dolphin processes or repair storage, then retry.");
      DisplaySyncMessage("EmuBank canceled savestate load: save safety was unavailable", 7000,
                         OsdTone::Error);
      return;
    }

    // Persist the affected save identity before deserialization. A root bit by itself cannot be
    // cleared safely: a later launch of game B must not make a crashed load of game A look fully
    // reconciled. Multiple admitted loads union their scopes until the epoch is consumed.
    const bool prior_pending = m_ancestor_invalidation_pending;
    const bool prior_selectors_complete = m_ancestor_invalidation_selectors_complete;
    const auto prior_game_selectors = m_ancestor_invalidation_game_selectors;
    const auto prior_path_selectors = m_ancestor_invalidation_path_selectors;
    if (!prior_pending)
    {
      m_ancestor_invalidation_game_selectors.clear();
      m_ancestor_invalidation_path_selectors.clear();
    }

    {
      std::lock_guard lock(m_active_game_mutex);
      if (!m_launch_priority_paths.empty())
      {
        m_ancestor_invalidation_path_selectors.insert(m_launch_priority_paths.begin(),
                                                      m_launch_priority_paths.end());
      }
      if (!m_launch_priority_game_id.empty())
      {
        m_ancestor_invalidation_game_selectors.insert(m_launch_priority_game_id);
      }
    }
    m_ancestor_invalidation_selectors_complete = prior_pending ? prior_selectors_complete : true;
    m_ancestor_invalidation_pending = true;
    for (auto& [id, state] : m_state)
    {
      (void)id;
      if (!state.ancestor_invalidated)
      {
        state.ancestor_invalidated = true;
        m_state_dirty = true;
      }
    }
    m_pending_uploads.clear();
    if (!prior_pending || prior_selectors_complete != m_ancestor_invalidation_selectors_complete ||
        prior_game_selectors != m_ancestor_invalidation_game_selectors ||
        prior_path_selectors != m_ancestor_invalidation_path_selectors)
    {
      m_state_dirty = true;
    }
    if (m_state_dirty)
      SaveState();

    if (m_state_dirty || !CreateSavestateInvalidationMarker())
    {
      // Retain the root request and any partially published marker. Both are conservative when a
      // load is rejected, and the next pass will invalidate ancestry before network access.
      Core::RequestSavestateLoadCancellation();
      SetStatus("EmuBank canceled the savestate load because its durable save-safety state could "
                "not be committed. Repair storage, then retry.");
      DisplaySyncMessage("EmuBank canceled savestate load: save safety was unavailable", 7000,
                         OsdTone::Error);
      return;
    }

    m_savestate_sync_gate.emplace(std::move(sync_gate));
  }

  void OnSavestateLoadFinished(bool loaded)
  {
    // A failed deserialize may already have mutated and queued a save-device flush. Treat every
    // admitted attempt exactly like a successful load and let the next pass discard old ancestry.
    if (m_savestate_sync_gate)
    {
      if (!loaded)
      {
        SetStatus("EmuBank marked a partially applied savestate as divergent; cloud sync will "
                  "reconcile it conservatively.");
      }
      m_savestate_sync_gate.reset();
    }
    Request();
  }

  void OnConfigChanged()
  {
    const SyncConfig next = ReadSyncConfig();
    // Download holds this lock from its final local/config checks through namespace publication.
    // Sharing it here gives a settings change and a local install a single linear order: whichever
    // enters first completes before the other can authorize work under a different connection.
    std::lock_guard install_lock(m_save_install_mutex);
    {
      std::lock_guard lock(m_config_snapshot_mutex);
      const bool save_root_setting_changed =
          next.wii_save_root_setting != m_last_sync_config.wii_save_root_setting;
      if (!next.wii_save_root_setting.empty())
        m_effective_wii_save_root = next.wii_save_root_setting;
      if (next == m_last_sync_config)
        return;
      m_last_sync_config = next;
      m_config_changed_during_sync.store(true, std::memory_order_release);
      if (save_root_setting_changed &&
          m_process_lock_admission_started.load(std::memory_order_acquire))
      {
        // Core may open the new root immediately after a GUI-pumped prelaunch callback returns.
        // Make the change restart-only at publication time; waiting for the next sync pass would
        // leave a post-check window in which only the former root is lifetime-locked.
        m_process_storage_changed.store(true, std::memory_order_release);
        m_canonical_recovery_required.store(true, std::memory_order_release);
        if (m_launch_pending.load(std::memory_order_acquire))
          Core::RequestBootCancellation();
      }
    }
    Request();
  }

  void OnBeforeBoot()
  {
    if (m_shutdown.load(std::memory_order_acquire) ||
        m_emulation_active.load(std::memory_order_acquire))
      return;

    std::thread prior_prelaunch_thread;
    {
      std::lock_guard lock(m_prelaunch_thread_mutex);
      if (m_prelaunch_thread.joinable())
      {
        if (m_prelaunch_in_progress.load(std::memory_order_acquire))
        {
          Core::RequestBootCancellation();
          SetStatus("EmuBank canceled launch because the prior bounded save check is still "
                    "finishing. Wait for it to complete, then retry.");
          DisplaySyncMessage("EmuBank save check is still finishing; launch canceled", 7000,
                             OsdTone::Warning);
          return;
        }
        prior_prelaunch_thread = std::move(m_prelaunch_thread);
      }
    }
    if (prior_prelaunch_thread.joinable())
      prior_prelaunch_thread.join();

    const auto prelaunch_deadline =
        std::chrono::steady_clock::now() + BEFORE_LAUNCH_OPERATION_TIMEOUT;

    u64 covered_save_generation = 0;
    u64 covered_request_generation = 0;
    {
      // Publish the launch gate under the same mutex the worker uses for its final start decision.
      // No new background pass can be admitted after this point.
      std::lock_guard lock(m_wake_mutex);
      m_launch_pending.store(true, std::memory_order_release);
      covered_save_generation = m_save_event_generation;
      covered_request_generation = m_requested_generation;
      m_sync_requested = false;
      m_immediate_sync_requested = false;
      m_automatic_request_time.reset();
    }
    m_wake_condition.notify_all();

    m_final_sync_generation.store(0, std::memory_order_release);
    {
      std::lock_guard lock(m_active_game_mutex);
      m_active_game = CaptureGameCubeIdentity();
      m_launch_priority_game_id = SConfig::GetInstance().GetGameID();
      Common::ToUpper(&m_launch_priority_game_id);
      if (!IsSafeGameIdentifier(m_launch_priority_game_id))
        m_launch_priority_game_id.clear();
      m_launch_priority_paths = CaptureConfiguredLaunchSavePaths(m_gamecube_save_root);
      m_resolved_save_paths.clear();
    }

    // Core::Init must remain on Qt's GUI thread for graphics setup, but the network pass does not.
    // Keep that thread pumping paint/timer events while a network-budgeted helper performs
    // reconciliation; Android's native boot thread uses the same path and Host_YieldToUI is a
    // no-op there.
    std::promise<void> completion;
    std::future<void> completed = completion.get_future();
    {
      std::lock_guard lock(m_prelaunch_thread_mutex);
      m_prelaunch_in_progress.store(true, std::memory_order_release);
      m_prelaunch_thread =
          std::thread([this, prelaunch_deadline, covered_save_generation,
                       covered_request_generation, completion = std::move(completion)]() mutable {
            // Wait for any install that crossed the launch flag check. After this barrier no stale
            // Idle pass can replace a save until Core enters Starting and marks emulation active.
            {
              std::lock_guard install_lock(m_save_install_mutex);
            }
            const bool prelaunch_completed = SyncOnce(SyncMode::BeforeLaunch, prelaunch_deadline);
            RecordAutomaticSyncCompleted(covered_save_generation, covered_request_generation,
                                         prelaunch_completed);
            m_prelaunch_in_progress.store(false, std::memory_order_release);
            completion.set_value();
          });
    }
    while (std::chrono::steady_clock::now() < prelaunch_deadline &&
           completed.wait_for(50ms) != std::future_status::ready)
    {
      Host_YieldToUI();
    }
    if (completed.wait_for(0ms) != std::future_status::ready)
    {
      Core::RequestBootCancellation();
      SetStatus("EmuBank canceled launch because the bounded pre-launch save check exceeded 12 "
                "seconds. The check will finish safely in the background; retry afterward.");
      DisplaySyncMessage("EmuBank save check exceeded 12 seconds; launch canceled", 7000,
                         OsdTone::Warning);
      Host_YieldToUI();
      return;
    }
    completed.get();
    std::thread finished_prelaunch_thread;
    {
      std::lock_guard lock(m_prelaunch_thread_mutex);
      if (m_prelaunch_thread.joinable())
        finished_prelaunch_thread = std::move(m_prelaunch_thread);
    }
    if (finished_prelaunch_thread.joinable())
      finished_prelaunch_thread.join();
    Host_YieldToUI();
    ProcessStorageStillStable();
    // This check deliberately lives outside SyncOnce. A prior pass can hold m_sync_mutex until the
    // prelaunch budget expires; a known unsafe canonical path must still veto boot in that case.
    if (m_canonical_recovery_required.load(std::memory_order_acquire))
    {
      Core::RequestBootCancellation();
      SetStatus(m_process_storage_changed.load(std::memory_order_acquire) ?
                    "EmuBank canceled launch because a locked Config or save-root directory "
                    "changed while Dolphin was running. Restart Dolphin before retrying." :
                m_state_unreadable.load(std::memory_order_acquire) ?
                    "EmuBank canceled launch because its durable sync state is unreadable or "
                    "over its safety limit. Inspect EmuBankSyncState.json before retrying." :
                m_state_capacity_exceeded ?
                    "EmuBank canceled launch because too many durable binding safety records are "
                    "pending. Reduce the server binding set, then retry." :
                m_recovery_journal_unreadable.load(std::memory_order_acquire) ?
                    "EmuBank canceled launch because its save recovery metadata is unreadable. "
                    "Inspect EmuBankSyncState.json, EmuBankRecovery.json, and retained backups "
                    "before retrying." :
                m_recovery_persistence_failed.load(std::memory_order_acquire) ?
                    "EmuBank canceled launch because save-path recovery could not be written to "
                    "disk. Keep Dolphin open and repair storage before retrying." :
                    "EmuBank canceled launch because a save still needs canonical-path recovery. "
                    "Restore its retained backup, then try again.");
    }
    if (HasPendingGameResolution())
      Request();
  }

  void OnBootAttemptFinished(bool started)
  {
    if (started)
      return;

    {
      std::lock_guard lock(m_wake_mutex);
      if (!m_launch_pending.load(std::memory_order_acquire))
        return;
      {
        // Keep the worker behind the launch predicate until the failed attempt's identity is gone;
        // condition-variable waits may wake spuriously before the explicit notification below.
        std::lock_guard game_lock(m_active_game_mutex);
        m_active_game.reset();
        m_launch_priority_game_id.clear();
        m_launch_priority_paths.clear();
        m_resolved_save_paths.clear();
      }
      m_launch_pending.store(false, std::memory_order_release);
    }
    m_wake_condition.notify_all();
  }

  void OnEmulationStateChanged(Core::State state)
  {
    if (state == Core::State::Starting)
    {
      // Core has only entered its emulation-thread initialization here. Keep the worker behind the
      // launch gate until Running/Paused proves that HW and video startup completed.
      {
        std::lock_guard lock(m_wake_mutex);
        m_emulation_active.store(true, std::memory_order_release);
      }
    }
    else if (state == Core::State::Running || state == Core::State::Paused)
    {
      {
        std::lock_guard lock(m_wake_mutex);
        m_emulation_active.store(true, std::memory_order_release);
        m_launch_pending.store(false, std::memory_order_release);
      }
      m_wake_condition.notify_all();
    }
    else if (state == Core::State::Stopping)
    {
      // If Stop was requested during Starting, keep the gate closed through teardown. Otherwise
      // Running/Paused already released it and this is just the normal active-state marker.
      m_emulation_active.store(true, std::memory_order_release);
    }
    else if (state == Core::State::Uninitialized)
    {
      u64 final_generation = 0;
      {
        std::lock_guard lock(m_wake_mutex);
        m_emulation_active.store(false, std::memory_order_release);
        m_launch_pending.store(false, std::memory_order_release);
        {
          // A Live pass may have resolved a cloud download that was deliberately closed while the
          // game was running. Preserve the stopped identity until a fresh resolver pass completes;
          // a queued next game may begin before this final worker pass gets the sync mutex.
          std::lock_guard game_lock(m_active_game_mutex);
          if (m_active_game)
          {
            if (!std::ranges::any_of(m_pending_game_resolutions, [this](const auto& pending) {
                  return pending.game == *m_active_game;
                }))
            {
              m_pending_game_resolutions.push_back(
                  PendingGameResolution{++m_next_game_resolution_token, *m_active_game});
            }
            // The stopped title is no longer active even when an older unresolved token already
            // represents it. Leaving it here would make every later idle pass resolve it twice.
            m_active_game.reset();
          }
          // Retain title/raw-card priority through the immediate stopped pass. A savestate epoch
          // cannot be finalized safely until that pass observes the affected binding after all
          // host save devices have flushed.
          m_resolved_save_paths.clear();
        }
        // Publish the stopped state and its immediate final generation together. Otherwise a
        // cadence-due worker can start one Idle pass in between and then run this requested pass a
        // second time back-to-back.
        if (!m_stop && !m_shutdown.load(std::memory_order_acquire))
        {
          m_sync_requested = true;
          m_immediate_sync_requested = true;
          final_generation = ++m_requested_generation;
        }
        m_final_sync_generation.store(final_generation, std::memory_order_release);
      }
      m_wake_condition.notify_all();
    }
  }

  void WorkerLoop()
  {
    Common::SetCurrentThreadName("EmuBank Sync");
    while (true)
    {
      const int interval = std::clamp(Config::Get(Config::MAIN_EMUBANK_SYNC_INTERVAL), 30, 300);
      const bool emulation_active = m_emulation_active.load(std::memory_order_acquire);
      const bool launch_pending_snapshot = m_launch_pending.load(std::memory_order_acquire);
      const bool automatic_sync_enabled =
          !launch_pending_snapshot && Config::Get(Config::MAIN_EMUBANK_ENABLED) &&
          (!emulation_active || Config::Get(Config::MAIN_EMUBANK_LIVE_SYNC));
      // Save events drive live uploads. Polling the manifest and hashing every bound save while a
      // game is idle wastes battery and I/O; periodic checks are only needed while files are
      // closed.
      const bool periodic_sync_enabled = automatic_sync_enabled && !emulation_active;
      const bool live_retry = automatic_sync_enabled && HasPendingLiveUpload();
      std::unique_lock lock(m_wake_mutex);
      if (m_stop)
        return;

      const bool launch_pending = m_launch_pending.load(std::memory_order_acquire);
      if (launch_pending != launch_pending_snapshot)
        continue;
      if (launch_pending)
      {
        m_wake_condition.wait(
            lock, [this] { return m_stop || !m_launch_pending.load(std::memory_order_acquire); });
        continue;
      }

      const auto now = std::chrono::steady_clock::now();
      const auto cadence_due = Policy::MinimumAutomaticDeadline(
          m_last_automatic_sync, std::chrono::seconds{interval}, now);
      std::optional<std::chrono::steady_clock::time_point> automatic_due;
      const auto include_automatic_deadline = [&automatic_due](const auto deadline) {
        automatic_due = automatic_due ? std::min(*automatic_due, deadline) : deadline;
      };

      if (periodic_sync_enabled)
        include_automatic_deadline(cadence_due);

      const bool save_event_pending = m_save_event_generation > m_consumed_save_event_generation;
      if (automatic_sync_enabled && save_event_pending && m_save_sync_deadline)
      {
        include_automatic_deadline(Policy::MinimumAutomaticDeadline(
            m_last_automatic_sync, std::chrono::seconds{interval}, *m_save_sync_deadline));
      }
      if (automatic_sync_enabled && live_retry)
      {
        include_automatic_deadline(Policy::MinimumAutomaticDeadline(
            m_last_automatic_sync, std::chrono::seconds{interval}, now));
      }

      std::optional<std::chrono::steady_clock::time_point> requested_deadline;
      if (m_sync_requested && !m_immediate_sync_requested)
      {
        requested_deadline =
            Policy::MinimumAutomaticDeadline(m_last_automatic_sync, std::chrono::seconds{interval},
                                             m_automatic_request_time.value_or(now));
        include_automatic_deadline(*requested_deadline);
      }

      const bool automatic_is_due = automatic_due && now >= *automatic_due;
      const bool requested_automatic_is_due = requested_deadline && now >= *requested_deadline;
      const bool immediate_is_due = m_sync_requested && m_immediate_sync_requested;
      if (!immediate_is_due && !automatic_is_due)
      {
        if (automatic_due)
          m_wake_condition.wait_until(lock, *automatic_due);
        else
          m_wake_condition.wait(lock);
        continue;
      }

      const bool request_is_covered = immediate_is_due || requested_automatic_is_due;
      const u64 request_generation =
          request_is_covered ? m_requested_generation : m_completed_generation;
      const bool pass_is_live = m_emulation_active.load(std::memory_order_acquire);
      // A manual/config/retry trigger may become due while a fresh save burst is still inside its
      // quiet period. Such a pass may do other work, but it must neither upload those changing
      // bytes nor consume their event generation.
      const bool live_save_events_ready =
          Policy::LiveSaveEventsReady(save_event_pending, m_save_sync_deadline, now);
      const bool live_uploads_open = !pass_is_live || live_save_events_ready;
      const u64 covered_save_generation =
          Policy::CoveredSaveGeneration(pass_is_live, live_save_events_ready,
                                        m_consumed_save_event_generation, m_save_event_generation);
      if (request_is_covered)
      {
        m_sync_requested = false;
        m_immediate_sync_requested = false;
        m_automatic_request_time.reset();
      }
      lock.unlock();

      const SyncMode mode = pass_is_live ? SyncMode::Live : SyncMode::Idle;
      bool sync_completed = true;
      if (mode != SyncMode::Live || Config::Get(Config::MAIN_EMUBANK_LIVE_SYNC) ||
          !Config::Get(Config::MAIN_EMUBANK_ENABLED))
      {
        sync_completed = SyncOnce(mode, std::nullopt, live_uploads_open, false, request_generation);
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
      if (sync_completed)
      {
        m_consumed_save_event_generation =
            std::max(m_consumed_save_event_generation, covered_save_generation);
        if (m_save_event_generation <= covered_save_generation)
          m_save_sync_deadline.reset();
      }
      m_last_automatic_sync = std::chrono::steady_clock::now();
      lock.unlock();
      m_sync_finished_condition.notify_all();
    }
  }

  void RecordAutomaticSyncCompleted(u64 covered_save_generation, u64 covered_request_generation,
                                    bool sync_completed)
  {
    {
      std::lock_guard lock(m_wake_mutex);
      m_completed_generation = std::max(m_completed_generation, covered_request_generation);
      if (sync_completed)
      {
        m_consumed_save_event_generation =
            std::max(m_consumed_save_event_generation, covered_save_generation);
        if (m_save_event_generation <= covered_save_generation)
          m_save_sync_deadline.reset();
      }
      m_last_automatic_sync = std::chrono::steady_clock::now();
    }
    m_wake_condition.notify_all();
    m_sync_finished_condition.notify_all();
  }

  bool HasPendingLiveUpload()
  {
    std::lock_guard operation_lock(m_sync_mutex);
    return m_emulation_active && !m_pending_uploads.empty();
  }

  bool HasPendingGameResolution() const
  {
    std::lock_guard lock(m_active_game_mutex);
    return !m_pending_game_resolutions.empty();
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

    return Connection{std::move(*base_url), device_id, token, m_gamecube_save_root,
                      EffectiveWiiSaveRoot()};
  }

  std::string EffectiveWiiSaveRoot()
  {
    std::string configured = Config::Get(Config::MAIN_FS_PATH);
    if (!configured.empty())
      return configured;
    std::lock_guard lock(m_config_snapshot_mutex);
    return m_effective_wii_save_root;
  }

  bool ProcessStorageStillStable()
  {
    if (m_process_storage_changed.load(std::memory_order_acquire))
      return false;
    const bool locks_stable = std::ranges::all_of(m_process_locks, [](const auto& process_lock) {
      return process_lock->StillOwnsConfiguredDirectory();
    });
    const bool aliases_stable =
        std::ranges::all_of(m_active_process_lock_aliases, [](const auto& alias) {
          FileIdentity current_identity;
          return LookupFileIdentity(alias.configured_path, &current_identity) ==
                     FileIdentityLookupResult::Exists &&
                 current_identity == alias.identity;
        });
    if (locks_stable && aliases_stable)
      return true;
    m_process_storage_changed.store(true, std::memory_order_release);
    m_canonical_recovery_required.store(true, std::memory_order_release);
    return false;
  }

  bool ConnectionStillConfigured(const Connection& connection)
  {
    if (!ProcessStorageStillStable())
      return false;
    if (m_config_changed_during_sync.load(std::memory_order_acquire))
      return false;
    const std::optional<Connection> current = GetConnection();
    return current && *current == connection &&
           !m_config_changed_during_sync.load(std::memory_order_acquire) &&
           ProcessStorageStillStable();
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

  ResolveResult ResolveBinding(const Connection& connection, const GameIdentity& game,
                               const SaveLocation& location, const LocalSaveCandidate* local_save,
                               SyncMode mode)
  {
    if (!ConnectionStillConfigured(connection))
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank settings changed; save linking will retry."};
    }
    picojson::object local_save_object{
        {"kind", picojson::value{"memory_card"}},
        {"file_format", picojson::value{"gci"}},
        {"exists", picojson::value{local_save != nullptr}},
    };
    if (local_save)
    {
      local_save_object.emplace("sha256", picojson::value{local_save->snapshot.sha256});
      local_save_object.emplace(
          "size_bytes", picojson::value{static_cast<double>(local_save->snapshot.contents.size())});
    }

    const picojson::value relative_path =
        local_save ? picojson::value{local_save->relative_path} : picojson::value{};
    const std::string body = picojson::value{
        picojson::object{
            {"version", picojson::value{1.0}},
            {"relative_path", relative_path},
            {"relative_directory", picojson::value{location.relative_directory}},
            {"game", picojson::value{picojson::object{
                         {"platform", picojson::value{game.platform}},
                         {"game_id", picojson::value{game.game_id}},
                         {"title", picojson::value{game.title}},
                         {"region", picojson::value{game.region}},
                         {"revision", picojson::value{static_cast<double>(game.revision)}},
                     }}},
            {"local_save", picojson::value{std::move(local_save_object)}},
            {"create_if_missing", picojson::value{true}},
        }}.serialize();

    auto headers = Headers(connection);
    headers["Content-Type"] = "application/json";
    Common::HttpRequest request(
        HttpTimeoutUntil(m_sync_deadline),
        LimitTransfer(MAX_BINDING_RESOLUTION_RESPONSE_SIZE, body.size(), m_sync_deadline,
                      mode == SyncMode::BeforeLaunch ? nullptr : &m_launch_pending,
                      &m_config_changed_during_sync));
    const auto response = request.Post(fmt::format("{}/api/v1/devices/{}/bindings/resolve",
                                                   connection.base_url, connection.device_id),
                                       body, headers, Common::HttpRequest::AllowedReturnCodes::All);
    if (!response)
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = fmt::format("EmuBank could not look up the save for {}.", game.title)};
    }
    if (!ConnectionStillConfigured(connection))
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank settings changed; save linking will retry."};
    }

    const s32 response_code = request.GetLastResponseCode();
    if (response_code != 200 && response_code != 201)
    {
      picojson::value root;
      const picojson::object* root_object = ParseJsonObject(*response, &root);
      const picojson::object* error_object =
          root_object ? ObjectValue(*root_object, "error") : nullptr;
      const std::string error_code =
          error_object ? ObjectString(*error_object, "code").value_or("") : "";

      std::string message;
      if (response_code == 401)
      {
        message = "EmuBank rejected this Dolphin installation. Reconnect it in EmuBank settings.";
      }
      else if (response_code == 403 && error_code == "capability_required")
      {
        message = "Reconnect this Dolphin installation to approve automatic EmuBank game and save "
                  "discovery.";
      }
      else if (response_code == 404 && error_code == "save_file_not_found")
      {
        message = "EmuBank could not find the selected save. Choose it again in Devices & Sync.";
      }
      else if (response_code == 404)
      {
        message = "This EmuBank server does not support automatic Dolphin save linking yet. "
                  "Update the server and try again.";
      }
      else if (response_code == 409 && error_code == "selection_required")
      {
        message = fmt::format("EmuBank found multiple saves for {}. Choose one in Devices & Sync.",
                              game.title);
      }
      else if (response_code == 409 && error_code == "path_already_bound")
      {
        message = "This Dolphin save path is linked to another EmuBank game. Review it in Devices "
                  "& Sync.";
      }
      else if (response_code == 409 && error_code == "save_format_incompatible")
      {
        message = "EmuBank cannot connect an individual GCI save to a raw memory-card save.";
      }
      else if (response_code == 422 && !local_save)
      {
        message = fmt::format("No cloud save is linked for {} yet. Dolphin will link it after the "
                              "game creates a save.",
                              game.title);
      }
      else
      {
        message =
            fmt::format("EmuBank could not safely link {} (HTTP {}).", game.title, response_code);
      }

      const bool retryable_status = response_code == 408 || response_code == 429 ||
                                    (response_code >= 500 && response_code <= 599);
      return {.disposition = retryable_status ? ResolveDisposition::RetryableFailure :
                                                ResolveDisposition::ActionRequired,
              .message = std::move(message)};
    }

    picojson::value root;
    const picojson::object* root_object = ParseJsonObject(*response, &root);
    const picojson::object* data = root_object ? ObjectValue(*root_object, "data") : nullptr;
    if (!root_object || !ReadBoolFromJson(*root_object, "ok").value_or(false) || !data)
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank returned an invalid game-link response."};
    }

    ResolveResult result;
    result.disposition = ResolveDisposition::Resolved;
    if (local_save)
      result.reported_local_sha256 = local_save->snapshot.sha256;
    result.status = ObjectString(*data, "status").value_or("");
    result.next_action = ObjectString(*data, "next_action").value_or("");
    const picojson::object* match = ObjectValue(*data, "match");
    if (match)
    {
      result.match_method = ObjectString(*match, "method").value_or("");
      result.match_confidence = ObjectNumber(*match, "confidence").value_or(-1.0);
    }

    static const std::set<std::string, std::less<>> VALID_STATUSES = {
        "already_bound", "bound_existing", "created", "matched_existing"};
    static const std::set<std::string, std::less<>> VALID_NEXT_ACTIONS = {
        "none", "download", "upload", "wait_for_local_save", "reconcile"};
    if (!VALID_STATUSES.contains(result.status) ||
        !VALID_NEXT_ACTIONS.contains(result.next_action) || result.match_method.empty() ||
        result.match_confidence < 0.0 || result.match_confidence > 1.0)
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank returned an invalid game-link response."};
    }

    const auto binding_it = data->find("binding");
    if (binding_it == data->end())
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank returned an invalid game-link response."};
    }
    if (!binding_it->second.is<picojson::null>())
      result.binding = ParseBinding(binding_it->second);

    if (!result.binding)
    {
      if (!binding_it->second.is<picojson::null>() || result.next_action != "wait_for_local_save" ||
          local_save)
      {
        return {.disposition = ResolveDisposition::RetryableFailure,
                .message = "EmuBank returned an invalid game-link response."};
      }
      result.message = fmt::format("EmuBank recognized {} and will link it after the game creates "
                                   "a local save.",
                                   game.title);
      return result;
    }

    if (result.match_confidence < 0.8)
    {
      return {.disposition = ResolveDisposition::ActionRequired,
              .message = fmt::format("EmuBank needs confirmation before linking the save for {}. "
                                     "Review it in Devices & Sync.",
                                     game.title)};
    }

    Binding& binding = *result.binding;
    if (binding.game_id != game.game_id ||
        !ResolveSavePath(binding.relative_path, connection.gamecube_save_root,
                         connection.wii_save_root))
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank returned a save link for the wrong game or an unsafe path."};
    }

    std::string lowercase_path = binding.relative_path;
    Common::ToLower(&lowercase_path);
    if (!lowercase_path.ends_with(".gci"))
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank returned a non-GCI path for an individual GameCube save."};
    }

    if (result.next_action == "download" && !binding.current_revision)
    {
      return {.disposition = ResolveDisposition::RetryableFailure,
              .message = "EmuBank recommended a download without identifying a cloud revision."};
    }

    if (local_save)
    {
      if (binding.relative_path != local_save->relative_path)
      {
        return {.disposition = ResolveDisposition::RetryableFailure,
                .message = "EmuBank returned a different path than Dolphin's active save."};
      }
    }
    else
    {
      const size_t separator = binding.relative_path.find_last_of('/');
      const std::string_view parent =
          separator == std::string::npos ?
              std::string_view{} :
              std::string_view{binding.relative_path}.substr(0, separator);
      if (parent != location.relative_directory || result.next_action != "download" ||
          !binding.current_revision)
      {
        return {.disposition = ResolveDisposition::RetryableFailure,
                .message = "EmuBank did not provide a trustworthy cloud GCI path for this game."};
      }
    }

    return result;
  }

  ActiveGameResolution ResolveGame(const Connection& connection, SyncMode mode,
                                   const GameIdentity& game, bool allow_live_cache)
  {
    ActiveGameResolution resolution;
    if (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire))
    {
      resolution.retry_needed = true;
      return resolution;
    }
    const auto discovered_locations = DiscoverGameCubeGciSaves(
        game, m_sync_deadline, connection.gamecube_save_root, connection.wii_save_root);
    if (!discovered_locations)
    {
      resolution.retry_needed = true;
      return resolution;
    }
    const std::vector<SaveLocation>& locations = *discovered_locations;
    if (locations.empty())
    {
      const std::string message =
          fmt::format("EmuBank automatic linking for {} needs a GCI Folder memory card inside "
                      "Dolphin's GC save folder.",
                      game.title);
      SetStatus(message);
      if (mode == SyncMode::BeforeLaunch)
        DisplaySyncMessage("EmuBank: active save is not an accessible GCI Folder", 6000,
                           OsdTone::Warning);
      return {.notice = message};
    }

    size_t local_file_count = 0;
    for (const SaveLocation& location : locations)
    {
      local_file_count += location.files.size();
      for (const LocalSaveCandidate& candidate : location.files)
        resolution.priority_paths.insert(RelativePathKey(candidate.relative_path));
    }

    // A GameCube title can own multiple independent GCI entries. The v1 resolver does not yet
    // carry the internal GCI filename needed to prove which cloud SaveFile each entry belongs to;
    // auto-linking all of them by game ID would collapse distinct saves into one revision stream.
    if (local_file_count > 1)
    {
      const std::string message = fmt::format(
          "EmuBank found {} local save entries for {}. Existing links will still sync, but "
          "automatic linking needs a per-save choice in Devices & Sync.",
          local_file_count, game.title);
      WARN_LOG_FMT(CORE, "EmuBank: {}", message);
      SetStatus(message);
      DisplaySyncMessage("EmuBank found multiple saves; choose one in Devices & Sync", 7000,
                         OsdTone::Warning);
      resolution.notice = message;
      return resolution;
    }

    DisplaySyncMessage(fmt::format("EmuBank: finding {} save for {}...",
                                   local_file_count == 0 ? "cloud" : "the matching", game.title),
                       3000);

    const auto process_result = [&](const ResolveResult& result) {
      if (result.disposition != ResolveDisposition::Resolved)
      {
        // Keep a stopped-game token until a later pass observes the user's selection as well as
        // across transient failures. Treating ActionRequired as complete would erase an empty
        // binding set and leave no durable follow-up after the web choice.
        resolution.retry_needed = true;
        if (!result.message.empty())
        {
          WARN_LOG_FMT(CORE, "EmuBank: active-game binding resolution: {}", result.message);
          resolution.notice = result.message;
          SetStatus(result.message);
          DisplaySyncMessage(result.message, 7000,
                             result.disposition == ResolveDisposition::ActionRequired ?
                                 OsdTone::Warning :
                                 OsdTone::Error);
        }
        return;
      }

      if (!result.binding)
      {
        INFO_LOG_FMT(CORE, "EmuBank: {}", result.message);
        resolution.notice = result.message;
        SetStatus(result.message);
        DisplaySyncMessage(result.message, 6000);
        return;
      }
      INFO_LOG_FMT(CORE,
                   "EmuBank: resolved active-game binding '{}' by {} (confidence {:.2f}); next "
                   "action is {}",
                   result.binding->relative_path, result.match_method, result.match_confidence,
                   result.next_action);
      {
        std::lock_guard lock(m_active_game_mutex);
        m_resolved_save_paths.insert(result.binding->relative_path);
      }
      resolution.priority_paths.insert(RelativePathKey(result.binding->relative_path));
      resolution.resolved_binding_ids.insert(result.binding->id);

      if (result.next_action == "download")
      {
        bool explicit_selection = result.binding->explicit_download_pending;
        if (explicit_selection &&
            !RememberExplicitDownload(connection, *result.binding, result.reported_local_sha256))
        {
          const std::string message =
              "EmuBank could not durably record the selected cloud revision; the local save was "
              "left unchanged.";
          ERROR_LOG_FMT(CORE, "EmuBank: {}", message);
          resolution.notice = message;
          resolution.retry_needed = true;
          resolution.blocked_binding_ids.insert(result.binding->id);
          SetStatus(message);
          DisplaySyncMessage(message, 7000, OsdTone::Error);
          return;
        }
        resolution.download_authorizations.insert_or_assign(
            result.binding->id,
            ActiveGameResolution::DownloadAuthorization{
                result.binding->relative_path, *result.binding->current_revision,
                result.reported_local_sha256, explicit_selection});
        DisplaySyncMessage("EmuBank: cloud save found; restoring before launch...", 3500);
      }
      else if (result.next_action == "upload")
        DisplaySyncMessage("EmuBank: save linked; preparing cloud backup...", 3500);
      else if (result.next_action == "reconcile")
        DisplaySyncMessage("EmuBank: local and cloud saves found; comparing safely...", 3500,
                           OsdTone::Warning);
      else
        DisplaySyncMessage("EmuBank: save link is current", 2500, OsdTone::Success);
    };

    if (local_file_count == 0)
    {
      // Before launch this can restore an existing cloud GCI. After shutdown it also covers a
      // first-time game that never produced a local save or whose launch-time lookup was offline.
      // Live passes wait for the pathless save notification to reveal Dolphin's real GCI leaf.
      if (mode != SyncMode::Live)
        process_result(ResolveBinding(connection, game, locations.front(), nullptr, mode));
      return resolution;
    }

    for (const SaveLocation& location : locations)
    {
      for (const LocalSaveCandidate& candidate : location.files)
      {
        if ((mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)) ||
            std::chrono::steady_clock::now() >= m_sync_deadline)
        {
          resolution.retry_needed = true;
          return resolution;
        }

        bool already_resolved = false;
        {
          std::lock_guard lock(m_active_game_mutex);
          // Only Live passes may reuse discovery performed during the same running session.
          // Stopped and pre-launch passes always obtain a fresh revision-bound server decision;
          // an in-flight Live request can otherwise finish after State::Uninitialized and leave a
          // stale deferred-download marker behind.
          already_resolved = allow_live_cache && mode == SyncMode::Live &&
                             m_resolved_save_paths.contains(candidate.relative_path);
        }
        if (!already_resolved)
          process_result(ResolveBinding(connection, game, location, &candidate, mode));
      }
    }
    return resolution;
  }

  ActiveGameResolution ResolveActiveGames(const Connection& connection, SyncMode mode)
  {
    std::optional<GameIdentity> active_game;
    std::vector<PendingGameResolution> pending_games;
    std::set<std::string, std::less<>> launch_priority_paths;
    std::string launch_priority_game_id;
    {
      std::lock_guard lock(m_active_game_mutex);
      active_game = m_active_game;
      pending_games = m_pending_game_resolutions;
      launch_priority_paths = m_launch_priority_paths;
      launch_priority_game_id = m_launch_priority_game_id;
    }

    ActiveGameResolution combined;
    combined.priority_paths = std::move(launch_priority_paths);
    combined.priority_game_id = std::move(launch_priority_game_id);
    struct Attempt
    {
      GameIdentity game;
      bool retry_needed = false;
      std::set<std::string, std::less<>> binding_ids;
    };
    std::vector<Attempt> attempts;

    const auto merge = [&combined](ActiveGameResolution part, bool launch_priority) {
      if (launch_priority)
      {
        combined.priority_paths.insert(part.priority_paths.begin(), part.priority_paths.end());
      }
      for (auto& [id, authorization] : part.download_authorizations)
      {
        // The active launch identity is merged first and wins any impossible binding-ID overlap.
        combined.download_authorizations.try_emplace(id, std::move(authorization));
      }
      combined.blocked_binding_ids.insert(part.blocked_binding_ids.begin(),
                                          part.blocked_binding_ids.end());
      combined.resolved_binding_ids.insert(part.resolved_binding_ids.begin(),
                                           part.resolved_binding_ids.end());
      if (!part.notice.empty())
      {
        if (!combined.notice.empty() && combined.notice != part.notice)
          combined.notice += " ";
        if (combined.notice != part.notice)
          combined.notice += part.notice;
      }
      combined.retry_needed = combined.retry_needed || part.retry_needed;
    };

    const auto attempt_game = [&](const GameIdentity& game, bool launch_priority,
                                  bool allow_live_cache) {
      ActiveGameResolution part = ResolveGame(connection, mode, game, allow_live_cache);
      const bool retry_needed = part.retry_needed;
      std::set<std::string, std::less<>> binding_ids = part.resolved_binding_ids;
      if (launch_priority && !part.priority_paths.empty())
      {
        // GCI-folder paths are discovered by the resolver rather than static configuration. Keep
        // them with the running launch identity so a later savestate load can persist its exact
        // affected files instead of falling back to whichever title launches next.
        std::lock_guard lock(m_active_game_mutex);
        m_launch_priority_paths.insert(part.priority_paths.begin(), part.priority_paths.end());
      }
      merge(std::move(part), launch_priority);
      attempts.push_back({game, retry_needed, std::move(binding_ids)});
      return &attempts.back();
    };

    if (active_game &&
        !(mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)))
      attempt_game(*active_game, true, true);

    // A prior game's stopped/final work must never spend the current game's launch budget. The
    // caller requeues those retained tokens as cadence-gated automatic work; the launch lifecycle
    // gate holds it until Core is fully Running or the attempted boot fails.
    if (mode == SyncMode::BeforeLaunch)
      return combined;

    for (const PendingGameResolution& pending : pending_games)
    {
      if (m_launch_pending.load(std::memory_order_acquire))
      {
        combined.retry_needed = true;
        return combined;
      }
      const auto prior = std::ranges::find(attempts, pending.game, &Attempt::game);
      const Attempt* attempt = nullptr;
      if (prior != attempts.end())
      {
        attempt = &*prior;
      }
      else if (std::chrono::steady_clock::now() >= m_sync_deadline)
      {
        combined.retry_needed = true;
        continue;
      }
      else
      {
        attempt = attempt_game(pending.game, false, false);
      }

      if (attempt && !attempt->retry_needed)
      {
        combined.pending_completions.push_back(
            ActiveGameResolution::PendingCompletion{pending.token, attempt->binding_ids});
      }
    }
    return combined;
  }

  void CompletePendingGameResolutions(
      const std::vector<ActiveGameResolution::PendingCompletion>& completions,
      const std::set<std::string, std::less<>>& manifest_binding_ids)
  {
    if (completions.empty())
      return;

    std::vector<u64> completed_tokens;
    for (const auto& completion : completions)
    {
      if (std::ranges::all_of(completion.binding_ids, [&manifest_binding_ids](const auto& id) {
            return manifest_binding_ids.contains(id);
          }))
      {
        completed_tokens.push_back(completion.token);
      }
    }
    if (completed_tokens.empty())
      return;

    std::lock_guard lock(m_active_game_mutex);
    std::erase_if(m_pending_game_resolutions, [&completed_tokens](const auto& pending) {
      return std::ranges::find(completed_tokens, pending.token) != completed_tokens.end();
    });
  }

  std::optional<Manifest> FetchManifest(const Connection& connection, SyncMode mode)
  {
    if (!ConnectionStillConfigured(connection))
      return std::nullopt;
    Common::HttpRequest request(
        HttpTimeoutUntil(m_sync_deadline),
        LimitTransfer(MAX_MANIFEST_RESPONSE_SIZE, 0, m_sync_deadline,
                      mode == SyncMode::BeforeLaunch ? nullptr : &m_launch_pending,
                      &m_config_changed_during_sync));
    const std::string url =
        fmt::format("{}/api/v1/devices/{}/manifest", connection.base_url, connection.device_id);
    const auto response =
        request.Get(url, Headers(connection), Common::HttpRequest::AllowedReturnCodes::All);
    if (!response)
    {
      SetStatus("EmuBank server could not be reached.");
      DisplaySyncMessage("EmuBank could not reach the server", 5000, OsdTone::Error);
      return std::nullopt;
    }
    if (!ConnectionStillConfigured(connection))
      return std::nullopt;
    if (request.GetLastResponseCode() == 401)
    {
      SetStatus("EmuBank rejected the device token.");
      DisplaySyncMessage("EmuBank authorization was rejected", 5000, OsdTone::Error);
      return std::nullopt;
    }
    if (request.GetLastResponseCode() != 200)
    {
      SetStatus(fmt::format("EmuBank manifest failed (HTTP {}).", request.GetLastResponseCode()));
      DisplaySyncMessage("EmuBank could not check cloud saves", 5000, OsdTone::Error);
      return std::nullopt;
    }

    auto manifest = ParseManifest(*response, m_sync_deadline, connection.gamecube_save_root,
                                  connection.wii_save_root);
    if (!manifest)
    {
      SetStatus("EmuBank returned an invalid device manifest.");
      DisplaySyncMessage("EmuBank returned an invalid save list", 5000, OsdTone::Error);
    }
    return manifest;
  }

  std::string RecoveryJournalPath() const { return m_config_root + "EmuBankRecovery.json"; }

  static bool ProcessLockIdentityLess(const FileIdentity& left, const FileIdentity& right)
  {
    if (left.volume != right.volume)
      return left.volume < right.volume;
#if defined(_WIN32)
    if (left.namespace_id != right.namespace_id)
      return left.namespace_id < right.namespace_id;
#endif
    return left.file < right.file;
  }

  std::optional<std::vector<ProcessLockDirectoryCandidate>> InspectProcessLockDirectories()
  {
    namespace fs = std::filesystem;
    std::vector<std::pair<fs::path, bool>> configured_directories{
        {StringToPath(m_config_root), true},
        {StringToPath(m_gamecube_save_root), true},
        {StringToPath(EffectiveWiiSaveRoot()), true}};
    configured_directories.reserve(configured_directories.size() + m_recovery_blocks.size());
    for (const auto& [canonical_key, recovery] : m_recovery_blocks)
    {
      (void)canonical_key;
      const auto components = ParseSavePathComponents(recovery.relative_path);
      if (!components ||
          !IsSafeRecoveryCanonicalPath(recovery.relative_path, recovery.canonical_path))
      {
        return std::nullopt;
      }
      fs::path recovery_root = StringToPath(recovery.canonical_path);
      for (size_t component = 1; component < components->size(); ++component)
        recovery_root = recovery_root.parent_path();
      configured_directories.emplace_back(std::move(recovery_root), false);
    }
    std::vector<ProcessLockDirectoryCandidate> candidates;
    candidates.reserve(configured_directories.size());
    for (auto& [requested_path, create_if_missing] : configured_directories)
    {
      fs::path configured_path = requested_path.lexically_normal();
      if (configured_path.empty() || !configured_path.is_absolute())
        return std::nullopt;
      if (create_if_missing &&
          !File::CreateFullPath(PathToString(configured_path / "EmuBankSync.lock")))
      {
        return std::nullopt;
      }

      std::error_code canonical_error;
      const fs::path canonical_path = fs::weakly_canonical(configured_path, canonical_error);
      std::error_code status_error;
      if (canonical_error || !fs::is_directory(canonical_path, status_error) || status_error)
        return std::nullopt;
      FileIdentity identity;
      if (LookupFileIdentity(canonical_path, &identity) != FileIdentityLookupResult::Exists)
        return std::nullopt;

      const auto existing = std::ranges::find_if(
          candidates, [&](const auto& candidate) { return candidate.identity == identity; });
      if (existing != candidates.end())
      {
        if (std::ranges::find(existing->configured_paths, configured_path) ==
            existing->configured_paths.end())
        {
          existing->configured_paths.emplace_back(std::move(configured_path));
        }
        continue;
      }
      candidates.push_back({identity, canonical_path, {std::move(configured_path)}});
    }
    std::ranges::sort(candidates, [](const auto& left, const auto& right) {
      return ProcessLockIdentityLess(left.identity, right.identity);
    });
    return candidates;
  }

  void UpdateRecoveryVeto()
  {
    m_canonical_recovery_required.store(
        !m_recovery_blocks.empty() ||
            m_recovery_persistence_failed.load(std::memory_order_acquire) ||
            m_recovery_journal_unreadable.load(std::memory_order_acquire) ||
            m_state_unreadable.load(std::memory_order_acquire) ||
            m_process_storage_changed.load(std::memory_order_acquire) || m_state_capacity_exceeded,
        std::memory_order_release);
  }

  FileIdentityLookupResult LookupConfigRootIdentity(FileIdentity* identity) const
  {
    const std::filesystem::path config_root = StringToPath(m_config_root).lexically_normal();
    if (config_root.empty() || !config_root.is_absolute())
      return FileIdentityLookupResult::Failed;
    return LookupFileIdentity(config_root, identity);
  }

  bool DurableStateCacheIsEmpty() const
  {
    return m_state.empty() && m_pending_uploads.empty() && m_recovery_generation == 0 &&
           m_recovery_blocks.empty() && !m_ancestor_invalidation_pending &&
           !m_ancestor_invalidation_selectors_complete &&
           m_ancestor_invalidation_game_selectors.empty() &&
           m_ancestor_invalidation_path_selectors.empty() &&
           !m_recovery_persistence_failed.load(std::memory_order_acquire) &&
           !m_recovery_journal_unreadable.load(std::memory_order_acquire) &&
           !m_state_unreadable.load(std::memory_order_acquire) &&
           !m_state_capacity_exceeded.load(std::memory_order_acquire);
  }

  bool ConfigNamespaceMatchesDurableStateSource()
  {
    FileIdentity current_identity;
    const FileIdentityLookupResult lookup = LookupConfigRootIdentity(&current_identity);
    if (m_durable_state_config_identity)
    {
      if (lookup == FileIdentityLookupResult::Exists &&
          current_identity == *m_durable_state_config_identity)
      {
        return true;
      }
      if (lookup != FileIdentityLookupResult::Exists)
        return false;
    }
    else if (m_durable_state_config_was_missing && DurableStateCacheIsEmpty() &&
             (lookup == FileIdentityLookupResult::Missing ||
              lookup == FileIdentityLookupResult::Exists))
    {
      // A genuinely fresh profile may have its Config directory created between manager
      // construction and first admission. The locked authoritative reload below will discover
      // any state another process published there and expand the full root set before use.
      return true;
    }
    else if (lookup != FileIdentityLookupResult::Exists)
    {
      return false;
    }

    // A different extant Config directory is a different recovery authority. Never let a
    // long-running process silently adopt it after caching state from the original namespace.
    m_process_storage_changed.store(true, std::memory_order_release);
    m_canonical_recovery_required.store(true, std::memory_order_release);
    return false;
  }

  void ReloadDurableState()
  {
    FileIdentity config_identity_before;
    const FileIdentityLookupResult config_lookup_before =
        LookupConfigRootIdentity(&config_identity_before);
    const u64 previous_recovery_generation = m_recovery_generation;
    const auto previous_recovery_blocks = m_recovery_blocks;

    m_state_server_url.clear();
    m_state_device_id.clear();
    m_state.clear();
    m_pending_uploads.clear();
    m_recovery_blocks.clear();
    m_recovery_generation = 0;
    m_ancestor_invalidation_pending = false;
    m_ancestor_invalidation_selectors_complete = false;
    m_ancestor_invalidation_game_selectors.clear();
    m_ancestor_invalidation_path_selectors.clear();
    m_state_dirty = false;
    m_recovery_persistence_failed.store(false, std::memory_order_release);
    m_recovery_journal_unreadable.store(false, std::memory_order_release);
    m_state_unreadable.store(false, std::memory_order_release);
    m_state_capacity_exceeded = false;
    LoadState();
    const bool recovery_journal_loaded = LoadRecoveryJournal();
    if (!recovery_journal_loaded)
    {
      m_recovery_journal_unreadable.store(true, std::memory_order_release);
      ERROR_LOG_FMT(CORE,
                    "EmuBank: save recovery metadata is unreadable; save mutation is blocked");
    }

    // Recovery generations are monotonic within one Config namespace. A missing/rolled-back pair
    // of files must not discharge an armed quarantine cached by this process; only a valid higher
    // generation may replace it, while an equal generation must describe the exact same map.
    if (m_recovery_generation < previous_recovery_generation ||
        (m_recovery_generation == previous_recovery_generation &&
         m_recovery_blocks != previous_recovery_blocks))
    {
      m_recovery_generation = previous_recovery_generation;
      m_recovery_blocks = previous_recovery_blocks;
      m_recovery_journal_unreadable.store(true, std::memory_order_release);
      ERROR_LOG_FMT(CORE, "EmuBank: recovery metadata rolled back; save mutation is blocked");
    }

    FileIdentity config_identity_after;
    const FileIdentityLookupResult config_lookup_after =
        LookupConfigRootIdentity(&config_identity_after);
    m_durable_state_config_identity.reset();
    m_durable_state_config_was_missing = false;
    if (config_lookup_before == FileIdentityLookupResult::Exists &&
        config_lookup_after == FileIdentityLookupResult::Exists &&
        config_identity_before == config_identity_after)
    {
      m_durable_state_config_identity = config_identity_after;
    }
    else if (config_lookup_before == FileIdentityLookupResult::Missing &&
             config_lookup_after == FileIdentityLookupResult::Missing)
    {
      m_durable_state_config_was_missing = true;
    }
    UpdateRecoveryVeto();
  }

  bool ReloadDurableStateUnderConfigLock(std::chrono::steady_clock::time_point deadline)
  {
    namespace fs = std::filesystem;
    if (!m_durable_state_config_identity)
      return false;

    const FileIdentity source_identity = *m_durable_state_config_identity;
    const fs::path configured_path = StringToPath(m_config_root).lexically_normal();
    if (configured_path.empty() || !configured_path.is_absolute())
      return false;

    FileIdentity current_identity;
    if (LookupFileIdentity(configured_path, &current_identity) !=
            FileIdentityLookupResult::Exists ||
        current_identity != source_identity)
    {
      return false;
    }
    std::error_code canonical_error;
    const fs::path canonical_path = fs::weakly_canonical(configured_path, canonical_error);
    std::error_code status_error;
    if (canonical_error || !fs::is_directory(canonical_path, status_error) || status_error ||
        LookupFileIdentity(canonical_path, &current_identity) != FileIdentityLookupResult::Exists ||
        current_identity != source_identity)
    {
      return false;
    }

    InterprocessSyncLock config_lock(PathToString(canonical_path / "EmuBankSync.lock"));
    if (!config_lock.TryLockUntil(deadline) || config_lock.DirectoryIdentity() != source_identity ||
        !config_lock.StillOwnsConfiguredDirectory() ||
        LookupFileIdentity(configured_path, &current_identity) !=
            FileIdentityLookupResult::Exists ||
        current_identity != source_identity)
    {
      return false;
    }

    ReloadDurableState();
    const bool stable = config_lock.StillOwnsConfiguredDirectory() &&
                        LookupFileIdentity(configured_path, &current_identity) ==
                            FileIdentityLookupResult::Exists &&
                        current_identity == source_identity &&
                        m_durable_state_config_identity == source_identity;
    if (!stable)
    {
      m_process_storage_changed.store(true, std::memory_order_release);
      m_canonical_recovery_required.store(true, std::memory_order_release);
    }
    return stable;
  }

  bool EnsureProcessLock(std::chrono::steady_clock::time_point deadline)
  {
    // From this publication onward a root-setting callback is restart-only, including while the
    // first authoritative lock set is still being stabilized. This closes the final-check-to-Core
    // window without reversing the Config-callback/install-lock order.
    m_process_lock_admission_started.store(true, std::memory_order_release);
    const bool locks_preexisted = !m_process_locks.empty();
    bool lock_set_committed = locks_preexisted;
    Common::ScopeGuard tentative_lock_guard{[this, locks_preexisted, &lock_set_committed] {
      if (!locks_preexisted && !lock_set_committed)
      {
        m_active_process_lock_aliases.clear();
        m_process_locks.clear();
      }
    }};
    bool config_refresh_available = !locks_preexisted;
    for (size_t attempt = 0; attempt < MAX_PROCESS_LOCK_STABILIZATION_ATTEMPTS; ++attempt)
    {
      if (!ProcessStorageStillStable() ||
          (!locks_preexisted && !ConfigNamespaceMatchesDurableStateSource()))
        return false;

      const auto candidates = InspectProcessLockDirectories();
      if (!candidates)
      {
        // A long-running process can still hold a constructor snapshot that names a recovery root
        // another process has since cleared from the durable journal and removed. Permit one
        // Config-serialized, pre-full-set refresh so that stale snapshot cannot veto first
        // admission forever. If the refreshed journal still names an unavailable root, fail
        // closed.
        if (config_refresh_available)
        {
          config_refresh_available = false;
          if (ReloadDurableStateUnderConfigLock(deadline))
            continue;
        }
        return false;
      }
      config_refresh_available = false;
      const size_t new_lock_count = std::ranges::count_if(*candidates, [&](const auto& candidate) {
        return std::ranges::none_of(m_process_locks, [&](const auto& process_lock) {
          return process_lock->DirectoryIdentity() == candidate.identity;
        });
      });
      // Lifetime retention is what protects save descriptors already opened by Core. Acquiring a
      // newly configured root after that point would permit two profiles to cross from A->B and
      // B->A while permanently retaining the opposite locks. Require a restart so every process
      // acquires its complete Config/GC/Wii/recovery identity set in the same global order.
      if (locks_preexisted && new_lock_count != 0)
      {
        m_process_storage_changed.store(true, std::memory_order_release);
        m_canonical_recovery_required.store(true, std::memory_order_release);
        return false;
      }
      if (m_process_locks.size() + new_lock_count > MAX_PROCESS_LOCK_DIRECTORIES)
        return false;

      std::vector<std::unique_ptr<InterprocessSyncLock>> acquired_locks;
      acquired_locks.reserve(new_lock_count);
      for (const ProcessLockDirectoryCandidate& candidate : *candidates)
      {
        const bool already_locked =
            std::ranges::any_of(m_process_locks, [&](const auto& process_lock) {
              return process_lock->DirectoryIdentity() == candidate.identity;
            });
        if (already_locked)
          continue;
        auto process_lock = std::make_unique<InterprocessSyncLock>(
            PathToString(candidate.canonical_path / "EmuBankSync.lock"));
        if (!process_lock->TryLockUntil(deadline) ||
            process_lock->DirectoryIdentity() != candidate.identity)
        {
          return false;
        }
        acquired_locks.emplace_back(std::move(process_lock));
      }

      std::vector<ProcessLockDirectoryAlias> active_aliases;
      for (const ProcessLockDirectoryCandidate& candidate : *candidates)
      {
        for (const std::filesystem::path& configured_path : candidate.configured_paths)
        {
          FileIdentity current_identity;
          if (LookupFileIdentity(configured_path, &current_identity) !=
                  FileIdentityLookupResult::Exists ||
              current_identity != candidate.identity)
          {
            return false;
          }
          active_aliases.push_back({configured_path, candidate.identity});
        }
      }
      if (std::ranges::any_of(acquired_locks,
                              [](const auto& process_lock) {
                                return !process_lock->StillOwnsConfiguredDirectory();
                              }) ||
          !ProcessStorageStillStable())
      {
        return false;
      }

      const bool first_lock_acquisition = m_process_locks.empty();
      for (auto& process_lock : acquired_locks)
        m_process_locks.emplace_back(std::move(process_lock));
      m_active_process_lock_aliases = std::move(active_aliases);
      if (!first_lock_acquisition)
      {
        const bool stable = ProcessStorageStillStable();
        if (stable)
          lock_set_committed = true;
        return stable;
      }

      // The constructor's unlocked cache may be stale. Reload while Config is excluded, then
      // verify that every old root named by the authoritative recovery journal was in the sorted
      // set. If not, release the whole tentative set and retry from that complete snapshot; no
      // namespace mutation or Core launch has yet been admitted.
      ReloadDurableState();
      if (!ProcessStorageStillStable() || !ConfigNamespaceMatchesDurableStateSource())
      {
        m_active_process_lock_aliases.clear();
        m_process_locks.clear();
        return false;
      }
      const auto authoritative_candidates = InspectProcessLockDirectories();
      if (!authoritative_candidates)
      {
        m_active_process_lock_aliases.clear();
        m_process_locks.clear();
        return false;
      }
      const bool authoritative_set_is_locked =
          std::ranges::all_of(*authoritative_candidates, [&](const auto& candidate) {
            return std::ranges::any_of(m_process_locks, [&](const auto& process_lock) {
              return process_lock->DirectoryIdentity() == candidate.identity;
            });
          });
      if (!authoritative_set_is_locked)
      {
        m_active_process_lock_aliases.clear();
        m_process_locks.clear();
      }
      // Re-run once even when the identities were complete so the active lexical-alias set comes
      // from the locked, authoritative journal rather than the constructor snapshot.
    }

    if (!locks_preexisted)
    {
      m_active_process_lock_aliases.clear();
      m_process_locks.clear();
    }
    return false;
  }

  bool SaveRecoveryJournal()
  {
    if (!ProcessStorageStillStable())
      return false;
    picojson::object recovery_required;
    for (const auto& [canonical_key, recovery] : m_recovery_blocks)
    {
      (void)canonical_key;
      recovery_required.emplace(
          recovery.canonical_path,
          picojson::value{picojson::object{
              {"relative_path", picojson::value{recovery.relative_path}},
              {"canonical_path", picojson::value{recovery.canonical_path}},
              {"required_sha256", picojson::value{recovery.required_sha256}},
              {"cloud_reinstall_allowed", picojson::value{recovery.cloud_reinstall_allowed}}}});
    }
    const std::string json =
        picojson::value{
            picojson::object{
                {"version", picojson::value{1.0}},
                {"generation", picojson::value{static_cast<double>(m_recovery_generation)}},
                {"recovery_required", picojson::value{std::move(recovery_required)}}}}
            .serialize(true);
    if (json.size() > MAX_RECOVERY_JOURNAL_FILE_SIZE)
    {
      ERROR_LOG_FMT(CORE, "EmuBank: refused to write oversized canonical recovery journal");
      return false;
    }
    const std::span<const u8> bytes{reinterpret_cast<const u8*>(json.data()), json.size()};
    if (WriteAtomically(RecoveryJournalPath(), bytes))
      return true;
    ERROR_LOG_FMT(CORE, "EmuBank: failed to save canonical recovery journal");
    return false;
  }

  bool LoadRecoveryJournal()
  {
    std::error_code status_error;
    const std::filesystem::file_status journal_status =
        std::filesystem::symlink_status(StringToPath(RecoveryJournalPath()), status_error);
    if (journal_status.type() == std::filesystem::file_type::not_found)
      return m_recovery_generation == 0 && m_recovery_blocks.empty();
    if (status_error || !std::filesystem::is_regular_file(journal_status))
      return false;
    std::error_code journal_size_error;
    const uintmax_t journal_size =
        std::filesystem::file_size(StringToPath(RecoveryJournalPath()), journal_size_error);
    if (journal_size_error || journal_size > MAX_RECOVERY_JOURNAL_FILE_SIZE)
      return false;

    picojson::value root;
    std::string error;
    if (!JsonFromFile(RecoveryJournalPath(), &root, &error) || !root.is<picojson::object>())
      return false;

    const picojson::object& root_object = root.get<picojson::object>();
    const std::optional<double> version = ObjectNumber(root_object, "version");
    const std::optional<double> generation_value = ObjectNumber(root_object, "generation");
    const picojson::object* recovery_required = ObjectValue(root_object, "recovery_required");
    if (!version || *version != 1.0 || !generation_value || *generation_value < 0.0 ||
        *generation_value > 9007199254740991.0 ||
        std::floor(*generation_value) != *generation_value || !recovery_required ||
        recovery_required->size() > MAX_RECOVERY_BLOCKS)
    {
      return false;
    }

    std::map<std::string, RecoveryBlock, std::less<>> journal_recovery;
    std::vector<CanonicalPathAliasInfo> journal_recovery_aliases;
    journal_recovery_aliases.reserve(recovery_required->size());
    for (const auto& [canonical_key, value] : *recovery_required)
    {
      if (!value.is<picojson::object>())
        return false;
      const picojson::object& recovery_object = value.get<picojson::object>();
      const std::string relative_path = ObjectString(recovery_object, "relative_path").value_or("");
      const std::string canonical_path =
          ObjectString(recovery_object, "canonical_path").value_or("");
      std::string required_sha256 = ObjectString(recovery_object, "required_sha256").value_or("");
      Common::ToLower(&required_sha256);
      const bool cloud_reinstall_allowed =
          ReadBoolFromJson(recovery_object, "cloud_reinstall_allowed").value_or(false);
      if (canonical_key != canonical_path || !IsSha256(required_sha256) ||
          !IsSafeRecoveryCanonicalPath(relative_path, canonical_path))
        return false;
      CanonicalPathAliasInfo alias_info = InspectCanonicalPathForAliases(canonical_path);
      if (std::ranges::any_of(journal_recovery_aliases,
                              [&](const CanonicalPathAliasInfo& existing) {
                                return CanonicalPathAliasInfosMayAlias(existing, alias_info);
                              }))
      {
        // Distinct persisted spellings may still identify one path on a case-folding or
        // normalization-aware filesystem. No recovery hash may win that ambiguity.
        return false;
      }
      if (!journal_recovery
               .emplace(RecoveryPathKey(canonical_path),
                        RecoveryBlock{relative_path, canonical_path, std::move(required_sha256),
                                      cloud_reinstall_allowed})
               .second)
      {
        // Distinct JSON keys may fold to the same Windows pathname. No single recovery hash may
        // silently win that ambiguity.
        return false;
      }
      journal_recovery_aliases.emplace_back(std::move(alias_info));
    }

    const u64 journal_generation = static_cast<u64>(*generation_value);
    if (journal_generation > m_recovery_generation)
    {
      m_recovery_generation = journal_generation;
      m_recovery_blocks = std::move(journal_recovery);
    }
    else if (journal_generation == m_recovery_generation)
    {
      // Equal generations are two copies of the same write-ahead record. Any difference is
      // corruption or an interrupted/manual rewrite and must fail closed instead of selecting one
      // required hash.
      if (journal_recovery != m_recovery_blocks)
        return false;
    }
    else
    {
      // The journal is the process-to-process authority and is written before the state copy. A
      // newer state generation therefore proves the authoritative write did not commit.
      return false;
    }
    return true;
  }

  void PersistRecoveryMapChange()
  {
    ++m_recovery_generation;
    m_canonical_recovery_required.store(!m_recovery_blocks.empty(), std::memory_order_release);
    m_state_dirty = true;
    const bool journal_saved = SaveRecoveryJournal();
    SaveState();
    // The independent journal is the process-to-process authority. The state copy remains a
    // redundant crash record, but a state-only pre-arm may not authorize namespace mutation.
    m_recovery_persistence_failed.store(!journal_saved, std::memory_order_release);
    UpdateRecoveryVeto();
  }

  void RetryRecoveryPersistence()
  {
    if (m_recovery_journal_unreadable.load(std::memory_order_acquire) ||
        !m_recovery_persistence_failed.load(std::memory_order_acquire))
      return;
    const bool journal_saved = SaveRecoveryJournal();
    m_state_dirty = true;
    SaveState();
    m_recovery_persistence_failed.store(!journal_saved, std::memory_order_release);
    UpdateRecoveryVeto();
  }

  bool RequireCanonicalRecovery(const Binding& binding, const std::string& canonical_path,
                                const std::string& required_sha256, bool cloud_reinstall_allowed,
                                bool report_recovery = true)
  {
    if (!IsSha256(required_sha256) ||
        !IsSafeRecoveryCanonicalPath(binding.relative_path, canonical_path))
    {
      ERROR_LOG_FMT(CORE, "EmuBank: could not identify the retained recovery body for '{}'",
                    binding.relative_path);
      return false;
    }

    const std::string recovery_key = RecoveryPathKey(canonical_path);
    const auto existing_key = m_recovery_blocks.find(recovery_key);
    const RecoveryBlock requested_block{binding.relative_path, canonical_path, required_sha256,
                                        cloud_reinstall_allowed};
    if (existing_key != m_recovery_blocks.end() && existing_key->second == requested_block)
    {
      // Retrying an already armed transaction is not a new generation. This keeps a missing-file
      // publication failure from rewriting both durable records every cadence; a prior failed
      // journal write is retried explicitly without changing the recovery meaning.
      RetryRecoveryPersistence();
      const bool persisted = !m_recovery_persistence_failed.load(std::memory_order_acquire);
      if (report_recovery || !persisted)
      {
        SetStatus(fmt::format(
            "EmuBank blocked launch because {} needs save-path recovery. Restore the retained "
            "copy from Config/EmuBankBackups, or repair storage and sync again.",
            BindingDisplayName(binding.relative_path)));
      }
      return persisted;
    }
    const CanonicalPathAliasInfo requested_alias =
        InspectCanonicalPathForAliases(canonical_path, m_sync_deadline);
    if ((existing_key == m_recovery_blocks.end() &&
         m_recovery_blocks.size() >= MAX_RECOVERY_BLOCKS) ||
        (existing_key != m_recovery_blocks.end() &&
         existing_key->second.canonical_path != canonical_path) ||
        std::ranges::any_of(m_recovery_blocks, [&](const auto& existing) {
          if (existing.first == recovery_key)
            return false;
          const CanonicalPathAliasInfo existing_alias =
              InspectCanonicalPathForAliases(existing.second.canonical_path, m_sync_deadline);
          return CanonicalPathAliasInfosMayAlias(existing_alias, requested_alias);
        }))
    {
      ERROR_LOG_FMT(CORE, "EmuBank: refused an ambiguous or excessive recovery target for '{}'",
                    binding.relative_path);
      return false;
    }

    m_recovery_blocks.insert_or_assign(std::move(recovery_key), requested_block);
    PersistRecoveryMapChange();
    const bool persisted = !m_recovery_persistence_failed.load(std::memory_order_acquire);
    if (report_recovery || !persisted)
    {
      SetStatus(fmt::format(
          "EmuBank blocked launch because {} needs save-path recovery. Restore the retained copy "
          "from Config/EmuBankBackups, or repair storage and sync again.",
          BindingDisplayName(binding.relative_path)));
    }
    return persisted;
  }

  bool ClearCanonicalRecovery(std::string_view canonical_path)
  {
    const auto recovery = m_recovery_blocks.find(RecoveryPathKey(std::string{canonical_path}));
    if (recovery != m_recovery_blocks.end())
    {
      m_recovery_blocks.erase(recovery);
      PersistRecoveryMapChange();
    }
    return !m_recovery_persistence_failed.load(std::memory_order_acquire) &&
           !m_recovery_journal_unreadable.load(std::memory_order_acquire);
  }

  void RefreshCanonicalRecoveryBlocks(SyncMode mode)
  {
    if (mode == SyncMode::Live || m_emulation_active.load(std::memory_order_acquire) ||
        (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)))
    {
      return;
    }
    std::lock_guard install_lock(m_save_install_mutex);
    if (m_emulation_active.load(std::memory_order_acquire) ||
        (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)) ||
        !ProcessStorageStillStable())
    {
      return;
    }
    const ConfirmationBudget budget{
        m_sync_deadline, mode == SyncMode::BeforeLaunch ? nullptr : &m_launch_pending, &m_shutdown};
    if (budget.Expired() || m_recovery_blocks.empty())
      return;

    // Inspect one record per pass. A 512-entry journal on a slow save root must not monopolize the
    // install barrier, and rotating the cursor prevents one wrong-hash body from starving later
    // manually restored records. Unvisited records remain an exact global launch veto.
    auto recovery = m_recovery_blocks.upper_bound(m_last_recovery_check_key);
    if (recovery == m_recovery_blocks.end())
      recovery = m_recovery_blocks.begin();
    m_last_recovery_check_key = recovery->first;
    if (!DurablyConfirmFileAtPath(recovery->second.canonical_path, recovery->second.required_sha256,
                                  &budget) ||
        !ProcessStorageStillStable())
    {
      return;
    }
    m_recovery_blocks.erase(recovery);
    PersistRecoveryMapChange();
  }

  bool BindingPathOwnershipIsUniqueNow(const Connection& connection, const Binding& binding,
                                       const Manifest& manifest,
                                       const CanonicalPathAliasInfo& current_path)
  {
    for (const Binding& other : manifest.bindings)
    {
      if (other.id == binding.id)
        continue;
      if (std::chrono::steady_clock::now() >= m_sync_deadline)
        return false;
      const auto other_path = ResolveSavePath(other.relative_path, connection.gamecube_save_root,
                                              connection.wii_save_root);
      if (!other_path)
        return false;
      const CanonicalPathAliasInfo other_alias =
          InspectCanonicalPathForAliases(*other_path, m_sync_deadline);
      if (CanonicalPathAliasInfosMayAlias(current_path, other_alias))
        return false;
    }
    return true;
  }

  bool Download(const Connection& connection, const Binding& binding, const Manifest& manifest,
                const Revision& revision, const std::string& path,
                const std::optional<std::string>& expected_local_sha256,
                const FileSnapshot* local_backup, SyncMode mode, SyncStats* stats,
                bool preserve_conflict = false)
  {
    if (!ConnectionStillConfigured(connection))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return false;
    }
    const CanonicalPathAliasInfo download_path_identity =
        InspectCanonicalPathForAliases(path, m_sync_deadline);
    if (!download_path_identity.safe || !download_path_identity.lookup_succeeded)
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return false;
    }
    SetStatus(fmt::format("EmuBank is downloading {}…", BindingDisplayName(binding.relative_path)));
    Common::HttpRequest request(
        HttpTimeoutUntil(m_sync_deadline),
        LimitTransfer(MAX_SAVE_SIZE, 0, m_sync_deadline,
                      mode == SyncMode::BeforeLaunch ? nullptr : &m_launch_pending,
                      &m_config_changed_during_sync));
    const auto response =
        request.Get(BindingUrl(connection, binding) + "/download", Headers(connection),
                    Common::HttpRequest::AllowedReturnCodes::All);
    if (!response || request.GetLastResponseCode() != 200)
    {
      if (!ConnectionStillConfigured(connection))
      {
        ++stats->deferred;
        stats->retry_needed = true;
        return false;
      }
      ERROR_LOG_FMT(CORE, "EmuBank: failed to download '{}' (HTTP {})", binding.relative_path,
                    request.GetLastResponseCode());
      ++stats->errors;
      DisplaySyncMessage(
          fmt::format("EmuBank failed to download {}", BindingDisplayName(binding.relative_path)),
          5000, OsdTone::Error);
      return false;
    }
    if (!ConnectionStillConfigured(connection))
    {
      ++stats->deferred;
      stats->retry_needed = true;
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
    if (downloaded_revision.id != revision.id || downloaded_revision.sha256 != revision.sha256 ||
        downloaded_revision.size != revision.size)
    {
      INFO_LOG_FMT(CORE,
                   "EmuBank: '{}' advanced after the manifest was read; deferring the download "
                   "until the newer revision can be reconciled",
                   binding.relative_path);
      SetStatus(fmt::format("EmuBank found a newer cloud revision for {}; checking it next pass.",
                            BindingDisplayName(binding.relative_path)));
      ++stats->deferred;
      return false;
    }

    std::string lowercase_path = binding.relative_path;
    Common::ToLower(&lowercase_path);
    if (lowercase_path.ends_with(".gci") && !ValidateGciContents(*response, binding.game_id))
    {
      ERROR_LOG_FMT(CORE,
                    "EmuBank: rejected structurally invalid or wrong-game GCI download for '{}'",
                    binding.relative_path);
      SetStatus(fmt::format("EmuBank refused a wrong-game or invalid GCI save for {}.",
                            BindingDisplayName(binding.relative_path)));
      DisplaySyncMessage("EmuBank refused an invalid or wrong-game cloud GCI", 6000,
                         OsdTone::Error);
      ++stats->errors;
      return false;
    }

    const bool local_exists_now = File::IsFile(path);
    const std::optional<FileSnapshot> local_now =
        local_exists_now ? ReadSaveFile(path) : std::nullopt;
    const bool local_is_unchanged = expected_local_sha256 ?
                                        local_now && local_now->sha256 == *expected_local_sha256 :
                                        !local_exists_now;
    if (!local_is_unchanged)
    {
      WARN_LOG_FMT(CORE,
                   "EmuBank: retained '{}' because it changed locally while the cloud revision "
                   "was downloading",
                   binding.relative_path);
      SetStatus(fmt::format("EmuBank kept a newer local change to {}; sync will compare it again.",
                            BindingDisplayName(binding.relative_path)));
      DisplaySyncMessage("EmuBank kept a save that changed during sync", 6000, OsdTone::Warning);
      ++stats->deferred;
      return false;
    }
    if (local_backup && !PreserveLocalBackup(binding, *local_backup))
    {
      ERROR_LOG_FMT(CORE, "EmuBank: could not preserve the local copy of '{}' before replacement",
                    binding.relative_path);
      SetStatus(fmt::format("EmuBank kept {} because its safety backup could not be written.",
                            BindingDisplayName(binding.relative_path)));
      ++stats->errors;
      return false;
    }
    if (local_backup)
    {
      INFO_LOG_FMT(CORE,
                   "EmuBank: preserved the prior local '{}' under Config/EmuBankBackups before "
                   "installing the selected cloud revision",
                   binding.relative_path);
    }

    const auto prepared_path_check = ResolveSavePath(
        binding.relative_path, connection.gamecube_save_root, connection.wii_save_root);
    const CanonicalPathAliasInfo prepared_path_identity =
        prepared_path_check ?
            InspectCanonicalPathForAliases(*prepared_path_check, m_sync_deadline) :
            CanonicalPathAliasInfo{};
    if (!prepared_path_check || CanonicalPathKey(*prepared_path_check) != CanonicalPathKey(path) ||
        !CanonicalPathAliasInfoMatchesSnapshot(download_path_identity, prepared_path_identity) ||
        !BindingPathOwnershipIsUniqueNow(connection, binding, manifest, prepared_path_identity))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return false;
    }

    // Build and flush the replacement before the final local hash check. The commit below is then
    // only a rename, rather than a potentially long write window in which a second process could
    // update the local save after it was verified.
    const auto temporary_path = PrepareAtomicWrite(path, *response);
    if (!temporary_path)
    {
      ERROR_LOG_FMT(CORE, "EmuBank: failed to prepare replacement for local save '{}'",
                    binding.relative_path);
      ++stats->errors;
      return false;
    }
    Common::ScopeGuard temporary_file_guard{[&temporary_path] {
      File::Delete(*temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
    }};
    const auto post_prepare_path_check = ResolveSavePath(
        binding.relative_path, connection.gamecube_save_root, connection.wii_save_root);
    const CanonicalPathAliasInfo post_prepare_path_identity =
        post_prepare_path_check ?
            InspectCanonicalPathForAliases(*post_prepare_path_check, m_sync_deadline) :
            CanonicalPathAliasInfo{};
    if (!post_prepare_path_check ||
        CanonicalPathKey(*post_prepare_path_check) != CanonicalPathKey(path) ||
        !post_prepare_path_identity.safe || !post_prepare_path_identity.lookup_succeeded ||
        !BindingPathOwnershipIsUniqueNow(connection, binding, manifest, post_prepare_path_identity))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return false;
    }

    // A pass can have captured Idle before launch began. Serialize the final install with the
    // pre-boot barrier and recheck both the lifecycle and local bytes while holding it. This makes
    // the old mode snapshot incapable of authorizing a write into a save Core is opening.
    std::lock_guard install_lock(m_save_install_mutex);
    if (mode != SyncMode::BeforeLaunch && (m_launch_pending.load(std::memory_order_acquire) ||
                                           m_emulation_active.load(std::memory_order_acquire)))
    {
      INFO_LOG_FMT(CORE, "EmuBank: deferred installing '{}' because launch or emulation began",
                   binding.relative_path);
      ++stats->deferred;
      return false;
    }
    if (!ConnectionStillConfigured(connection))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return false;
    }
    const auto final_path_check = ResolveSavePath(
        binding.relative_path, connection.gamecube_save_root, connection.wii_save_root);
    const CanonicalPathAliasInfo final_path_identity =
        final_path_check ? InspectCanonicalPathForAliases(*final_path_check, m_sync_deadline) :
                           CanonicalPathAliasInfo{};
    if (!final_path_check || CanonicalPathKey(*final_path_check) != CanonicalPathKey(path) ||
        !CanonicalPathAliasInfoMatchesSnapshot(post_prepare_path_identity, final_path_identity) ||
        !BindingPathOwnershipIsUniqueNow(connection, binding, manifest, final_path_identity))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return false;
    }

    if (!expected_local_sha256)
    {
      std::error_code target_status_error;
      const std::filesystem::file_status target_status =
          std::filesystem::symlink_status(StringToPath(path), target_status_error);
      if (target_status.type() != std::filesystem::file_type::not_found)
      {
        ERROR_LOG_FMT(CORE,
                      "EmuBank: refused to publish missing save '{}' over an existing non-file "
                      "target",
                      binding.relative_path);
        SetStatus(fmt::format(
            "EmuBank kept {} unchanged because its target is not an absent regular-save path.",
            BindingDisplayName(binding.relative_path)));
        ++stats->errors;
        stats->retry_needed = true;
        return false;
      }
    }

    const bool local_exists_before_install = File::IsFile(path);
    const std::optional<FileSnapshot> local_before_install =
        local_exists_before_install ? ReadSaveFile(path) : std::nullopt;
    const bool local_is_still_unchanged =
        expected_local_sha256 ?
            local_before_install && local_before_install->sha256 == *expected_local_sha256 :
            !local_exists_before_install;
    if (!local_is_still_unchanged)
    {
      WARN_LOG_FMT(CORE,
                   "EmuBank: retained '{}' because it changed before the cloud revision could be "
                   "installed",
                   binding.relative_path);
      SetStatus(fmt::format("EmuBank kept a newer local change to {}; sync will compare it again.",
                            BindingDisplayName(binding.relative_path)));
      ++stats->deferred;
      return false;
    }

    const bool cloud_reinstall_allowed = !expected_local_sha256.has_value();
    const std::string transaction_recovery_sha256 =
        expected_local_sha256.value_or(downloaded_revision.sha256);
    const auto report_changed_before_commit = [&] {
      WARN_LOG_FMT(CORE,
                   "EmuBank: retained '{}' because it changed during the atomic cloud install",
                   binding.relative_path);
      SetStatus(fmt::format("EmuBank kept a newer local change to {}; sync will compare it again.",
                            BindingDisplayName(binding.relative_path)));
      ++stats->deferred;
    };
    const auto require_recovery_for_unsafe_path = [&](const std::string& required_sha256) {
      RequireCanonicalRecovery(binding, path, required_sha256, cloud_reinstall_allowed);
      if (mode == SyncMode::BeforeLaunch)
      {
        Core::RequestBootCancellation();
        DisplaySyncMessage("EmuBank retained the local save, but launch was canceled for recovery",
                           8000, OsdTone::Error);
      }
    };

    if (expected_local_sha256 && !FlushFileData(path))
    {
      ERROR_LOG_FMT(CORE, "EmuBank: could not flush local '{}' before replacement",
                    binding.relative_path);
      ++stats->errors;
      return false;
    }

    // Write-ahead quarantine: a power loss immediately after the first namespace mutation must
    // not leave a cloud or missing canonical path that a later boot silently accepts. If neither
    // redundant recovery record can be committed, leave the verified local namespace untouched.
    const bool recovery_preexisted = m_recovery_blocks.contains(RecoveryPathKey(path));
    if (!RequireCanonicalRecovery(binding, path, transaction_recovery_sha256,
                                  cloud_reinstall_allowed, false))
    {
      ERROR_LOG_FMT(CORE, "EmuBank: refused to mutate '{}' without a durable recovery transaction",
                    binding.relative_path);
      ++stats->errors;
      return false;
    }
    if (!ConnectionStillConfigured(connection))
    {
      // No namespace mutation has occurred in this attempt. Remove only a recovery pre-arm created
      // by this attempt; an older interrupted transaction remains credential-independent and must
      // keep blocking launch across account/enablement changes.
      if (!recovery_preexisted)
        ClearCanonicalRecovery(path);
      ++stats->deferred;
      stats->retry_needed = true;
      return false;
    }

    if (expected_local_sha256)
    {
      const AtomicExchangeResult exchange_result =
          ExchangeFilesAtomically(*temporary_path, path, *expected_local_sha256);
      if (exchange_result.commit != NamespaceCommitResult::Failed)
      {
        // displaced_path now names the exact file displaced by the atomic exchange. Never let the
        // generic temp guard delete anything: another process may still be writing that inode.
        temporary_file_guard.Dismiss();
        const auto discard_unused_prepared_body = [&] {
          if (exchange_result.displaced_path == *temporary_path || !File::IsFile(*temporary_path))
          {
            return;
          }
          const auto residue = ReadSaveFile(*temporary_path);
          if (residue && residue->sha256 == downloaded_revision.sha256)
          {
            File::Delete(*temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
          }
          else
          {
            // The helper never owns this name. If an external writer replaced the prepared body,
            // retain that inode rather than treating it as disposable residue.
            PreserveDisplacedLocal(binding, *temporary_path);
          }
        };
        if (exchange_result.commit != NamespaceCommitResult::Durable)
        {
          PreserveDisplacedLocal(binding, exchange_result.displaced_path);
          discard_unused_prepared_body();
          require_recovery_for_unsafe_path(*expected_local_sha256);
          ERROR_LOG_FMT(CORE,
                        "EmuBank: atomically exchanged '{}' but could not durably sync its "
                        "directory; launch remains quarantined",
                        binding.relative_path);
          ++stats->errors;
          return false;
        }
        const auto displaced = ReadSaveFile(exchange_result.displaced_path);
        if (!displaced || displaced->sha256 != *expected_local_sha256)
        {
          // Back up the stable snapshot before any durability operation. On Windows a failed
          // write-through namespace confirmation can strand a body at its hash-bound sibling;
          // this independent content-addressed copy keeps the exact recovery bytes discoverable.
          const bool displaced_backed_up = displaced && PreserveLocalBackup(binding, *displaced);
          const bool displaced_flushed =
              displaced_backed_up && FlushFileData(exchange_result.displaced_path);
          const auto durable_displaced =
              displaced_flushed ? ReadSaveFile(exchange_result.displaced_path) : std::nullopt;
          if (!durable_displaced || durable_displaced->sha256 != displaced->sha256)
          {
            if (durable_displaced)
              PreserveLocalBackup(binding, *durable_displaced);
            if (File::IsFile(exchange_result.displaced_path))
              PreserveDisplacedLocal(binding, exchange_result.displaced_path);
            discard_unused_prepared_body();
            require_recovery_for_unsafe_path(durable_displaced ? durable_displaced->sha256 :
                                             displaced         ? displaced->sha256 :
                                                                 *expected_local_sha256);
            ERROR_LOG_FMT(CORE,
                          "EmuBank: retained a concurrent change to '{}' but could not flush it "
                          "before restoring the canonical path",
                          binding.relative_path);
            ++stats->errors;
            return false;
          }

          // The concurrent body now has an independent durable backup. Transition the journal to
          // that exact body before any exchange-back or Windows namespace confirmation can strand
          // it under a hash-bound sibling unknown to recovery.
          if (!RequireCanonicalRecovery(binding, path, durable_displaced->sha256, false, false))
          {
            discard_unused_prepared_body();
            ERROR_LOG_FMT(CORE, "EmuBank: could not arm recovery for the concurrent change to '{}'",
                          binding.relative_path);
            ++stats->errors;
            return false;
          }

          const AtomicExchangeResult restore_result = ExchangeFilesAtomically(
              exchange_result.displaced_path, path, durable_displaced->sha256);
          // After a successful exchange-back this is normally just the downloaded body. Preserve
          // it anyway because a second external rename could have put different bytes there. On
          // Windows error 1177, however, the restore source still names the required local body
          // while the downloaded body moves to a different backup name; retain both names.
          if (File::IsFile(exchange_result.displaced_path))
            PreserveDisplacedLocal(binding, exchange_result.displaced_path);
          if (restore_result.displaced_path != exchange_result.displaced_path &&
              File::IsFile(restore_result.displaced_path))
          {
            PreserveDisplacedLocal(binding, restore_result.displaced_path);
          }
          discard_unused_prepared_body();
          if (restore_result.commit == NamespaceCommitResult::Durable &&
              DurablyConfirmFileAtPath(path, durable_displaced->sha256))
          {
            if (ClearCanonicalRecovery(path))
              report_changed_before_commit();
            else
              ++stats->errors;
          }
          else
          {
            ERROR_LOG_FMT(CORE,
                          "EmuBank: retained a concurrently changed '{}' but could not durably "
                          "restore it to the original path",
                          binding.relative_path);
            SetStatus(fmt::format(
                "EmuBank retained a concurrent change to {} in its backup folder; restore it "
                "before continuing.",
                BindingDisplayName(binding.relative_path)));
            require_recovery_for_unsafe_path(durable_displaced->sha256);
            ++stats->errors;
          }
          return false;
        }

        // Moving the displaced inode into the backup tree also preserves writes made through a
        // handle that another process opened before the exchange.
        if (!PreserveDisplacedLocal(binding, exchange_result.displaced_path))
        {
          discard_unused_prepared_body();
          require_recovery_for_unsafe_path(*expected_local_sha256);
          ERROR_LOG_FMT(CORE, "EmuBank: could not durably retain displaced local '{}'",
                        binding.relative_path);
          ++stats->errors;
          return false;
        }
        discard_unused_prepared_body();
      }
      else
      {
        // A refused atomic exchange may discharge its write-ahead record only when the exact
        // pre-transaction body is still canonical. Merely seeing a pathname is not evidence that
        // an unusual filesystem/API failure left it untouched.
        if (DurablyConfirmFileAtPath(path, *expected_local_sha256))
          ClearCanonicalRecovery(path);
        else
          require_recovery_for_unsafe_path(*expected_local_sha256);
        ERROR_LOG_FMT(CORE, "EmuBank: filesystem could not atomically replace cloud save '{}'",
                      binding.relative_path);
        ++stats->errors;
        return false;
      }
    }
    else
    {
      // Publish the fully flushed body without overwriting a local file that appeared after the
      // final absence check. Hosts use no-replace rename, a hard link, a write-through Windows
      // move, or Android's exclusive-create fallback.
      NamespaceCommitResult install_result =
          PublishPreparedFileWithoutOverwrite(*temporary_path, path);
      if (install_result == NamespaceCommitResult::CommittedNotDurable)
      {
        // A missing-file publication never gives the prepared source local ownership. Delete an
        // exact cloud residue through the still-active guard; if an external actor somehow
        // replaced the secret temporary name, retain that unexpected inode instead.
        if (File::IsFile(*temporary_path))
        {
          const auto residue = ReadSaveFile(*temporary_path);
          if (!residue || residue->sha256 != downloaded_revision.sha256)
          {
            temporary_file_guard.Dismiss();
            PreserveDisplacedLocal(binding, *temporary_path);
          }
        }
        require_recovery_for_unsafe_path(downloaded_revision.sha256);
        ERROR_LOG_FMT(CORE, "EmuBank: published '{}' but could not durably sync its directory",
                      binding.relative_path);
        ++stats->errors;
        return false;
      }
      if (install_result == NamespaceCommitResult::Failed)
      {
        std::error_code canonical_status_error;
        const std::filesystem::file_status canonical_status =
            std::filesystem::symlink_status(StringToPath(path), canonical_status_error);
        const bool canonical_definitely_absent =
            canonical_status.type() == std::filesystem::file_type::not_found;
        const bool canonical_is_regular =
            !canonical_status_error && std::filesystem::is_regular_file(canonical_status);
        const auto canonical_after_failure =
            canonical_is_regular ? ReadSaveFile(path) : std::nullopt;
        if (canonical_after_failure &&
            canonical_after_failure->sha256 != downloaded_revision.sha256 &&
            !PreserveLocalBackup(binding, *canonical_after_failure))
        {
          // Bind the quarantine to the observed concurrent body, but never move that pathname
          // through a durability transaction until its exact snapshot has a durable recovery copy.
          require_recovery_for_unsafe_path(canonical_after_failure->sha256);
          ERROR_LOG_FMT(CORE,
                        "EmuBank: could not preserve the concurrent save that appeared at '{}'",
                        binding.relative_path);
          ++stats->errors;
          return false;
        }
        if (canonical_after_failure &&
            canonical_after_failure->sha256 == downloaded_revision.sha256 &&
            DurablyConfirmFileAtPath(path, downloaded_revision.sha256))
        {
          // A filesystem/API may report an ambiguous failure after publication. Exact body and
          // namespace durability checks turn only that state into a successful install.
          install_result = NamespaceCommitResult::Durable;
        }
        else if (File::IsFile(*temporary_path))
        {
          // The prepared inode still has its original name, proving it was not published. If a
          // concurrent file appeared, durably retain that exact body before discharging our
          // transaction; otherwise the canonical path is still absent as originally observed.
          if (canonical_after_failure &&
              (!RequireCanonicalRecovery(binding, path, canonical_after_failure->sha256, false,
                                         false) ||
               !DurablyConfirmFileAtPath(path, canonical_after_failure->sha256)))
          {
            ++stats->errors;
            return false;
          }
          if (canonical_after_failure || canonical_definitely_absent)
            ClearCanonicalRecovery(path);
          else
            require_recovery_for_unsafe_path(downloaded_revision.sha256);
          if (canonical_after_failure)
            report_changed_before_commit();
          ERROR_LOG_FMT(CORE, "EmuBank: filesystem could not publish missing save '{}'",
                        binding.relative_path);
          ++stats->errors;
          return false;
        }
        else if (canonical_after_failure)
        {
          // The prepared name disappeared, so the API result cannot prove this different body was
          // an independent concurrent winner. Its content-addressed backup is already durable;
          // keep the original cloud-body quarantine armed without moving the ambiguous canonical
          // inode through a differently keyed Windows durability sibling.
          require_recovery_for_unsafe_path(downloaded_revision.sha256);
          ++stats->errors;
          return false;
        }
        else
        {
          ERROR_LOG_FMT(CORE, "EmuBank: filesystem could not install missing local save '{}'",
                        binding.relative_path);
          require_recovery_for_unsafe_path(canonical_after_failure ?
                                               canonical_after_failure->sha256 :
                                               downloaded_revision.sha256);
          ++stats->errors;
          return false;
        }
      }
      File::Delete(*temporary_path, File::IfAbsentBehavior::NoConsoleWarning);
      temporary_file_guard.Dismiss();
    }

    // At this point every displaced local/concurrent inode has a durable backup. Transition the
    // journal from rollback to authenticated cloud roll-forward before confirmation. A crash in a
    // Windows hash-bound namespace move can then restore the exact installed body, and a later
    // server revision may safely roll forward without losing the retained local copy.
    if (!RequireCanonicalRecovery(binding, path, downloaded_revision.sha256, true, false))
    {
      ERROR_LOG_FMT(CORE,
                    "EmuBank: installed '{}' but could not durably authorize its confirmation",
                    binding.relative_path);
      ++stats->errors;
      stats->retry_needed = true;
      return false;
    }
    if (!DurablyConfirmFileAtPath(path, downloaded_revision.sha256))
    {
      ERROR_LOG_FMT(CORE,
                    "EmuBank: installed '{}' but its expected body and namespace did not remain "
                    "stable through the durability barrier",
                    binding.relative_path);
      ++stats->errors;
      stats->retry_needed = true;
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

    if (!ClearCanonicalRecovery(path))
    {
      SetStatus(
          fmt::format("EmuBank installed {}, but could not durably clear its recovery quarantine.",
                      BindingDisplayName(binding.relative_path)));
      ++stats->errors;
      stats->retry_needed = true;
      return false;
    }
    UpdateState(binding, path, downloaded_revision.sha256, downloaded_revision.id);
    if (preserve_conflict)
    {
      m_state[binding.id].conflict_pending = true;
      m_state[binding.id].conflict_sha256 = std::move(retained_conflict_sha256);
      m_state_dirty = true;
    }
    m_pending_uploads.erase(binding.id);
    ++stats->downloaded;
    DisplaySyncMessage(
        fmt::format("EmuBank restored {}", BindingDisplayName(binding.relative_path)), 4000,
        OsdTone::Success);
    INFO_LOG_FMT(CORE, "EmuBank: downloaded '{}' at revision {}", binding.relative_path,
                 downloaded_revision.id);
    return true;
  }

  UploadResult Upload(const Connection& connection, const Binding& binding,
                      const std::string& canonical_path, const FileSnapshot& snapshot,
                      std::string_view expected_sha256, Policy::UploadBase upload_base,
                      SyncMode mode, SyncStats* stats)
  {
    // A savestate may finish loading while an older sync pass is still examining files. Let the
    // next pass persist per-binding invalidation before any post-load bytes can be uploaded against
    // the old common ancestor.
    if (m_invalidate_ancestors_requested.load(std::memory_order_acquire))
    {
      ++stats->deferred;
      return UploadResult::Failed;
    }
    if (!ConnectionStillConfigured(connection))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return UploadResult::Failed;
    }

    auto headers = Headers(connection);
    headers["Content-Type"] = "application/octet-stream";
    headers["X-EmuBank-Base-Sha256"] = std::string{expected_sha256};
    headers["X-EmuBank-Filename"] =
        binding.relative_path.substr(binding.relative_path.find_last_of("/\\") + 1);

    SetStatus(fmt::format("EmuBank is uploading {}…", BindingDisplayName(binding.relative_path)));
    DisplaySyncMessage(
        fmt::format("EmuBank: backing up {}...", BindingDisplayName(binding.relative_path)), 3000);

    Common::HttpRequest request(
        HttpTimeoutUntil(m_sync_deadline),
        LimitTransfer(MAX_SAVE_SIZE, snapshot.contents.size(), m_sync_deadline,
                      mode == SyncMode::BeforeLaunch ? nullptr : &m_launch_pending,
                      &m_config_changed_during_sync));
    const auto response = request.Post(BindingUrl(connection, binding), snapshot.contents, headers,
                                       Common::HttpRequest::AllowedReturnCodes::All);
    if (!response)
    {
      if (!ConnectionStillConfigured(connection))
      {
        ++stats->deferred;
        stats->retry_needed = true;
        return UploadResult::Failed;
      }
      ++stats->errors;
      DisplaySyncMessage(
          fmt::format("EmuBank failed to upload {}", BindingDisplayName(binding.relative_path)),
          5000, OsdTone::Error);
      return UploadResult::Failed;
    }
    if (!ConnectionStillConfigured(connection))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return UploadResult::Failed;
    }
    if (request.GetLastResponseCode() == 409)
    {
      ++stats->conflicts;
      m_pending_uploads.erase(binding.id);
      LocalState& state = StateForBinding(binding, canonical_path);
      if (upload_base == Policy::UploadBase::TrustedBase)
        state.base_sha256 = std::string{expected_sha256};
      else if (upload_base == Policy::UploadBase::NoAncestor)
        state.base_sha256.clear();
      state.revision_id.clear();
      state.conflict_pending = true;
      state.conflict_sha256 = snapshot.sha256;
      state.ancestor_invalidated = false;
      m_state_dirty = true;
      SaveState();
      if (m_state_dirty)
      {
        ++stats->errors;
        stats->retry_needed = true;
        stats->abort_reconciliation = true;
        SetStatus(fmt::format(
            "EmuBank could not durably record the retained conflict for {}; sync will retry.",
            BindingDisplayName(binding.relative_path)));
        DisplaySyncMessage(fmt::format("EmuBank could not record the conflict for {}",
                                       BindingDisplayName(binding.relative_path)),
                           6000, OsdTone::Error);
        return UploadResult::Failed;
      }
      WARN_LOG_FMT(CORE,
                   "EmuBank: '{}' changed locally and in the cloud; the local copy was retained "
                   "as a conflict revision",
                   binding.relative_path);
      DisplaySyncMessage(fmt::format("EmuBank kept a conflict copy of {}",
                                     BindingDisplayName(binding.relative_path)),
                         6000, OsdTone::Warning);
      return UploadResult::Conflict;
    }
    if (request.GetLastResponseCode() != 200)
    {
      ERROR_LOG_FMT(CORE, "EmuBank: failed to upload '{}' (HTTP {})", binding.relative_path,
                    request.GetLastResponseCode());
      ++stats->errors;
      DisplaySyncMessage(
          fmt::format("EmuBank failed to upload {}", BindingDisplayName(binding.relative_path)),
          5000, OsdTone::Error);
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

    UpdateState(binding, canonical_path, snapshot.sha256, revision->id);
    m_pending_uploads.erase(binding.id);
    ++stats->uploaded;
    DisplaySyncMessage(
        fmt::format("EmuBank backed up {}", BindingDisplayName(binding.relative_path)), 4000,
        OsdTone::Success);
    INFO_LOG_FMT(CORE, "EmuBank: uploaded '{}' as revision {}", binding.relative_path,
                 revision->id);
    return UploadResult::Success;
  }

  bool ReadyForLiveUpload(const Binding& binding, const FileSnapshot& snapshot, SyncMode mode,
                          bool live_uploads_open)
  {
    if (mode != SyncMode::Live)
      return true;

    auto [it, inserted] = m_pending_uploads.try_emplace(binding.id, PendingUpload{snapshot.sha256});
    if (!inserted && it->second.sha256 != snapshot.sha256)
      it->second = {snapshot.sha256};
    return live_uploads_open;
  }

  void ProcessBinding(const Connection& connection, const Binding& binding,
                      const Manifest& manifest, const ActiveGameResolution& resolution,
                      const std::string& expected_canonical_path, SyncMode mode,
                      bool live_uploads_open, SyncStats* stats)
  {
    ++stats->bindings;
    if (!ConnectionStillConfigured(connection))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return;
    }
    if ((mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)) ||
        (mode == SyncMode::Idle && m_emulation_active.load(std::memory_order_acquire)))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return;
    }

    const bool server_conflict = binding.status == "conflict";
    if (binding.status != "active" && !server_conflict)
    {
      m_pending_uploads.erase(binding.id);
      ++stats->deferred;
      return;
    }
    if (binding.sync_mode != "two_way" && binding.sync_mode != "upload_only" &&
        binding.sync_mode != "download_only")
    {
      m_pending_uploads.erase(binding.id);
      ERROR_LOG_FMT(CORE, "EmuBank: refused unsupported sync mode '{}' for '{}'", binding.sync_mode,
                    binding.relative_path);
      ++stats->errors;
      return;
    }

    const auto path = ResolveSavePath(binding.relative_path, connection.gamecube_save_root,
                                      connection.wii_save_root);
    if (!path || CanonicalPathKey(*path) != CanonicalPathKey(expected_canonical_path))
    {
      m_pending_uploads.erase(binding.id);
      ERROR_LOG_FMT(CORE,
                    "EmuBank: refused a changed, unsafe, or unsupported Dolphin save path '{}' "
                    "(bindings must be supported files below GC/ or Wii/)",
                    binding.relative_path);
      ++stats->errors;
      return;
    }
    const std::string recovery_key = RecoveryPathKey(*path);
    if (!m_recovery_blocks.contains(recovery_key) && !m_recovery_blocks.empty())
    {
      // Filesystem spelling cannot prove that this target is independent of an armed path: hard
      // links, bind mounts, mapped drives, Unicode aliases, and platform namespace prefixes can
      // all defeat lexical comparison. Until every recovery record clears, process only its exact
      // key and never let another binding enter ordinary upload/download policy.
      SetStatus(fmt::format("EmuBank deferred {} while another save needs path recovery.",
                            BindingDisplayName(binding.relative_path)));
      ++stats->deferred;
      stats->retry_needed = true;
      return;
    }
    EnsureStateIdentity(binding, *path);
    if (resolution.blocked_binding_ids.contains(binding.id))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return;
    }
    const bool file_exists = File::IsFile(*path);
    const std::optional<FileSnapshot> local = file_exists ? ReadSaveFile(*path) : std::nullopt;
    const bool downloads_open =
        mode == SyncMode::BeforeLaunch ||
        (mode == SyncMode::Idle && !m_launch_pending.load(std::memory_order_acquire) &&
         !m_emulation_active.load(std::memory_order_acquire));
    const Revision* const cloud = binding.current_revision ? &*binding.current_revision : nullptr;
    const auto recovery = m_recovery_blocks.find(recovery_key);
    if (recovery != m_recovery_blocks.end())
    {
      if (local && local->sha256 == recovery->second.required_sha256)
      {
        if (mode == SyncMode::Live || m_emulation_active.load(std::memory_order_acquire) ||
            (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)))
        {
          SetStatus(fmt::format(
              "EmuBank will verify the restored namespace for {} after emulation stops.",
              BindingDisplayName(binding.relative_path)));
          ++stats->deferred;
          stats->retry_needed = true;
          return;
        }
        std::lock_guard install_lock(m_save_install_mutex);
        if (m_emulation_active.load(std::memory_order_acquire) ||
            (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)))
        {
          ++stats->deferred;
          stats->retry_needed = true;
          return;
        }
        const auto restored = ReadSaveFile(*path);
        // A matching pathname is not enough to discharge a write-ahead quarantine. Make the
        // recovered body and its namespace entry durable before persisting that launch is safe.
        if (!restored || restored->sha256 != recovery->second.required_sha256 ||
            !DurablyConfirmFileAtPath(*path, recovery->second.required_sha256))
        {
          SetStatus(fmt::format(
              "EmuBank kept {} blocked because its recovered save could not be flushed.",
              BindingDisplayName(binding.relative_path)));
          ++stats->errors;
          stats->retry_needed = true;
          return;
        }
        if (!ClearCanonicalRecovery(*path))
        {
          ++stats->errors;
          stats->retry_needed = true;
          return;
        }
      }
      else if (cloud && downloads_open &&
               (recovery->second.cloud_reinstall_allowed ||
                cloud->sha256 == recovery->second.required_sha256))
      {
        // The durable transaction kind identifies a failed publication of a previously missing
        // save and permits a roll-forward to the server's now-current authenticated revision. The
        // hash equality is retained as backward-compatible proof for older recovery records.
        // Android's exclusive-copy fallback can leave a partial canonical file after a crash or
        // short write. A readable different body is indistinguishable from a genuine concurrent
        // local save: retain it, but never clear quarantine and upload it as an ordinary edit.
        {
          std::lock_guard install_lock(m_save_install_mutex);
          if (m_emulation_active.load(std::memory_order_acquire) ||
              (mode != SyncMode::BeforeLaunch &&
               m_launch_pending.load(std::memory_order_acquire)) ||
              !ConnectionStillConfigured(connection))
          {
            ++stats->deferred;
            stats->retry_needed = true;
            return;
          }

          const bool canonical_is_file = File::IsFile(*path);
          const auto canonical = canonical_is_file ? ReadSaveFile(*path) : std::nullopt;
          if (canonical && canonical->sha256 == recovery->second.required_sha256)
          {
            if (!DurablyConfirmFileAtPath(*path, recovery->second.required_sha256))
            {
              ++stats->errors;
              stats->retry_needed = true;
              return;
            }
            if (!ClearCanonicalRecovery(*path))
            {
              ++stats->errors;
              stats->retry_needed = true;
              return;
            }
            ++stats->deferred;
            stats->retry_needed = true;
            return;
          }
          else if (canonical)
          {
            if (!PreserveLocalBackup(binding, *canonical))
            {
              ++stats->errors;
              stats->retry_needed = true;
              return;
            }
            SetStatus(fmt::format(
                "EmuBank retained the different file at {} and kept sync blocked because it may "
                "be a local save or an incomplete install. Its backup is durable; review it, "
                "move the canonical file aside, then retry recovery.",
                BindingDisplayName(binding.relative_path)));
            ++stats->errors;
            stats->retry_needed = true;
            return;
          }
          else
          {
            if (File::Exists(*path) && !canonical_is_file)
            {
              SetStatus(fmt::format(
                  "EmuBank kept {} blocked because its save path is not a regular file.",
                  BindingDisplayName(binding.relative_path)));
              ++stats->errors;
              stats->retry_needed = true;
              return;
            }
            if (canonical_is_file && !PreserveDisplacedLocal(binding, *path))
            {
              ++stats->errors;
              stats->retry_needed = true;
              return;
            }
            if (File::Exists(*path))
            {
              ++stats->deferred;
              stats->retry_needed = true;
              return;
            }
          }
        }

        if (m_recovery_blocks.contains(RecoveryPathKey(*path)))
        {
          if (server_conflict)
            ++stats->conflicts;
          Download(connection, binding, manifest, *cloud, *path, std::nullopt, nullptr, mode, stats,
                   server_conflict);
          return;
        }
      }
      else
      {
        SetStatus(fmt::format(
            "EmuBank kept {} blocked for recovery; restore its retained local copy before "
            "launching.",
            BindingDisplayName(binding.relative_path)));
        if (downloads_open)
          ++stats->errors;
        else
          ++stats->deferred;
        stats->retry_needed = true;
        return;
      }
    }
    if (!m_recovery_blocks.empty())
    {
      // The current exact recovery may have cleared, but another armed pathname still makes the
      // shared save namespace globally unsafe for ordinary upload/download policy.
      ++stats->deferred;
      stats->retry_needed = true;
      return;
    }
    if (file_exists && !local)
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return;
    }
    const std::optional<std::string> observed_local_sha256 =
        local ? std::optional<std::string>{local->sha256} : std::nullopt;
    bool rejected_explicit_download = false;
    if (auto rejected_state = m_state.find(binding.id);
        rejected_state != m_state.end() &&
        (!rejected_state->second.rejected_explicit_revision_id.empty() ||
         !rejected_state->second.rejected_explicit_sha256.empty()))
    {
      rejected_explicit_download =
          binding.explicit_download_pending && binding.current_revision &&
          rejected_state->second.rejected_explicit_revision_id == binding.current_revision->id &&
          rejected_state->second.rejected_explicit_sha256 == binding.current_revision->sha256;
      if (!rejected_explicit_download)
      {
        // A tombstone applies only while the server continues advertising the exact stale choice.
        // Once that marker disappears or changes, a genuinely new selection may be recorded.
        rejected_state->second.rejected_explicit_revision_id.clear();
        rejected_state->second.rejected_explicit_sha256.clear();
        m_state_dirty = true;
      }
    }
    if (binding.explicit_download_pending && !rejected_explicit_download &&
        !RememberExplicitDownload(connection, binding, observed_local_sha256))
    {
      ERROR_LOG_FMT(CORE,
                    "EmuBank: could not durably retain the selected revision for binding '{}'",
                    binding.id);
      ++stats->errors;
      stats->retry_needed = true;
      stats->abort_reconciliation = true;
      return;
    }
    if (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire))
    {
      ++stats->deferred;
      stats->retry_needed = true;
      return;
    }
    const auto* const download_authorization =
        FindMatchingDownloadAuthorization(resolution, binding, local);

    const bool can_upload = binding.sync_mode != "download_only";
    const bool can_download = binding.sync_mode != "upload_only";

    auto state_it = m_state.find(binding.id);
    bool durable_explicit_download = false;
    bool discarded_stale_explicit_download = false;
    if (state_it != m_state.end() && (!state_it->second.explicit_revision_id.empty() ||
                                      !state_it->second.explicit_sha256.empty()))
    {
      const bool explicit_cloud_matches = cloud &&
                                          state_it->second.explicit_revision_id == cloud->id &&
                                          state_it->second.explicit_sha256 == cloud->sha256;
      const bool explicit_local_matches = Policy::ResolverLocalMatches(
          state_it->second.explicit_local_present, state_it->second.explicit_local_sha256,
          local.has_value(), local ? local->sha256 : "");
      durable_explicit_download = explicit_cloud_matches && explicit_local_matches;
      if (!durable_explicit_download)
      {
        // A one-shot choice is bound to both the selected cloud body and the exact local state it
        // was allowed to replace. This also makes a marker left by a crash after installation
        // harmless when the local file is later edited.
        if (explicit_cloud_matches && !explicit_local_matches)
        {
          // Keep a durable tombstone while the server advertises this exact pending choice. The
          // choice was made against different local bytes and cannot be silently rebound on a
          // later stopped pass merely because its one-shot GET has not happened yet.
          state_it->second.rejected_explicit_revision_id = state_it->second.explicit_revision_id;
          state_it->second.rejected_explicit_sha256 = state_it->second.explicit_sha256;
          rejected_explicit_download = true;
        }
        state_it->second.explicit_revision_id.clear();
        state_it->second.explicit_sha256.clear();
        state_it->second.explicit_local_present = false;
        state_it->second.explicit_local_sha256.clear();
        m_state_dirty = true;
        discarded_stale_explicit_download = true;
      }
    }
    if (discarded_stale_explicit_download && binding.explicit_download_pending)
    {
      // Persist the tombstone before taking any other action in this pass.
      SaveState();
      if (m_state_dirty)
      {
        SetStatus(
            fmt::format("EmuBank could not durably reject the stale selected revision for {}.",
                        BindingDisplayName(binding.relative_path)));
        ++stats->errors;
        stats->abort_reconciliation = true;
      }
      else
      {
        ++stats->deferred;
      }
      stats->retry_needed = true;
      return;
    }
    const bool resolver_requests_download =
        download_authorization != nullptr && !rejected_explicit_download;
    const bool server_explicit_download =
        durable_explicit_download ||
        (resolver_requests_download && download_authorization->explicit_selection);
    const bool server_requests_download = resolver_requests_download || durable_explicit_download;
    const bool has_trusted_base =
        state_it != m_state.end() && IsSha256(state_it->second.base_sha256);
    const bool local_matches_base =
        local && has_trusted_base && local->sha256 == state_it->second.base_sha256;
    const bool cloud_matches_base =
        cloud && has_trusted_base && cloud->sha256 == state_it->second.base_sha256;
    const bool conflict_pending = state_it != m_state.end() && state_it->second.conflict_pending;
    const bool local_matches_conflict = local && conflict_pending &&
                                        IsSha256(state_it->second.conflict_sha256) &&
                                        local->sha256 == state_it->second.conflict_sha256;
    const bool ancestor_invalidated =
        state_it != m_state.end() && state_it->second.ancestor_invalidated;
    const Policy::SaveRecency recency = local && cloud && local->sha256 != cloud->sha256 ?
                                            CompareSaveRecency(*local, *cloud, manifest) :
                                            Policy::SaveRecency::Unknown;

    const Policy::Decision decision = Policy::Decide({
        .server_conflict = server_conflict,
        .cloud_present = cloud != nullptr,
        .local_present = local.has_value(),
        .local_matches_cloud = local && cloud && local->sha256 == cloud->sha256,
        .can_upload = can_upload,
        .can_download = can_download,
        .downloads_open = downloads_open,
        .server_requests_download = server_requests_download,
        .server_explicit_download = server_explicit_download,
        .has_trusted_base = has_trusted_base,
        .local_matches_base = local_matches_base,
        .cloud_matches_base = cloud_matches_base,
        .ancestor_invalidated = ancestor_invalidated,
        .conflict_pending = conflict_pending,
        .local_matches_conflict = local_matches_conflict,
        .recency = recency,
    });

    switch (decision.action)
    {
    case Policy::Action::Current:
      if (server_conflict)
        ++stats->conflicts;
      if (local && cloud)
      {
        if (ancestor_invalidated)
        {
          // The next post-savestate flush must remain untrusted even if the host still contains
          // the pre-load bytes at this instant.
        }
        else if (server_conflict && conflict_pending)
        {
          if (state_it->second.base_sha256 != cloud->sha256 ||
              state_it->second.revision_id != cloud->id)
          {
            state_it->second.base_sha256 = cloud->sha256;
            state_it->second.revision_id = cloud->id;
            m_state_dirty = true;
          }
        }
        else
        {
          UpdateState(binding, *path, cloud->sha256, cloud->id);
        }
      }
      m_pending_uploads.erase(binding.id);
      ++stats->current;
      return;

    case Policy::Action::Download:
    {
      if (!cloud)
      {
        ++stats->deferred;
        return;
      }
      // Every divergent replacement gets a content-addressed backup. A trusted-base relationship
      // does not prove the selected cloud pointer is newer because the server can reactivate an
      // existing historical revision.
      const bool local_needs_backup = local.has_value();
      if (server_conflict)
        ++stats->conflicts;
      Download(connection, binding, manifest, *cloud, *path, observed_local_sha256,
               local_needs_backup ? &*local : nullptr, mode, stats, server_conflict);
      return;
    }

    case Policy::Action::Upload:
    {
      if (!local)
        return;
      if (!ReadyForLiveUpload(binding, *local, mode, live_uploads_open))
      {
        ++stats->deferred;
        stats->retry_needed = true;
        return;
      }

      std::string_view expected_sha256 = ZERO_SHA256;
      if (decision.upload_base == Policy::UploadBase::TrustedBase)
      {
        if (!has_trusted_base)
        {
          ++stats->deferred;
          return;
        }
        expected_sha256 = state_it->second.base_sha256;
      }
      else if (decision.upload_base == Policy::UploadBase::CurrentCloud)
      {
        if (!cloud)
        {
          ++stats->deferred;
          return;
        }
        // The local file is clearly newer. Compare-and-swap against the manifest's current hash
        // so EmuBank promotes it directly instead of manufacturing a false conflict. If the cloud
        // advances during the request, the server still returns 409 and the local file stays put.
        expected_sha256 = cloud->sha256;
      }
      const UploadResult result = Upload(connection, binding, *path, *local, expected_sha256,
                                         decision.upload_base, mode, stats);
      if (server_conflict && result == UploadResult::Failed)
        ++stats->conflicts;
      return;
    }

    case Policy::Action::KeepLocal:
      m_pending_uploads.erase(binding.id);
      if (server_conflict)
        ++stats->conflicts;
      else
        ++stats->deferred;
      return;

    case Policy::Action::Defer:
      if (mode == SyncMode::Live)
        m_pending_uploads.erase(binding.id);
      if (server_conflict)
        ++stats->conflicts;
      ++stats->deferred;
      return;
    }
  }

  struct AncestorInvalidationStatus
  {
    bool pending = false;
    bool ready = false;
  };

  // Caller holds m_sync_mutex. The root-level pending bit is durable so a crash cannot strand a
  // binding first discovered between resolver and manifest with a trusted ancestor. Marker I/O is
  // deliberately fail-closed: an unreadable directory never means that no invalidation exists.
  AncestorInvalidationStatus PersistPendingAncestorInvalidation()
  {
    const std::optional<std::vector<std::string>> durable_markers =
        FindSavestateInvalidationMarkers();
    if (durable_markers)
      m_pending_ancestor_marker_paths = *durable_markers;
    else
      m_invalidate_ancestors_requested.store(true, std::memory_order_release);
    const bool newly_invalidated =
        m_invalidate_ancestors_requested.exchange(false, std::memory_order_acq_rel) ||
        (durable_markers && !durable_markers->empty()) || !durable_markers;
    if (newly_invalidated && !m_ancestor_invalidation_pending)
    {
      m_ancestor_invalidation_pending = true;
      m_state_dirty = true;
    }
    if (m_ancestor_invalidation_pending)
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
    return {m_ancestor_invalidation_pending,
            durable_markers.has_value() && (!m_ancestor_invalidation_pending || !m_state_dirty)};
  }

  bool
  SyncOnce(SyncMode mode,
           std::optional<std::chrono::steady_clock::time_point> deadline_override = std::nullopt,
           bool live_uploads_open = true, bool allow_during_shutdown = false,
           u64 tracked_generation = 0)
  {
    const auto deadline = deadline_override.value_or(std::chrono::steady_clock::now() +
                                                     (mode == SyncMode::BeforeLaunch ?
                                                          BEFORE_LAUNCH_OPERATION_TIMEOUT :
                                                          SYNC_OPERATION_TIMEOUT));
    std::unique_lock operation_lock(m_sync_mutex, std::defer_lock);
    if (!operation_lock.try_lock_until(deadline))
    {
      SetStatus("EmuBank sync timed out waiting for another sync pass to finish.");
      return false;
    }
    // A worker may already be waiting behind a savestate lease when shutdown removes the matching
    // completion hook and releases that lease. Do not let it reconcile partially deserialized
    // bytes. The one explicit final pass runs only after the worker has joined.
    if (m_shutdown.load(std::memory_order_acquire) && !allow_during_shutdown)
      return false;
    m_config_changed_during_sync.store(false, std::memory_order_release);
    if (std::chrono::steady_clock::now() >= deadline)
    {
      SetStatus(mode == SyncMode::BeforeLaunch ?
                    "EmuBank's pre-launch check timed out; launch is continuing without waiting." :
                    "EmuBank sync timed out before it could start.");
      return false;
    }
    if (tracked_generation != 0)
    {
      u64 attempted = m_last_attempted_generation.load(std::memory_order_acquire);
      while (attempted < tracked_generation &&
             !m_last_attempted_generation.compare_exchange_weak(attempted, tracked_generation,
                                                                std::memory_order_acq_rel,
                                                                std::memory_order_acquire))
      {
      }
    }
    if (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire))
      return false;

    const auto process_lock_deadline =
        mode == SyncMode::BeforeLaunch ?
            deadline :
            std::min(deadline, std::chrono::steady_clock::now() + 250ms);
    if (!EnsureProcessLock(process_lock_deadline))
    {
      SetStatus("EmuBank could not acquire the shared save-root lock. Close other Dolphin "
                "processes using this user folder or save root, then retry.");
      if (mode == SyncMode::BeforeLaunch)
        Core::RequestBootCancellation();
      return false;
    }
    if (m_recovery_journal_unreadable.load(std::memory_order_acquire))
    {
      SetStatus("EmuBank blocked save reconciliation because its recovery metadata is unreadable. "
                "Inspect EmuBankSyncState.json, EmuBankRecovery.json, and retained backups before "
                "retrying.");
      if (mode == SyncMode::BeforeLaunch)
        Core::RequestBootCancellation();
      return false;
    }
    if (m_state_unreadable.load(std::memory_order_acquire))
    {
      SetStatus("EmuBank blocked save reconciliation because its durable sync state is unreadable "
                "or over its safety limit. Inspect EmuBankSyncState.json before retrying.");
      if (mode == SyncMode::BeforeLaunch)
        Core::RequestBootCancellation();
      return false;
    }

    m_is_syncing.store(true, std::memory_order_release);
    Common::ScopeGuard syncing_guard{
        [this] { m_is_syncing.store(false, std::memory_order_release); }};
    Common::ScopeGuard recovery_launch_guard{[this, mode] {
      if (mode != SyncMode::BeforeLaunch ||
          !m_canonical_recovery_required.load(std::memory_order_acquire))
        return;
      Core::RequestBootCancellation();
      if (m_process_storage_changed.load(std::memory_order_acquire))
      {
        SetStatus("EmuBank canceled launch because a locked Config or save-root directory changed "
                  "while Dolphin was running. Restart Dolphin before retrying.");
      }
      else if (m_state_unreadable.load(std::memory_order_acquire))
      {
        SetStatus("EmuBank canceled launch because its durable sync state is unreadable or over "
                  "its safety limit.");
      }
      else if (m_state_capacity_exceeded)
      {
        SetStatus("EmuBank canceled launch because too many durable binding safety records are "
                  "pending.");
      }
      else if (m_recovery_journal_unreadable.load(std::memory_order_acquire))
      {
        SetStatus("EmuBank canceled launch because its save recovery metadata is unreadable.");
      }
      else if (m_recovery_persistence_failed.load(std::memory_order_acquire))
      {
        SetStatus("EmuBank canceled launch because durable save recovery state could not be "
                  "written.");
      }
      else if (!m_recovery_blocks.empty())
      {
        const std::string& relative_path = m_recovery_blocks.begin()->second.relative_path;
        SetStatus(fmt::format(
            "EmuBank canceled launch because {} still needs save-path recovery. Restore its "
            "retained backup, then try again.",
            BindingDisplayName(relative_path)));
      }
    }};
    m_sync_deadline = deadline;
    if (mode == SyncMode::BeforeLaunch)
      SetStatus("EmuBank is checking cloud saves before launch…");
    else if (mode == SyncMode::Live)
      SetStatus("EmuBank is checking for stable local save changes…");
    else
      SetStatus("EmuBank is checking device save bindings…");
    DisplaySyncMessage("EmuBank: connecting...", 2500);

    // Recovery blocks are credential-independent because they describe the canonical local path,
    // not a server relationship. A manually restored byte-identical retained copy clears its own
    // block even while EmuBank is disabled or offline.
    RetryRecoveryPersistence();
    RefreshCanonicalRecoveryBlocks(mode);
    if (m_recovery_persistence_failed.load(std::memory_order_acquire))
    {
      SetStatus("EmuBank could not durably update save recovery metadata; sync will retry.");
      return false;
    }

    if ((mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire)) ||
        std::chrono::steady_clock::now() >= m_sync_deadline)
      return false;

    const auto connection = GetConnection();
    if (!connection)
    {
      // Preserve known binding markers even while disconnected. The durable root pending bit
      // keeps the first successful manifest responsible for bindings not yet discovered.
      PersistPendingAncestorInvalidation();
      return false;
    }
    if (!ConnectionStillConfigured(*connection))
      return false;

    // Associate the durable state file with this credential before the resolver can record a
    // one-shot explicit revision selection. The server clears that marker when download begins,
    // so the local authorization must already survive a failed install or process crash.
    if (m_state_server_url != connection->base_url || m_state_device_id != connection->device_id)
    {
      const bool capacity_was_exceeded =
          m_state_capacity_exceeded.exchange(false, std::memory_order_acq_rel);
      m_state.clear();
      m_pending_uploads.clear();
      m_state_server_url = connection->base_url;
      m_state_device_id = connection->device_id;
      m_state_dirty = true;
      SaveState();
      if (m_state_dirty)
      {
        if (capacity_was_exceeded)
          m_state_capacity_exceeded.store(true, std::memory_order_release);
        UpdateRecoveryVeto();
        SetStatus("EmuBank could not durably associate sync state with this device; sync will "
                  "retry.");
        return false;
      }
      UpdateRecoveryVeto();
    }

    const AncestorInvalidationStatus invalidation = PersistPendingAncestorInvalidation();
    const bool invalidate_savestate_ancestors = invalidation.pending;
    if (!invalidation.ready)
    {
      SetStatus("EmuBank could not durably inspect or invalidate old savestate ancestry; sync was "
                "left unchanged and will retry.");
      return false;
    }

    const ActiveGameResolution resolution = ResolveActiveGames(*connection, mode);
    if (m_invalidate_ancestors_requested.load(std::memory_order_acquire))
      return false;
    if (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire))
      return false;
    if (std::chrono::steady_clock::now() >= m_sync_deadline)
    {
      if (mode == SyncMode::BeforeLaunch)
      {
        SetStatus("EmuBank's pre-launch check timed out; launch is continuing without waiting.");
        DisplaySyncMessage("EmuBank check timed out; continuing launch", 5000, OsdTone::Warning);
      }
      else
      {
        SetStatus("EmuBank sync timed out while linking the active game; it will retry later.");
      }
      return false;
    }
    const auto manifest = FetchManifest(*connection, mode);
    if (!manifest)
      return false;
    if (!ConnectionStillConfigured(*connection))
      return false;
    if (m_invalidate_ancestors_requested.load(std::memory_order_acquire))
      return false;
    if (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire))
      return false;

    if (!manifest->bindings.empty())
    {
      DisplaySyncMessage(fmt::format("EmuBank: found {} bound save{}", manifest->bindings.size(),
                                     manifest->bindings.size() == 1 ? "" : "s"),
                         2500);
    }

    const auto carries_safety_state = [](const LocalState& state) {
      return state.conflict_pending || state.ancestor_invalidated ||
             !state.explicit_revision_id.empty() || !state.rejected_explicit_revision_id.empty();
    };
    std::set<std::string, std::less<>> manifest_binding_ids;
    for (const Binding& binding : manifest->bindings)
      manifest_binding_ids.insert(binding.id);

    size_t required_state_entries = manifest_binding_ids.size();
    for (const auto& [id, state] : m_state)
    {
      if (!manifest_binding_ids.contains(id) && carries_safety_state(state))
        ++required_state_entries;
    }
    if (required_state_entries > MAX_DURABLE_STATE_BINDINGS)
    {
      if (!m_state_capacity_exceeded.exchange(true, std::memory_order_acq_rel))
      {
        m_state_dirty = true;
        SaveState();
      }
      UpdateRecoveryVeto();
      SetStatus("EmuBank blocked reconciliation because too many durable binding safety records "
                "are pending. Reduce the server binding set, then retry.");
      return false;
    }

    // Remove only entries with no safety meaning before admitting new manifest IDs. This makes
    // the hard map bound exact without evicting conflict, savestate, or explicit-selection state.
    const size_t stale_state_erased = std::erase_if(m_state, [&](const auto& entry) {
      return !manifest_binding_ids.contains(entry.first) && !carries_safety_state(entry.second);
    });
    m_state_dirty = m_state_dirty || stale_state_erased != 0;
    if (m_state_capacity_exceeded.exchange(false, std::memory_order_acq_rel))
    {
      m_state_dirty = true;
      SaveState();
      if (m_state_dirty)
      {
        m_state_capacity_exceeded.store(true, std::memory_order_release);
        UpdateRecoveryVeto();
        SetStatus("EmuBank could not durably clear its binding safety limit; sync will retry.");
        return false;
      }
      UpdateRecoveryVeto();
    }

    // Resolve and inspect each binding/selector once. Pairwise alias decisions below are then
    // entirely in-memory, so a 512-entry manifest cannot turn the prelaunch budget into hundreds
    // of thousands of filesystem probes on a removable or network save root.
    std::map<std::string, RelativeSavePathAliasInfo, std::less<>> binding_path_aliases;
    for (const Binding& binding : manifest->bindings)
    {
      RelativeSavePathAliasInfo alias =
          InspectRelativeSavePathForAliases(binding.relative_path, connection->gamecube_save_root,
                                            connection->wii_save_root, m_sync_deadline);
      if (!alias.safe)
      {
        SetStatus("EmuBank refused an unsafe save-path alias in the device manifest.");
        return false;
      }
      if (std::ranges::any_of(binding_path_aliases, [&](const auto& existing) {
            return RelativeSavePathAliasInfosMayAlias(existing.second, alias);
          }))
      {
        SetStatus("EmuBank refused bindings whose local save paths are equal or overlap.");
        return false;
      }
      binding_path_aliases.emplace(binding.id, std::move(alias));
    }

    std::set<std::string, std::less<>> priority_path_binding_ids;
    for (const std::string& path : resolution.priority_paths)
    {
      if (std::chrono::steady_clock::now() >= m_sync_deadline)
        return false;
      const RelativeSavePathAliasInfo priority_alias = InspectRelativeSavePathForAliases(
          path, connection->gamecube_save_root, connection->wii_save_root, m_sync_deadline);
      for (const auto& [binding_id, binding_alias] : binding_path_aliases)
      {
        if (RelativeSavePathAliasInfosMayAlias(priority_alias, binding_alias))
          priority_path_binding_ids.insert(binding_id);
      }
    }

    std::map<std::string, std::set<std::string, std::less<>>, std::less<>>
        path_selector_binding_ids;
    std::set<std::string, std::less<>> invalidated_path_binding_ids;
    for (const std::string& selector : m_ancestor_invalidation_path_selectors)
    {
      if (std::chrono::steady_clock::now() >= m_sync_deadline)
        return false;
      const RelativeSavePathAliasInfo selector_alias = InspectRelativeSavePathForAliases(
          selector, connection->gamecube_save_root, connection->wii_save_root, m_sync_deadline);
      auto& matches = path_selector_binding_ids[selector];
      for (const auto& [binding_id, binding_alias] : binding_path_aliases)
      {
        if (RelativeSavePathAliasInfosMayAlias(selector_alias, binding_alias))
        {
          matches.insert(binding_id);
          invalidated_path_binding_ids.insert(binding_id);
        }
      }
    }

    const auto binding_launch_priority = [&](const Binding& binding) {
      if (priority_path_binding_ids.contains(binding.id))
        return 2;
      return !resolution.priority_game_id.empty() &&
                     Common::CaseInsensitiveEquals(binding.game_id, resolution.priority_game_id) ?
                 1 :
                 0;
    };

    const auto binding_matches_path_selector = [&](const Binding& binding) {
      return invalidated_path_binding_ids.contains(binding.id);
    };
    const auto binding_matches_game_selector = [&](const Binding& binding) {
      return std::ranges::any_of(m_ancestor_invalidation_game_selectors,
                                 [&](const std::string& selector) {
                                   return Common::CaseInsensitiveEquals(binding.game_id, selector);
                                 });
    };

    if (invalidate_savestate_ancestors || !m_ancestor_invalidation_path_selectors.empty() ||
        !m_ancestor_invalidation_game_selectors.empty())
    {
      // Apply the global epoch to a complete manifest and also carry unmatched path/title scopes
      // beyond it. The latter catches a previously omitted binding without forcing intentionally
      // unbound memory-card slots to keep every unrelated binding globally tainted forever.
      for (const Binding& binding : manifest->bindings)
      {
        if (!invalidate_savestate_ancestors && !binding_matches_path_selector(binding) &&
            !binding_matches_game_selector(binding))
        {
          continue;
        }
        const auto canonical_path = ResolveSavePath(
            binding.relative_path, connection->gamecube_save_root, connection->wii_save_root);
        if (!canonical_path)
        {
          m_ancestor_invalidation_pending = true;
          SetStatus("EmuBank could not bind savestate invalidation to a safe local save path.");
          return false;
        }
        LocalState& state = StateForBinding(binding, *canonical_path);
        if (!state.ancestor_invalidated)
        {
          state.ancestor_invalidated = true;
          m_state_dirty = true;
        }
      }
      if (m_state_dirty)
        SaveState();
      if (m_state_dirty)
      {
        SetStatus("EmuBank could not durably mark the savestate-derived save; sync was left "
                  "unchanged and will retry.");
        return false;
      }
    }

    if (invalidate_savestate_ancestors)
    {
      // A live save device can flush or acquire its first binding after this manifest. Retain the
      // root epoch and marker through the running session. A stopped pass may clear the global
      // epoch once the complete manifest is tainted; unmatched affected paths/titles remain as
      // durable targeted taints for bindings which appear later.
      const bool relevant_binding_visible =
          std::ranges::any_of(manifest->bindings, [&](const Binding& binding) {
            return binding_matches_path_selector(binding) || binding_matches_game_selector(binding);
          });
      const bool finalize_invalidation = ConnectionStillConfigured(*connection) &&
                                         mode != SyncMode::Live &&
                                         m_ancestor_invalidation_selectors_complete &&
                                         relevant_binding_visible && !resolution.retry_needed;

      if (!finalize_invalidation)
        SetStatus("EmuBank retained the savestate safety epoch until the affected save binding is "
                  "visible after emulation stops.");

      if (finalize_invalidation)
      {
        if (!ConnectionStillConfigured(*connection))
          return false;
        bool markers_consumed = true;
        for (const std::string& marker_path : m_pending_ancestor_marker_paths)
        {
          markers_consumed = ConsumeSavestateInvalidationMarker(marker_path) && markers_consumed;
        }
        m_pending_ancestor_marker_paths.clear();
        const std::optional<std::vector<std::string>> remaining_markers =
            FindSavestateInvalidationMarkers();
        if (!markers_consumed || !remaining_markers || !remaining_markers->empty())
        {
          m_invalidate_ancestors_requested.store(true, std::memory_order_release);
          SetStatus(
              "EmuBank deferred sync because savestate safety markers changed or could not be "
              "durably inspected.");
          return false;
        }
        if (!ConnectionStillConfigured(*connection))
          return false;

        // The affected binding taints are durable and every active marker is now durably absent.
        // Clear the root epoch last. A crash before this commit merely repeats a safe pass.
        m_ancestor_invalidation_pending = false;
        m_state_dirty = true;
        SaveState();
        if (m_state_dirty)
        {
          m_ancestor_invalidation_pending = true;
          SetStatus("EmuBank could not durably finish savestate ancestry invalidation; sync will "
                    "retry.");
          return false;
        }
      }
    }

    SyncStats stats;
    bool timed_out = false;
    std::vector<const Binding*> ordered_bindings;
    ordered_bindings.reserve(manifest->bindings.size());
    for (const Binding& binding : manifest->bindings)
    {
      ordered_bindings.push_back(&binding);
    }

    if (mode == SyncMode::BeforeLaunch)
    {
      std::stable_sort(ordered_bindings.begin(), ordered_bindings.end(),
                       [&binding_launch_priority](const Binding* lhs, const Binding* rhs) {
                         return binding_launch_priority(*lhs) > binding_launch_priority(*rhs);
                       });
    }

    std::vector<CanonicalPathAliasInfo> processed_save_paths;
    processed_save_paths.reserve(ordered_bindings.size());
    for (size_t index = 0; index < ordered_bindings.size(); ++index)
    {
      if (m_invalidate_ancestors_requested.load(std::memory_order_acquire))
      {
        stats.deferred += static_cast<int>(ordered_bindings.size() - index);
        stats.retry_needed = true;
        break;
      }
      if (mode != SyncMode::BeforeLaunch && m_launch_pending.load(std::memory_order_acquire))
        return false;
      if (std::chrono::steady_clock::now() >= m_sync_deadline)
      {
        stats.deferred += static_cast<int>(ordered_bindings.size() - index);
        timed_out = true;
        break;
      }
      const Binding& binding = *ordered_bindings[index];
      const auto canonical_path = ResolveSavePath(
          binding.relative_path, connection->gamecube_save_root, connection->wii_save_root);
      CanonicalPathAliasInfo alias_info =
          canonical_path ? InspectCanonicalPathForAliases(*canonical_path, m_sync_deadline) :
                           CanonicalPathAliasInfo{};
      const auto aliases_cached_other_binding = [&](const CanonicalPathAliasInfo& current_alias) {
        return std::ranges::any_of(binding_path_aliases, [&](const auto& cached) {
          return cached.first != binding.id && cached.second.canonical &&
                 CanonicalPathAliasInfosMayAlias(current_alias, *cached.second.canonical);
        });
      };
      if (!canonical_path || !alias_info.safe || !alias_info.lookup_succeeded ||
          aliases_cached_other_binding(alias_info) ||
          std::ranges::any_of(processed_save_paths, [&](const CanonicalPathAliasInfo& processed) {
            return CanonicalPathAliasInfosMayAlias(processed, alias_info);
          }))
      {
        stats.deferred += static_cast<int>(ordered_bindings.size() - index);
        ++stats.errors;
        stats.retry_needed = true;
        SetStatus("EmuBank stopped because two bindings may own the same local save path, or the "
                  "path identity could not be verified.");
        break;
      }
      SetStatus(fmt::format("EmuBank is checking save {} of {}: {}…", index + 1,
                            ordered_bindings.size(), BindingDisplayName(binding.relative_path)));
      ProcessBinding(*connection, binding, *manifest, resolution, *canonical_path, mode,
                     live_uploads_open, &stats);
      if (stats.abort_reconciliation)
      {
        stats.deferred += static_cast<int>(ordered_bindings.size() - index - 1);
        break;
      }

      const auto canonical_path_after = ResolveSavePath(
          binding.relative_path, connection->gamecube_save_root, connection->wii_save_root);
      CanonicalPathAliasInfo alias_info_after =
          canonical_path_after ?
              InspectCanonicalPathForAliases(*canonical_path_after, m_sync_deadline) :
              CanonicalPathAliasInfo{};
      if (!canonical_path_after ||
          CanonicalPathKey(*canonical_path_after) != CanonicalPathKey(*canonical_path) ||
          !alias_info_after.safe || !alias_info_after.lookup_succeeded ||
          aliases_cached_other_binding(alias_info_after) ||
          std::ranges::any_of(processed_save_paths, [&](const CanonicalPathAliasInfo& processed) {
            return CanonicalPathAliasInfosMayAlias(processed, alias_info_after);
          }))
      {
        stats.deferred += static_cast<int>(ordered_bindings.size() - index - 1);
        ++stats.errors;
        stats.retry_needed = true;
        SetStatus("EmuBank stopped because a save path changed identity during reconciliation.");
        break;
      }
      processed_save_paths.emplace_back(std::move(alias_info_after));
    }

    if (!ConnectionStillConfigured(*connection))
      return false;

    const size_t cleared_path_selectors =
        std::erase_if(m_ancestor_invalidation_path_selectors, [&](const std::string& selector) {
          const auto matches = path_selector_binding_ids.find(selector);
          if (matches == path_selector_binding_ids.end() || matches->second.empty())
            return false;
          return std::ranges::all_of(matches->second, [&](const std::string& binding_id) {
            const auto state = m_state.find(binding_id);
            return state != m_state.end() && !state->second.ancestor_invalidated;
          });
        });
    const size_t cleared_game_selectors =
        std::erase_if(m_ancestor_invalidation_game_selectors, [&](const std::string& selector) {
          bool matched = false;
          const bool all_reconciled =
              std::ranges::all_of(manifest->bindings, [&](const Binding& binding) {
                if (!Common::CaseInsensitiveEquals(binding.game_id, selector))
                  return true;
                matched = true;
                const auto state = m_state.find(binding.id);
                return state != m_state.end() && !state->second.ancestor_invalidated;
              });
          return matched && all_reconciled;
        });
    m_state_dirty = m_state_dirty || cleared_path_selectors != 0 || cleared_game_selectors != 0;

    for (auto& [id, state] : m_state)
    {
      if (manifest_binding_ids.contains(id) || !carries_safety_state(state))
        continue;
      // A transient unbind/omission is not permanent-deletion evidence. Keep conservative state
      // but drop positive common-ancestor authority until the binding is observed again.
      if (!state.base_sha256.empty() || !state.revision_id.empty())
      {
        state.base_sha256.clear();
        state.revision_id.clear();
        m_state_dirty = true;
      }
    }
    const size_t erased =
        std::erase_if(m_state, [&manifest_binding_ids, &carries_safety_state](const auto& entry) {
          return !manifest_binding_ids.contains(entry.first) && !carries_safety_state(entry.second);
        });
    std::erase_if(m_pending_uploads, [&manifest_binding_ids](const auto& entry) {
      return !manifest_binding_ids.contains(entry.first);
    });
    m_state_dirty = m_state_dirty || erased != 0;
    if (m_state_dirty)
      SaveState();
    if (m_state_dirty)
    {
      ++stats.errors;
      stats.retry_needed = true;
      SetStatus("EmuBank could not durably finish its sync state; reconciliation will retry.");
    }

    // A stopped-game identity is durable in memory until both resolver evidence and the manifest
    // actions complete in a stopped pass. In particular, do not consume it on a Live deferral, a
    // changed download response, or a transient upload/download error.
    if (mode != SyncMode::Live && !timed_out && !stats.retry_needed && stats.errors == 0 &&
        stats.deferred == 0)
    {
      CompletePendingGameResolutions(resolution.pending_completions, manifest_binding_ids);
    }

    if (manifest->bindings.empty())
    {
      if (!resolution.notice.empty())
      {
        SetStatus(resolution.notice);
      }
      else
      {
        SetStatus("EmuBank is connected, but this device has no Dolphin save bindings. Nothing was "
                  "uploaded or downloaded. Start a GameCube game to link its GCI save.");
        DisplaySyncMessage("EmuBank: no Dolphin save is linked to this device", 6000,
                           OsdTone::Warning);
      }
    }
    else
    {
      std::string status = fmt::format("EmuBank sync{}: {} current, {} uploaded, {} downloaded",
                                       timed_out ? " timed out" : " complete", stats.current,
                                       stats.uploaded, stats.downloaded);
      if (stats.deferred)
        status += fmt::format(", {} deferred", stats.deferred);
      if (stats.conflicts)
        status += fmt::format(", {} conflict(s)", stats.conflicts);
      if (stats.errors)
        status += fmt::format(", {} error(s)", stats.errors);
      status += '.';
      if (!resolution.notice.empty())
        status += " " + resolution.notice;
      SetStatus(std::move(status));
      if (timed_out)
      {
        DisplaySyncMessage(fmt::format("EmuBank timed out; {} save(s) deferred", stats.deferred),
                           5000, OsdTone::Warning);
      }
      else if (stats.errors)
      {
        DisplaySyncMessage(
            fmt::format("EmuBank finished with {} error(s); it will retry", stats.errors), 6000,
            OsdTone::Error);
      }
      else if (stats.conflicts)
      {
        DisplaySyncMessage(
            fmt::format("EmuBank safely retained {} conflict copy/copies", stats.conflicts), 6000,
            OsdTone::Warning);
      }
      else if (stats.deferred)
      {
        DisplaySyncMessage(
            fmt::format("EmuBank deferred {} save(s); it will retry", stats.deferred), 5000,
            OsdTone::Warning);
      }
      else if (!resolution.notice.empty())
      {
        DisplaySyncMessage("EmuBank synced other saves; the active game needs attention", 6000,
                           OsdTone::Warning);
      }
      else
      {
        DisplaySyncMessage(fmt::format("EmuBank sync complete: {} uploaded, {} downloaded",
                                       stats.uploaded, stats.downloaded),
                           4000, OsdTone::Success);
      }
    }
    return !timed_out && !stats.retry_needed && !resolution.retry_needed &&
           ProcessStorageStillStable();
  }

  void LoadState()
  {
    namespace fs = std::filesystem;
    const std::string wii_save_root = EffectiveWiiSaveRoot();
    const fs::path state_path = StringToPath(StatePath());
    std::error_code status_error;
    const fs::file_status status = fs::symlink_status(state_path, status_error);
    if (status.type() == fs::file_type::not_found)
      return;
    if (status_error || !fs::is_regular_file(status))
    {
      m_state_unreadable.store(true, std::memory_order_release);
      return;
    }
    std::error_code size_error;
    const uintmax_t state_size = fs::file_size(state_path, size_error);
    if (size_error || state_size > MAX_DURABLE_STATE_FILE_SIZE)
    {
      m_state_unreadable.store(true, std::memory_order_release);
      return;
    }

    picojson::value root;
    std::string error;
    if (!JsonFromFile(StatePath(), &root, &error) || !root.is<picojson::object>())
    {
      m_state_unreadable.store(true, std::memory_order_release);
      return;
    }

    const auto& root_object = root.get<picojson::object>();
    const std::optional<double> state_version = ObjectNumber(root_object, "version");
    if (!state_version || *state_version != 1.0)
    {
      m_state_unreadable.store(true, std::memory_order_release);
      return;
    }
    m_state_capacity_exceeded =
        ReadBoolFromJson(root_object, "state_capacity_exceeded").value_or(false);
    m_state_server_url = ObjectString(root_object, "server_url").value_or("");
    m_state_device_id = ObjectString(root_object, "device_id").value_or("");
    if (const std::optional<double> recovery_generation =
            ObjectNumber(root_object, "recovery_generation");
        recovery_generation && *recovery_generation >= 0.0 &&
        *recovery_generation <= 9007199254740991.0 &&
        std::floor(*recovery_generation) == *recovery_generation)
    {
      m_recovery_generation = static_cast<u64>(*recovery_generation);
    }
    else if (root_object.contains("recovery_generation"))
    {
      m_recovery_journal_unreadable.store(true, std::memory_order_release);
    }
    m_ancestor_invalidation_pending =
        ReadBoolFromJson(root_object, "ancestor_invalidation_pending").value_or(false);
    const auto load_selector_array =
        [&root_object](std::string_view key, auto&& normalize,
                       std::set<std::string, std::less<>>* destination) {
          const auto found = root_object.find(std::string{key});
          if (found == root_object.end() || !found->second.is<picojson::array>())
            return false;
          const picojson::array& values = found->second.get<picojson::array>();
          if (values.size() > 512)
            return false;

          std::set<std::string, std::less<>> parsed;
          for (const picojson::value& value : values)
          {
            if (!value.is<std::string>())
              return false;
            const std::optional<std::string> normalized = normalize(value.get<std::string>());
            if (!normalized || !parsed.insert(*normalized).second)
              return false;
          }
          *destination = std::move(parsed);
          return true;
        };
    const bool game_selectors_valid = load_selector_array(
        "ancestor_invalidation_game_selectors",
        [](std::string selector) -> std::optional<std::string> {
          if (!IsSafeGameIdentifier(selector))
            return std::nullopt;
          Common::ToUpper(&selector);
          return selector;
        },
        &m_ancestor_invalidation_game_selectors);
    const bool path_selectors_valid = load_selector_array(
        "ancestor_invalidation_path_selectors",
        [](std::string selector) -> std::optional<std::string> {
          if (!ParseSavePathComponents(selector))
            return std::nullopt;
          return RelativePathKey(std::move(selector));
        },
        &m_ancestor_invalidation_path_selectors);
    m_ancestor_invalidation_selectors_complete =
        ReadBoolFromJson(root_object, "ancestor_invalidation_selectors_complete").value_or(false) &&
        game_selectors_valid && path_selectors_valid;
    if (!game_selectors_valid || !path_selectors_valid)
    {
      m_ancestor_invalidation_game_selectors.clear();
      m_ancestor_invalidation_path_selectors.clear();
      m_state_unreadable.store(true, std::memory_order_release);
    }
    const auto recovery_required_value = root_object.find("recovery_required");
    if (recovery_required_value != root_object.end() &&
        !recovery_required_value->second.is<picojson::object>())
    {
      m_recovery_journal_unreadable.store(true, std::memory_order_release);
    }
    if (const picojson::object* recovery_required = ObjectValue(root_object, "recovery_required"))
    {
      if (recovery_required->size() > MAX_RECOVERY_BLOCKS)
      {
        m_recovery_journal_unreadable.store(true, std::memory_order_release);
      }
      else
      {
        std::vector<CanonicalPathAliasInfo> recovery_aliases;
        recovery_aliases.reserve(recovery_required->size());
        for (const auto& [canonical_key, value] : *recovery_required)
        {
          // Keep the quarantine even when a removable/custom save root is currently unavailable.
          // Its armed absolute target, not the currently configured root, owns the transaction.
          if (!value.is<picojson::object>())
          {
            m_recovery_journal_unreadable.store(true, std::memory_order_release);
            continue;
          }
          const picojson::object& recovery_object = value.get<picojson::object>();
          const std::string relative_path =
              ObjectString(recovery_object, "relative_path").value_or("");
          const std::string canonical_path =
              ObjectString(recovery_object, "canonical_path").value_or("");
          std::string required_sha256 =
              ObjectString(recovery_object, "required_sha256").value_or("");
          Common::ToLower(&required_sha256);
          const bool cloud_reinstall_allowed =
              ReadBoolFromJson(recovery_object, "cloud_reinstall_allowed").value_or(false);
          CanonicalPathAliasInfo alias_info = InspectCanonicalPathForAliases(canonical_path);
          if (canonical_key != canonical_path || !IsSha256(required_sha256) ||
              !IsSafeRecoveryCanonicalPath(relative_path, canonical_path) ||
              std::ranges::any_of(recovery_aliases, [&](const CanonicalPathAliasInfo& existing) {
                return CanonicalPathAliasInfosMayAlias(existing, alias_info);
              }))
          {
            m_recovery_journal_unreadable.store(true, std::memory_order_release);
            continue;
          }
          if (!m_recovery_blocks
                   .emplace(RecoveryPathKey(canonical_path),
                            RecoveryBlock{relative_path, canonical_path, std::move(required_sha256),
                                          cloud_reinstall_allowed})
                   .second)
          {
            // Case/slash-distinct JSON keys can identify one Windows path. Treat that state copy
            // as unreadable rather than allowing its first required hash to win.
            m_recovery_journal_unreadable.store(true, std::memory_order_release);
          }
          else
          {
            recovery_aliases.emplace_back(std::move(alias_info));
          }
        }
      }
    }
    const auto bindings = ObjectValue(root_object, "bindings");
    if (!bindings || bindings->size() > MAX_DURABLE_STATE_BINDINGS)
    {
      m_state_unreadable.store(true, std::memory_order_release);
      return;
    }

    for (const auto& [id, value] : *bindings)
    {
      if (!IsSafeIdentifier(id) || !value.is<picojson::object>())
      {
        m_state_unreadable.store(true, std::memory_order_release);
        continue;
      }
      const auto& object = value.get<picojson::object>();
      const std::string relative_path = ObjectString(object, "relative_path").value_or("");
      const std::string canonical_path = ObjectString(object, "canonical_path").value_or("");
      const auto resolved_path =
          ResolveSavePath(relative_path, m_gamecube_save_root, wii_save_root);
      if (!resolved_path || canonical_path.empty() ||
          CanonicalPathKey(*resolved_path) != CanonicalPathKey(canonical_path))
      {
        std::string rejected_revision_id =
            ObjectString(object, "rejected_explicit_revision_id").value_or("");
        std::string rejected_sha256 = ObjectString(object, "rejected_explicit_sha256").value_or("");
        Common::ToLower(&rejected_sha256);
        if (!IsSafeIdentifier(rejected_revision_id) || !IsSha256(rejected_sha256))
        {
          rejected_revision_id = ObjectString(object, "explicit_revision_id").value_or("");
          rejected_sha256 = ObjectString(object, "explicit_sha256").value_or("");
          Common::ToLower(&rejected_sha256);
        }
        const bool preserve_rejected_selection =
            IsSafeIdentifier(rejected_revision_id) && IsSha256(rejected_sha256);
        // Legacy entries and entries from another root/path lose authority, but never lose a
        // conservative savestate taint. Every identity change also keeps a negative explicit
        // revision tombstone so retargeting the binding cannot reauthorize the rejected download.
        // StateForBinding binds this minimal record to the next validated path without transferring
        // any positive upload/download authority.
        if (ReadBoolFromJson(object, "ancestor_invalidated").value_or(false) ||
            m_ancestor_invalidation_pending || preserve_rejected_selection)
        {
          LocalState state;
          state.ancestor_invalidated =
              ReadBoolFromJson(object, "ancestor_invalidated").value_or(false) ||
              m_ancestor_invalidation_pending;
          if (preserve_rejected_selection)
          {
            state.rejected_explicit_revision_id = std::move(rejected_revision_id);
            state.rejected_explicit_sha256 = std::move(rejected_sha256);
          }
          state.relative_path = relative_path;
          if (resolved_path)
            state.canonical_path = *resolved_path;
          m_state.emplace(id, std::move(state));
        }
        continue;
      }
      const std::optional<bool> explicit_local_present =
          ReadBoolFromJson(object, "explicit_local_present");
      LocalState state{ObjectString(object, "base_sha256").value_or(""),
                       ObjectString(object, "revision_id").value_or(""),
                       ReadBoolFromJson(object, "conflict_pending").value_or(false),
                       ObjectString(object, "conflict_sha256").value_or(""),
                       ReadBoolFromJson(object, "ancestor_invalidated").value_or(false),
                       ObjectString(object, "explicit_revision_id").value_or(""),
                       ObjectString(object, "explicit_sha256").value_or(""),
                       explicit_local_present.value_or(false),
                       ObjectString(object, "explicit_local_sha256").value_or(""),
                       ObjectString(object, "rejected_explicit_revision_id").value_or(""),
                       ObjectString(object, "rejected_explicit_sha256").value_or(""),
                       relative_path,
                       canonical_path};
      if (m_ancestor_invalidation_pending)
        state.ancestor_invalidated = true;
      Common::ToLower(&state.base_sha256);
      Common::ToLower(&state.conflict_sha256);
      Common::ToLower(&state.explicit_sha256);
      Common::ToLower(&state.explicit_local_sha256);
      Common::ToLower(&state.rejected_explicit_sha256);
      if (!IsSha256(state.base_sha256) || !IsSafeIdentifier(state.revision_id))
      {
        state.base_sha256.clear();
        state.revision_id.clear();
      }
      if (!IsSha256(state.conflict_sha256))
        state.conflict_sha256.clear();
      const bool valid_explicit_local =
          explicit_local_present &&
          (state.explicit_local_present ? IsSha256(state.explicit_local_sha256) :
                                          state.explicit_local_sha256.empty());
      if (!IsSafeIdentifier(state.explicit_revision_id) || !IsSha256(state.explicit_sha256) ||
          !valid_explicit_local)
      {
        state.explicit_revision_id.clear();
        state.explicit_sha256.clear();
        state.explicit_local_present = false;
        state.explicit_local_sha256.clear();
      }
      if (!IsSafeIdentifier(state.rejected_explicit_revision_id) ||
          !IsSha256(state.rejected_explicit_sha256))
      {
        state.rejected_explicit_revision_id.clear();
        state.rejected_explicit_sha256.clear();
      }
      if ((IsSha256(state.base_sha256) && IsSafeIdentifier(state.revision_id)) ||
          state.conflict_pending || state.ancestor_invalidated ||
          !state.explicit_revision_id.empty() || !state.rejected_explicit_revision_id.empty())
        m_state.emplace(id, std::move(state));
    }
  }

  bool StateIdentityMatches(const LocalState& state, const std::string& canonical_path) const
  {
    return !state.canonical_path.empty() &&
           CanonicalPathKey(state.canonical_path) == CanonicalPathKey(canonical_path);
  }

  void EnsureStateIdentity(const Binding& binding, const std::string& canonical_path)
  {
    const auto found = m_state.find(binding.id);
    if (found == m_state.end())
      return;
    if (StateIdentityMatches(found->second, canonical_path))
    {
      // Exact canonical identity preserves the existing safety state. Refresh only the
      // server-facing relative spelling used for diagnostics and persistence.
      if (found->second.relative_path != binding.relative_path)
      {
        found->second.relative_path = binding.relative_path;
        m_state_dirty = true;
      }
      if (found->second.canonical_path != canonical_path)
      {
        found->second.canonical_path = canonical_path;
        m_state_dirty = true;
      }
      return;
    }

    // Binding IDs and configured roots are mutable server/user state. Never transfer ancestry,
    // conflict, or one-shot replacement authority to a different local file.
    const bool ancestor_invalidated = found->second.ancestor_invalidated;
    std::string rejected_revision_id;
    std::string rejected_sha256;
    if (IsSafeIdentifier(found->second.rejected_explicit_revision_id) &&
        IsSha256(found->second.rejected_explicit_sha256))
    {
      rejected_revision_id = std::move(found->second.rejected_explicit_revision_id);
      rejected_sha256 = std::move(found->second.rejected_explicit_sha256);
    }
    else if (IsSafeIdentifier(found->second.explicit_revision_id) &&
             IsSha256(found->second.explicit_sha256))
    {
      // A positive choice is bound to the old identity. Convert it to a negative record so the
      // same still-pending selection cannot be rebound to a newly targeted local file.
      rejected_revision_id = std::move(found->second.explicit_revision_id);
      rejected_sha256 = std::move(found->second.explicit_sha256);
    }
    found->second = {};
    // Drop positive ancestry/selection authority on any path change. Negative safety state must
    // survive every retargeting, or the server could revive the same pending revision for a new
    // path without observing a genuinely new user selection cycle.
    found->second.ancestor_invalidated = ancestor_invalidated;
    found->second.rejected_explicit_revision_id = std::move(rejected_revision_id);
    found->second.rejected_explicit_sha256 = std::move(rejected_sha256);
    found->second.relative_path = binding.relative_path;
    found->second.canonical_path = canonical_path;
    m_pending_uploads.erase(binding.id);
    m_state_dirty = true;
  }

  LocalState& StateForBinding(const Binding& binding, const std::string& canonical_path)
  {
    EnsureStateIdentity(binding, canonical_path);
    auto [it, inserted] = m_state.try_emplace(binding.id);
    if (inserted)
    {
      it->second.relative_path = binding.relative_path;
      it->second.canonical_path = canonical_path;
      m_state_dirty = true;
    }
    return it->second;
  }

  void UpdateState(const Binding& binding, const std::string& canonical_path,
                   const std::string& sha256, const std::string& revision_id)
  {
    LocalState& state = StateForBinding(binding, canonical_path);

    if (state.base_sha256 != sha256 || state.revision_id != revision_id || state.conflict_pending ||
        state.ancestor_invalidated || !state.explicit_revision_id.empty())
    {
      std::string relative_path = std::move(state.relative_path);
      std::string bound_canonical_path = std::move(state.canonical_path);
      std::string rejected_revision_id;
      std::string rejected_sha256;
      if (IsSafeIdentifier(state.rejected_explicit_revision_id) &&
          IsSha256(state.rejected_explicit_sha256))
      {
        rejected_revision_id = std::move(state.rejected_explicit_revision_id);
        rejected_sha256 = std::move(state.rejected_explicit_sha256);
      }
      else if (IsSafeIdentifier(state.explicit_revision_id) && IsSha256(state.explicit_sha256))
      {
        // Current bytes do not prove that the authenticated one-shot selection was consumed.
        // Keep it as a negative record until the server removes or changes the pending marker.
        rejected_revision_id = std::move(state.explicit_revision_id);
        rejected_sha256 = std::move(state.explicit_sha256);
      }
      state = {};
      state.base_sha256 = sha256;
      state.revision_id = revision_id;
      // The server pending marker, not a coincidental Current/upload/download transition, defines
      // a new explicit-selection cycle. ProcessBinding clears a nonmatching tombstone before this
      // point; retain a matching negative authorization until that marker disappears or changes.
      state.rejected_explicit_revision_id = std::move(rejected_revision_id);
      state.rejected_explicit_sha256 = std::move(rejected_sha256);
      state.relative_path = relative_path;
      state.canonical_path = bound_canonical_path;
      m_state_dirty = true;
    }
  }

  bool RememberExplicitDownload(const Connection& connection, const Binding& binding,
                                const std::optional<std::string>& local_sha256)
  {
    if (!binding.explicit_download_pending || !binding.current_revision)
      return false;

    if (!m_state.contains(binding.id) && m_state.size() >= MAX_DURABLE_STATE_BINDINGS)
    {
      if (!m_state_capacity_exceeded.exchange(true, std::memory_order_acq_rel))
      {
        m_state_dirty = true;
        SaveState();
      }
      UpdateRecoveryVeto();
      SetStatus("EmuBank blocked a new binding because its durable safety-state limit was "
                "reached. Reduce the server binding set, then retry.");
      return false;
    }

    const auto canonical_path = ResolveSavePath(
        binding.relative_path, connection.gamecube_save_root, connection.wii_save_root);
    if (!canonical_path)
      return false;

    LocalState& state = StateForBinding(binding, *canonical_path);
    if (m_ancestor_invalidation_pending && !state.ancestor_invalidated)
    {
      state.ancestor_invalidated = true;
      m_state_dirty = true;
    }
    const bool rejected_same_selection =
        state.rejected_explicit_revision_id == binding.current_revision->id &&
        state.rejected_explicit_sha256 == binding.current_revision->sha256;
    if (rejected_same_selection)
    {
      if (m_state_dirty)
        SaveState();
      return !m_state_dirty;
    }
    if (!state.rejected_explicit_revision_id.empty() || !state.rejected_explicit_sha256.empty())
    {
      state.rejected_explicit_revision_id.clear();
      state.rejected_explicit_sha256.clear();
      m_state_dirty = true;
    }
    // Do not broaden an already-recorded choice to a different local snapshot. If that snapshot
    // changed between resolver and manifest, ProcessBinding replaces it with a durable tombstone.
    if (state.explicit_revision_id != binding.current_revision->id ||
        state.explicit_sha256 != binding.current_revision->sha256)
    {
      state.explicit_revision_id = binding.current_revision->id;
      state.explicit_sha256 = binding.current_revision->sha256;
      state.explicit_local_present = local_sha256.has_value();
      state.explicit_local_sha256 = local_sha256.value_or("");
      m_state_dirty = true;
    }
    if (m_state_dirty)
      SaveState();
    return !m_state_dirty;
  }

  void SaveState()
  {
    if (!ProcessStorageStillStable())
    {
      ERROR_LOG_FMT(CORE, "EmuBank: refused to write state after its Config directory changed");
      return;
    }
    picojson::object bindings;
    for (const auto& [id, state] : m_state)
    {
      bindings.emplace(
          id, picojson::value{picojson::object{
                  {"base_sha256", picojson::value{state.base_sha256}},
                  {"revision_id", picojson::value{state.revision_id}},
                  {"conflict_pending", picojson::value{state.conflict_pending}},
                  {"conflict_sha256", picojson::value{state.conflict_sha256}},
                  {"ancestor_invalidated", picojson::value{state.ancestor_invalidated}},
                  {"explicit_revision_id", picojson::value{state.explicit_revision_id}},
                  {"explicit_sha256", picojson::value{state.explicit_sha256}},
                  {"explicit_local_present", picojson::value{state.explicit_local_present}},
                  {"explicit_local_sha256", picojson::value{state.explicit_local_sha256}},
                  {"rejected_explicit_revision_id",
                   picojson::value{state.rejected_explicit_revision_id}},
                  {"rejected_explicit_sha256", picojson::value{state.rejected_explicit_sha256}},
                  {"relative_path", picojson::value{state.relative_path}},
                  {"canonical_path", picojson::value{state.canonical_path}}}});
    }
    picojson::object recovery_required;
    for (const auto& [canonical_key, recovery] : m_recovery_blocks)
    {
      (void)canonical_key;
      recovery_required.emplace(
          recovery.canonical_path,
          picojson::value{picojson::object{
              {"relative_path", picojson::value{recovery.relative_path}},
              {"canonical_path", picojson::value{recovery.canonical_path}},
              {"required_sha256", picojson::value{recovery.required_sha256}},
              {"cloud_reinstall_allowed", picojson::value{recovery.cloud_reinstall_allowed}}}});
    }
    picojson::array ancestor_invalidation_game_selectors;
    for (const std::string& selector : m_ancestor_invalidation_game_selectors)
      ancestor_invalidation_game_selectors.emplace_back(selector);
    picojson::array ancestor_invalidation_path_selectors;
    for (const std::string& selector : m_ancestor_invalidation_path_selectors)
      ancestor_invalidation_path_selectors.emplace_back(selector);

    const std::string json = picojson::value{
        picojson::object{
            {"version", picojson::value{1.0}},
            {"server_url", picojson::value{m_state_server_url}},
            {"device_id", picojson::value{m_state_device_id}},
            {"state_capacity_exceeded",
             picojson::value{m_state_capacity_exceeded.load(std::memory_order_acquire)}},
            {"ancestor_invalidation_pending", picojson::value{m_ancestor_invalidation_pending}},
            {"ancestor_invalidation_selectors_complete",
             picojson::value{m_ancestor_invalidation_selectors_complete}},
            {"ancestor_invalidation_game_selectors",
             picojson::value{std::move(ancestor_invalidation_game_selectors)}},
            {"ancestor_invalidation_path_selectors",
             picojson::value{std::move(ancestor_invalidation_path_selectors)}},
            {"recovery_generation", picojson::value{static_cast<double>(m_recovery_generation)}},
            {"recovery_required", picojson::value{std::move(recovery_required)}},
            {"bindings",
             picojson::value{std::move(
                 bindings)}}}}.serialize(true);
    if (json.size() > MAX_DURABLE_STATE_FILE_SIZE)
    {
      m_state_unreadable.store(true, std::memory_order_release);
      UpdateRecoveryVeto();
      ERROR_LOG_FMT(CORE, "EmuBank: refused to write oversized local sync state");
      return;
    }
    const std::span<const u8> bytes{reinterpret_cast<const u8*>(json.data()), json.size()};
    if (WriteAtomically(StatePath(), bytes))
      m_state_dirty = false;
    else
      ERROR_LOG_FMT(CORE, "EmuBank: failed to save local sync state");
  }

  std::string StatePath() const { return m_config_root + "EmuBankSyncState.json"; }

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
  bool m_immediate_sync_requested = false;
  bool m_stop = false;
  std::optional<std::chrono::steady_clock::time_point> m_automatic_request_time;
  std::optional<std::chrono::steady_clock::time_point> m_save_sync_deadline;
  std::optional<std::chrono::steady_clock::time_point> m_last_automatic_sync;
  u64 m_save_event_generation = 0;
  u64 m_consumed_save_event_generation = 0;
  u64 m_requested_generation = 0;
  u64 m_completed_generation = 0;
  std::atomic<u64> m_last_attempted_generation = 0;
  std::atomic<u64> m_final_sync_generation = 0;
  std::thread m_worker;
  std::mutex m_prelaunch_thread_mutex;
  std::thread m_prelaunch_thread;
  std::atomic<bool> m_prelaunch_in_progress = false;

  CrossThreadTimedGate m_sync_mutex;
  std::optional<std::unique_lock<CrossThreadTimedGate>> m_savestate_sync_gate;
  std::vector<std::unique_ptr<InterprocessSyncLock>> m_process_locks;
  std::vector<ProcessLockDirectoryAlias> m_active_process_lock_aliases;
  std::optional<FileIdentity> m_durable_state_config_identity;
  bool m_durable_state_config_was_missing = false;
  std::atomic<bool> m_process_lock_admission_started = false;
  std::chrono::steady_clock::time_point m_sync_deadline{};
  std::atomic<bool> m_is_syncing = false;
  std::atomic<bool> m_emulation_active = false;
  std::atomic<bool> m_launch_pending = false;
  std::atomic<bool> m_canonical_recovery_required = false;
  const std::string m_config_root;
  const std::string m_gamecube_save_root;
  std::string m_effective_wii_save_root;
  std::mutex m_save_install_mutex;
  mutable std::mutex m_active_game_mutex;
  std::optional<GameIdentity> m_active_game;
  std::string m_launch_priority_game_id;
  std::set<std::string, std::less<>> m_launch_priority_paths;
  u64 m_next_game_resolution_token = 0;
  std::vector<PendingGameResolution> m_pending_game_resolutions;
  std::set<std::string, std::less<>> m_resolved_save_paths;
  // Armed on the CPU thread before savestate deserialization and consumed by the sync worker. The
  // paired durable marker survives a crash; m_sync_mutex prevents an admitted load from racing an
  // in-flight reconciliation pass.
  std::atomic<bool> m_invalidate_ancestors_requested = false;
  std::vector<std::string> m_pending_ancestor_marker_paths;
  std::string m_state_server_url;
  std::string m_state_device_id;
  std::map<std::string, LocalState, std::less<>> m_state;
  std::map<std::string, PendingUpload, std::less<>> m_pending_uploads;
  // Credential-independent canonical-path quarantine. A fatal namespace recovery may retain the
  // desired inode outside the live save path; no launch may silently accept another body there.
  std::map<std::string, RecoveryBlock, std::less<>> m_recovery_blocks;
  std::string m_last_recovery_check_key;
  u64 m_recovery_generation = 0;
  std::atomic<bool> m_recovery_persistence_failed = false;
  std::atomic<bool> m_recovery_journal_unreadable = false;
  std::atomic<bool> m_state_unreadable = false;
  std::atomic<bool> m_process_storage_changed = false;
  std::atomic<bool> m_state_capacity_exceeded = false;
  bool m_ancestor_invalidation_pending = false;
  bool m_ancestor_invalidation_selectors_complete = false;
  std::set<std::string, std::less<>> m_ancestor_invalidation_game_selectors;
  std::set<std::string, std::less<>> m_ancestor_invalidation_path_selectors;
  bool m_state_dirty = false;

  std::mutex m_config_snapshot_mutex;
  SyncConfig m_last_sync_config;
  std::atomic<bool> m_config_changed_during_sync = false;

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

  Common::EventHook m_before_boot_hook;
  Common::EventHook m_boot_attempt_finished_hook;
  Common::EventHook m_state_changed_hook;
  Common::EventHook m_save_data_changed_hook;
  Common::EventHook m_before_savestate_load_hook;
  Common::EventHook m_savestate_load_finished_hook;
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
    manager->Request(RequestPriority::UserInitiated);
}

bool IsSyncing()
{
  std::shared_ptr<Manager> manager;
  {
    std::lock_guard lock(s_manager_mutex);
    manager = s_manager;
  }
  return manager && manager->IsSyncing();
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
