// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace UICommon::EmuBank::Policy
{
// Ages within the comparison margin deliberately have unknown ordering. Filesystem timestamps and
// server clocks are not precise enough to choose a destructive winner in that case.
enum class SaveRecency
{
  Unknown,
  LocalNewer,
  CloudNewer,
};

enum class Action
{
  Current,
  Upload,
  Download,
  KeepLocal,
  Defer,
};

enum class UploadBase
{
  None,
  NoAncestor,
  TrustedBase,
  CurrentCloud,
};

struct Input
{
  bool server_conflict = false;
  bool cloud_present = false;
  bool local_present = false;
  bool local_matches_cloud = false;
  bool can_upload = false;
  bool can_download = false;
  bool downloads_open = false;
  bool server_requests_download = false;
  bool server_explicit_download = false;
  bool has_trusted_base = false;
  bool local_matches_base = false;
  bool cloud_matches_base = false;
  bool ancestor_invalidated = false;
  bool conflict_pending = false;
  bool local_matches_conflict = false;
  SaveRecency recency = SaveRecency::Unknown;
};

struct Decision
{
  Action action = Action::Defer;
  UploadBase upload_base = UploadBase::None;

  bool operator==(const Decision&) const = default;
};

// A lower age is newer. Require a strict gap greater than margin so clock jitter near the boundary
// never authorizes an overwrite.
constexpr SaveRecency CompareAges(std::chrono::seconds local_age, std::chrono::seconds cloud_age,
                                  std::chrono::seconds margin = std::chrono::seconds{5})
{
  if (margin < std::chrono::seconds::zero())
    margin = std::chrono::seconds::zero();

  if (local_age < cloud_age && cloud_age - local_age > margin)
    return SaveRecency::LocalNewer;
  if (cloud_age < local_age && local_age - cloud_age > margin)
    return SaveRecency::CloudNewer;
  return SaveRecency::Unknown;
}

constexpr std::chrono::steady_clock::time_point
MinimumAutomaticDeadline(std::optional<std::chrono::steady_clock::time_point> last_attempt,
                         std::chrono::seconds interval,
                         std::chrono::steady_clock::time_point requested_at)
{
  if (!last_attempt)
    return requested_at;
  if (interval < std::chrono::seconds::zero())
    interval = std::chrono::seconds::zero();
  return std::max(requested_at, *last_attempt + interval);
}

constexpr std::chrono::steady_clock::time_point
SaveEventAutomaticDeadline(std::optional<std::chrono::steady_clock::time_point> last_attempt,
                           std::chrono::seconds interval,
                           std::chrono::steady_clock::time_point quiet_deadline,
                           bool unattempted_live_save_event)
{
  // A newly flushed in-game save is the payload Live Sync exists to protect. Its first upload
  // attempt begins as soon as the save has stayed quiet long enough to snapshot safely; the
  // configured automatic cadence still rate-limits retries and stopped-emulation housekeeping.
  if (unattempted_live_save_event)
    return quiet_deadline;
  return MinimumAutomaticDeadline(last_attempt, interval, quiet_deadline);
}

constexpr bool FreshLiveSaveEventPending(bool emulation_active, std::uint64_t attempted_generation,
                                         std::uint64_t latest_generation)
{
  return emulation_active && latest_generation > attempted_generation;
}

constexpr std::uint64_t AdvanceAttemptedSaveGeneration(std::uint64_t attempted_generation,
                                                       std::uint64_t covered_generation)
{
  return std::max(attempted_generation, covered_generation);
}

constexpr bool
LiveSaveEventsReady(bool save_event_pending,
                    std::optional<std::chrono::steady_clock::time_point> quiet_deadline,
                    std::chrono::steady_clock::time_point now)
{
  return !save_event_pending || (quiet_deadline && now >= *quiet_deadline);
}

constexpr std::uint64_t CoveredSaveGeneration(bool pass_is_live, bool live_save_events_ready,
                                              std::uint64_t consumed_generation,
                                              std::uint64_t latest_generation)
{
  return pass_is_live && !live_save_events_ready ? consumed_generation : latest_generation;
}

// The original version-1 durable-state writer predated scoped savestate invalidation and emitted
// none of these four fields. Only that complete legacy shape may omit the selector arrays. Once
// any selector-era field is present, requiring both arrays keeps a torn or manually damaged state
// file from silently broadening an invalidation to the wrong game or save path.
constexpr bool DurableSelectorArraysMayBeOmitted(bool has_pending, bool has_selectors_complete,
                                                 bool has_game_selectors, bool has_path_selectors)
{
  return !has_pending && !has_selectors_complete && !has_game_selectors && !has_path_selectors;
}

constexpr bool ResolverLocalMatches(bool expected_present, std::string_view expected_sha256,
                                    bool local_present, std::string_view local_sha256)
{
  return expected_present == local_present &&
         (!expected_present || expected_sha256 == local_sha256);
}

constexpr bool ExplicitDownloadMatches(std::string_view action,
                                       std::string_view pending_revision_id,
                                       std::string_view pending_sha256,
                                       std::string_view current_revision_id,
                                       std::string_view current_sha256)
{
  return action == "download_if_different" && pending_revision_id == current_revision_id &&
         pending_sha256 == current_sha256;
}

constexpr bool DurableExplicitDownloadMatches(std::string_view selected_revision_id,
                                              std::string_view selected_sha256,
                                              std::string_view current_revision_id,
                                              std::string_view current_sha256,
                                              bool expected_local_present,
                                              std::string_view expected_local_sha256,
                                              bool local_present, std::string_view local_sha256)
{
  return selected_revision_id == current_revision_id && selected_sha256 == current_sha256 &&
         ResolverLocalMatches(expected_local_present, expected_local_sha256, local_present,
                              local_sha256);
}

constexpr char AsciiLower(char value)
{
  return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

constexpr bool AsciiCaseInsensitiveEquals(std::string_view left, std::string_view right)
{
  if (left.size() != right.size())
    return false;
  for (std::size_t index = 0; index < left.size(); ++index)
  {
    if (AsciiLower(left[index]) != AsciiLower(right[index]))
      return false;
  }
  return true;
}

constexpr bool IsAscii(std::string_view value)
{
  for (const char byte : value)
  {
    if (static_cast<unsigned char>(byte) >= 0x80)
      return false;
  }
  return true;
}

constexpr bool IsWellFormedUtf8(std::string_view value)
{
  for (std::size_t index = 0; index < value.size();)
  {
    const auto lead = static_cast<unsigned char>(value[index++]);
    if (lead < 0x80)
      continue;

    std::size_t continuation_count = 0;
    std::uint32_t code_point = 0;
    std::uint32_t minimum = 0;
    if ((lead & 0xe0) == 0xc0)
    {
      continuation_count = 1;
      code_point = lead & 0x1f;
      minimum = 0x80;
    }
    else if ((lead & 0xf0) == 0xe0)
    {
      continuation_count = 2;
      code_point = lead & 0x0f;
      minimum = 0x800;
    }
    else if ((lead & 0xf8) == 0xf0)
    {
      continuation_count = 3;
      code_point = lead & 0x07;
      minimum = 0x10000;
    }
    else
    {
      return false;
    }

    if (value.size() - index < continuation_count)
      return false;
    for (std::size_t continuation = 0; continuation < continuation_count; ++continuation)
    {
      const auto byte = static_cast<unsigned char>(value[index++]);
      if ((byte & 0xc0) != 0x80)
        return false;
      code_point = (code_point << 6) | (byte & 0x3f);
    }
    if (code_point < minimum || code_point > 0x10ffff ||
        (code_point >= 0xd800 && code_point <= 0xdfff))
    {
      return false;
    }
  }
  return true;
}

constexpr bool IsWindowsDeviceStem(std::string_view stem)
{
  while (!stem.empty() && (stem.back() == ' ' || stem.back() == '.'))
    stem.remove_suffix(1);

  if (AsciiCaseInsensitiveEquals(stem, "con") || AsciiCaseInsensitiveEquals(stem, "prn") ||
      AsciiCaseInsensitiveEquals(stem, "aux") || AsciiCaseInsensitiveEquals(stem, "nul") ||
      AsciiCaseInsensitiveEquals(stem, "clock$") || AsciiCaseInsensitiveEquals(stem, "conin$") ||
      AsciiCaseInsensitiveEquals(stem, "conout$"))
  {
    return true;
  }

  if (stem.size() == 4 &&
      (AsciiCaseInsensitiveEquals(stem.substr(0, 3), "com") ||
       AsciiCaseInsensitiveEquals(stem.substr(0, 3), "lpt")) &&
      stem[3] >= '1' && stem[3] <= '9')
  {
    return true;
  }

  // Win32 also treats the ISO-8859-1 superscript digits 1, 2, and 3 as device-number aliases.
  return stem.size() == 5 &&
         (AsciiCaseInsensitiveEquals(stem.substr(0, 3), "com") ||
          AsciiCaseInsensitiveEquals(stem.substr(0, 3), "lpt")) &&
         static_cast<unsigned char>(stem[3]) == 0xc2 &&
         (static_cast<unsigned char>(stem[4]) == 0xb9 ||
          static_cast<unsigned char>(stem[4]) == 0xb2 ||
          static_cast<unsigned char>(stem[4]) == 0xb3);
}

constexpr bool IsPlausibleDosShortComponent(std::string_view component)
{
  if (!IsAscii(component))
    return false;

  const std::size_t first_dot = component.find('.');
  if (first_dot != std::string_view::npos &&
      component.find('.', first_dot + 1) != std::string_view::npos)
    return false;
  const std::string_view stem = component.substr(0, first_dot);
  const std::string_view extension =
      first_dot == std::string_view::npos ? std::string_view{} : component.substr(first_dot + 1);
  if (stem.empty() || stem.size() > 8 || extension.size() > 3)
    return false;

  const std::size_t tilde = stem.rfind('~');
  if (tilde == std::string_view::npos || tilde == 0 || tilde + 1 == stem.size())
    return false;
  for (const char digit : stem.substr(tilde + 1))
  {
    if (digit < '0' || digit > '9')
      return false;
  }
  return true;
}

// Cloud paths use one portable namespace on every Dolphin platform. Reject spellings that Win32
// aliases or cannot represent, even on a case-sensitive host, so a later device cannot interpret
// one binding as a different local file.
constexpr bool IsPortablePathComponent(std::string_view component)
{
  if (component.empty() || component == "." || component == ".." || component.front() == ' ' ||
      component.back() == ' ' || component.back() == '.' || !IsWellFormedUtf8(component))
  {
    return false;
  }

  for (std::size_t index = 0; index < component.size(); ++index)
  {
    const char value = component[index];
    const auto byte = static_cast<unsigned char>(value);
    if (byte < 0x20 || byte == 0x7f || value == '<' || value == '>' || value == ':' ||
        value == '"' || value == '/' || value == '\\' || value == '|' || value == '?' ||
        value == '*')
    {
      return false;
    }
  }

  const std::size_t first_dot = component.find('.');
  return !IsWindowsDeviceStem(component.substr(0, first_dot));
}

// Returning false means that the filesystem might identify these two components. Unicode case
// and normalization rules vary by volume, so only a differing all-ASCII pair proves distinction.
constexpr bool PathComponentsDefinitelyDistinct(std::string_view left, std::string_view right)
{
  if (!IsAscii(left) || !IsAscii(right) || IsPlausibleDosShortComponent(left) ||
      IsPlausibleDosShortComponent(right))
    return false;
  return !AsciiCaseInsensitiveEquals(left, right);
}

// Binding targets are regular files. Alias-compatible equality is one owner collision, and an
// alias-compatible prefix is another because one target would have to be the parent directory of
// the other. Only a provably distinct component can make the two sequences coexist safely.
template <typename LeftRange, typename RightRange>
constexpr bool PathTargetComponentSequencesMayConflict(const LeftRange& left,
                                                       const RightRange& right)
{
  auto left_component = left.begin();
  auto right_component = right.begin();
  while (left_component != left.end() && right_component != right.end())
  {
    if (PathComponentsDefinitelyDistinct(*left_component, *right_component))
      return false;
    ++left_component;
    ++right_component;
  }
  return true;
}

constexpr Decision Decide(const Input& input)
{
  constexpr Decision current{Action::Current, UploadBase::None};
  constexpr Decision keep_local{Action::KeepLocal, UploadBase::None};
  constexpr Decision defer{Action::Defer, UploadBase::None};

  const auto download = [&input] {
    return input.downloads_open ? Decision{Action::Download, UploadBase::None} :
                                  Decision{Action::Defer, UploadBase::None};
  };
  const auto upload = [](UploadBase base) { return Decision{Action::Upload, base}; };

  if (!input.local_present)
  {
    if (!input.cloud_present)
      return current;
    return input.can_download ? download() : defer;
  }

  if (input.cloud_present && input.local_matches_cloud)
    return current;

  // Download-only is an explicit request to make EmuBank authoritative, including while the
  // server retains a separate conflict revision. No other mode may download an unresolved
  // conflict over divergent local bytes.
  if (!input.can_upload && input.can_download)
    return input.cloud_present ? download() : keep_local;

  if (input.server_conflict)
  {
    // A foreign conflict supplies no proof about the ancestry of this installation's file.
    if (!input.conflict_pending)
      return keep_local;

    // This installation already retained these exact bytes as the conflict revision. If their
    // local write time proves they are newer than the still-selected cloud revision, promote that
    // known conflict copy with a compare-and-swap instead of repeatedly returning 409. A later
    // edit remains a genuine divergence and must use the guarded path below.
    if (!input.ancestor_invalidated && input.local_matches_conflict &&
        input.recency == SaveRecency::LocalNewer && input.can_upload)
      return upload(UploadBase::CurrentCloud);

    // Preserve both the immutable conflict copy and the previously trusted local base while the
    // conflict is unresolved. A subsequent local edit may be uploaded, but only with a guarded
    // base so it cannot silently replace the selected cloud revision.
    if (input.local_matches_conflict || (input.has_trusted_base && input.local_matches_base))
    {
      return keep_local;
    }
    if (!input.can_upload)
      return keep_local;
    if (input.ancestor_invalidated || !input.has_trusted_base)
      return upload(UploadBase::NoAncestor);
    return upload(UploadBase::TrustedBase);
  }

  if (!input.cloud_present)
    return input.can_upload ? upload(UploadBase::NoAncestor) : keep_local;

  // Savestate-derived bytes have no trustworthy relationship to the recorded base.
  if (input.ancestor_invalidated)
    return input.can_upload ? upload(UploadBase::NoAncestor) : keep_local;

  // A server revision selection is a user decision, not ordinary resolver inference. The client
  // accepts it only when separately authenticated against the binding's pending reconciliation
  // metadata and the exact resolver revision/local report.
  if (input.server_explicit_download && input.server_requests_download)
    return input.can_download ? download() : keep_local;

  // The server becoming active while the unchanged retained conflict remains local proves that a
  // conflict resolution selected the current cloud revision. This is the sole two-way conflict
  // path that may replace those retained bytes, and only while no savestate invalidation is
  // pending.
  if (input.conflict_pending && input.local_matches_conflict)
    return input.can_download ? download() : keep_local;

  // A cloud pointer move is not proof that its contents are newer: EmuBank can reactivate an
  // existing historical revision. Therefore a clearly newer local file wins before ordinary
  // resolver advice or the trusted-base matrix can authorize a download. Compare-and-swap against
  // the manifest's current hash so a concurrent cloud change still leaves the local file intact.
  // The authenticated explicit-selection branches above remain the only two-way exceptions.
  if (input.recency == SaveRecency::LocalNewer)
    return input.can_upload ? upload(UploadBase::CurrentCloud) : keep_local;

  // Ordinary active-game resolver advice is only a hint: it can come from a known-hash heuristic
  // after the server reactivates an older revision. Let the ancestry matrix below authorize a
  // replacement only when hashes prove that local is still the unchanged common base. Without
  // that proof, preserve/upload local bytes even when timestamp ordering is unknown or cloud-newer.

  if (!input.has_trusted_base)
  {
    switch (input.recency)
    {
    case SaveRecency::LocalNewer:
      return keep_local;  // Handled before resolver and ancestry decisions above.
    case SaveRecency::CloudNewer:
      // A revision can contain an older save that was uploaded later, so its creation time alone
      // can never authorize replacing divergent local bytes.
      return input.can_upload ? upload(UploadBase::NoAncestor) : keep_local;
    case SaveRecency::Unknown:
      return input.can_upload ? upload(UploadBase::NoAncestor) : keep_local;
    }
  }

  const bool local_changed = !input.local_matches_base;
  const bool cloud_changed = !input.cloud_matches_base;
  if (!local_changed && !cloud_changed)
    return keep_local;  // Inconsistent hashes; do not choose a destructive winner.
  if (local_changed && !cloud_changed)
    return input.can_upload ? upload(UploadBase::TrustedBase) : keep_local;
  if (!local_changed && cloud_changed)
    return input.can_download ? download() : keep_local;

  switch (input.recency)
  {
  case SaveRecency::LocalNewer:
    return keep_local;  // Handled before the ancestry matrix above.
  case SaveRecency::CloudNewer:
    return input.can_upload ? upload(UploadBase::TrustedBase) : keep_local;
  case SaveRecency::Unknown:
    return input.can_upload ? upload(UploadBase::TrustedBase) : keep_local;
  }

  return defer;
}
}  // namespace UICommon::EmuBank::Policy
