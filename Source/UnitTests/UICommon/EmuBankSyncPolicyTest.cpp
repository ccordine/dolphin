// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <array>
#include <chrono>

#include <gtest/gtest.h>

#include "UICommon/EmuBankSyncPolicy.h"

namespace UICommon::EmuBank::Policy
{
namespace
{
using namespace std::chrono_literals;

void ExpectDecision(const Input& input, Action action, UploadBase upload_base = UploadBase::None)
{
  const Decision decision = Decide(input);
  EXPECT_EQ(decision.action, action);
  EXPECT_EQ(decision.upload_base, upload_base);
}

Input DivergentTwoWay()
{
  return {
      .cloud_present = true,
      .local_present = true,
      .can_upload = true,
      .can_download = true,
      .downloads_open = true,
  };
}

TEST(EmuBankSyncPolicy, AcceptsPairedCredentialsWithoutChangingTheirAlphabet)
{
  const std::string paired_secret = std::string(41, 'a') + "-_";
  EXPECT_EQ(paired_secret.size(), 43u);
  EXPECT_TRUE(IsSafeSecret(paired_secret));
  EXPECT_TRUE(IsSafeSecret("0123456789abcdefABCDEF"));
  EXPECT_TRUE(IsSafeSecret(std::string(128, 'Z')));
  EXPECT_FALSE(IsSafeSecret(""));
  EXPECT_FALSE(IsSafeSecret(std::string(129, 'Z')));
  for (const char bad : std::string{"\r\n\t ./+=%:"})
    EXPECT_FALSE(IsSafeSecret(std::string(42, 'a') + bad));
}

TEST(EmuBankSyncPolicy, ComparesAgesOnlyOutsideSafetyMargin)
{
  EXPECT_EQ(CompareAges(10s, 16s), SaveRecency::LocalNewer);
  EXPECT_EQ(CompareAges(16s, 10s), SaveRecency::CloudNewer);
  EXPECT_EQ(CompareAges(10s, 15s), SaveRecency::Unknown);
  EXPECT_EQ(CompareAges(15s, 10s), SaveRecency::Unknown);
  EXPECT_EQ(CompareAges(10s, 11s, -1s), SaveRecency::LocalNewer);
}

TEST(EmuBankSyncPolicy, AutomaticWorkCannotBypassConfiguredCadence)
{
  const std::chrono::steady_clock::time_point start{1000s};
  EXPECT_EQ(MinimumAutomaticDeadline(std::nullopt, 180s, start + 1ms), start + 1ms);
  EXPECT_EQ(MinimumAutomaticDeadline(start, 180s, start + 1ms), start + 180s);
  EXPECT_EQ(MinimumAutomaticDeadline(start, 180s, start + 2s), start + 180s);
  EXPECT_EQ(MinimumAutomaticDeadline(start, 180s, start + 179s), start + 180s);
  EXPECT_EQ(MinimumAutomaticDeadline(start, 180s, start + 181s), start + 181s);
}

TEST(EmuBankSyncPolicy, FreshLiveSaveBypassesCadenceButRetryDoesNot)
{
  const std::chrono::steady_clock::time_point start{1000s};
  const auto quiet_deadline = start + 2s;

  EXPECT_EQ(SaveEventAutomaticDeadline(start, 300s, quiet_deadline, true), quiet_deadline);
  EXPECT_EQ(SaveEventAutomaticDeadline(start, 300s, quiet_deadline, false), start + 300s);
  EXPECT_EQ(SaveEventAutomaticDeadline(std::nullopt, 300s, quiet_deadline, false), quiet_deadline);
  EXPECT_EQ(SaveEventAutomaticDeadline(start, 30s, start + 31s, false), start + 31s);
}

TEST(EmuBankSyncPolicy, SaveEventAttemptGenerationsPreserveOnlyFreshBypasses)
{
  constexpr std::uint64_t consumed = 4;
  constexpr std::uint64_t first_save = 7;

  EXPECT_TRUE(FreshLiveSaveEventPending(true, consumed, first_save));
  EXPECT_FALSE(FreshLiveSaveEventPending(false, consumed, first_save));

  // An unrelated live pass inside the quiet window covers only the consumed generation, so the
  // new save keeps its immediate first attempt even though that pass updates the last-sync time.
  const std::uint64_t covered_while_changing =
      CoveredSaveGeneration(true, false, consumed, first_save);
  EXPECT_EQ(covered_while_changing, consumed);
  EXPECT_EQ(AdvanceAttemptedSaveGeneration(consumed, covered_while_changing), consumed);
  EXPECT_TRUE(FreshLiveSaveEventPending(true, consumed, first_save));

  // Success and failure both spend generation 7's first attempt. Failure leaves it unconsumed,
  // but that same generation must retry at cadence rather than spinning immediately.
  const std::uint64_t attempted = AdvanceAttemptedSaveGeneration(consumed, first_save);
  EXPECT_EQ(attempted, first_save);
  EXPECT_FALSE(FreshLiveSaveEventPending(true, attempted, first_save));

  // A save arriving during or after that pass advances the latest generation and therefore gets
  // a new immediate attempt after its own quiet period.
  EXPECT_TRUE(FreshLiveSaveEventPending(true, attempted, first_save + 1));

  // A stopped or pre-launch pass covers the pending generation even if it fails. Starting the
  // next game cannot make the old event fresh again.
  const std::uint64_t stopped_covered = CoveredSaveGeneration(false, false, consumed, first_save);
  EXPECT_EQ(stopped_covered, first_save);
  EXPECT_FALSE(FreshLiveSaveEventPending(
      true, AdvanceAttemptedSaveGeneration(consumed, stopped_covered), first_save));
}

TEST(EmuBankSyncPolicy, UnrelatedLivePassCannotConsumeSaveBurstInsideQuietPeriod)
{
  const std::chrono::steady_clock::time_point start{1000s};
  EXPECT_TRUE(LiveSaveEventsReady(false, std::nullopt, start));
  EXPECT_FALSE(LiveSaveEventsReady(true, std::nullopt, start));
  EXPECT_FALSE(LiveSaveEventsReady(true, start + 2s, start + 1999ms));
  EXPECT_TRUE(LiveSaveEventsReady(true, start + 2s, start + 2s));

  EXPECT_EQ(CoveredSaveGeneration(true, false, 4, 7), 4u);
  EXPECT_EQ(CoveredSaveGeneration(true, true, 4, 7), 7u);
  EXPECT_EQ(CoveredSaveGeneration(false, false, 4, 7), 7u);
}

TEST(EmuBankSyncPolicy, OnlyCompleteLegacySelectorSchemaMayOmitArrays)
{
  // The deployed legacy v1 state contains none of these fields. Every partially present schema
  // remains invalid so compatibility cannot turn a torn current-state write into trusted input.
  for (unsigned int present_fields = 0; present_fields < 16; ++present_fields)
  {
    const bool arrays_may_be_omitted =
        DurableSelectorArraysMayBeOmitted((present_fields & 1) != 0, (present_fields & 2) != 0,
                                          (present_fields & 4) != 0, (present_fields & 8) != 0);
    EXPECT_EQ(arrays_may_be_omitted, present_fields == 0) << present_fields;
  }
}

TEST(EmuBankSyncPolicy, ResolverAuthorizationExpiresWhenLocalSaveChanges)
{
  EXPECT_TRUE(ResolverLocalMatches(false, {}, false, {}));
  EXPECT_TRUE(ResolverLocalMatches(true, "local-a", true, "local-a"));
  EXPECT_FALSE(ResolverLocalMatches(false, {}, true, "new-local"));
  EXPECT_FALSE(ResolverLocalMatches(true, "local-a", false, {}));
  EXPECT_FALSE(ResolverLocalMatches(true, "local-a", true, "local-b"));
}

TEST(EmuBankSyncPolicy, ExplicitDownloadRequiresExactPendingRevisionMetadata)
{
  EXPECT_TRUE(ExplicitDownloadMatches("download_if_different", "revision-a", "hash-a", "revision-a",
                                      "hash-a"));
  EXPECT_FALSE(ExplicitDownloadMatches("download", "revision-a", "hash-a", "revision-a", "hash-a"));
  EXPECT_FALSE(ExplicitDownloadMatches("download_if_different", "revision-b", "hash-a",
                                       "revision-a", "hash-a"));
  EXPECT_FALSE(ExplicitDownloadMatches("download_if_different", "revision-a", "hash-b",
                                       "revision-a", "hash-a"));
}

TEST(EmuBankSyncPolicy, DurableExplicitChoiceCannotSurviveItsLocalSnapshot)
{
  EXPECT_TRUE(DurableExplicitDownloadMatches("revision-b", "cloud-b", "revision-b", "cloud-b", true,
                                             "local-a", true, "local-a"));

  // Model a crash after B was installed but before its one-shot marker was consumed on disk. A
  // later local edit D must not inherit permission originally granted to replace A.
  EXPECT_FALSE(DurableExplicitDownloadMatches("revision-b", "cloud-b", "revision-b", "cloud-b",
                                              true, "local-a", true, "local-d"));
  EXPECT_FALSE(DurableExplicitDownloadMatches("revision-b", "cloud-b", "revision-b", "cloud-b",
                                              false, {}, true, "local-d"));
  EXPECT_FALSE(DurableExplicitDownloadMatches("revision-b", "cloud-b", "revision-c", "cloud-c",
                                              true, "local-a", true, "local-a"));
}

TEST(EmuBankSyncPolicy, SaveComponentsUseOneFailClosedCrossPlatformNamespace)
{
  EXPECT_TRUE(IsPortablePathComponent("Card.raw"));
  EXPECT_TRUE(IsPortablePathComponent("日本語.gci"));

  EXPECT_FALSE(IsPortablePathComponent(" Card.raw"));
  EXPECT_FALSE(IsPortablePathComponent("Slot."));
  EXPECT_FALSE(IsPortablePathComponent("Slot "));
  EXPECT_FALSE(IsPortablePathComponent("bad?.gci"));
  EXPECT_TRUE(IsPortablePathComponent("LONGFI~1.gci"));
  EXPECT_FALSE(IsPortablePathComponent("CON.gci"));
  EXPECT_FALSE(IsPortablePathComponent("con .gci"));
  EXPECT_FALSE(IsPortablePathComponent("LPT9.backup"));
  EXPECT_FALSE(IsPortablePathComponent("COM\xC2\xB9.gci"));
  EXPECT_FALSE(IsPortablePathComponent(std::string_view{"\xc0\xaf.gci", 6}));
}

TEST(EmuBankSyncPolicy, UnicodePathComponentsNeverProveFilesystemDistinction)
{
  EXPECT_FALSE(PathComponentsDefinitelyDistinct("Slot", "slot"));
  EXPECT_TRUE(PathComponentsDefinitelyDistinct("SlotA", "SlotB"));
  EXPECT_FALSE(PathComponentsDefinitelyDistinct("É.gci", "é.gci"));
  EXPECT_FALSE(PathComponentsDefinitelyDistinct("\xE2\x84\xAA.gci", "k.gci"));
  EXPECT_FALSE(PathComponentsDefinitelyDistinct("日本.gci", "different.gci"));
  EXPECT_TRUE(IsPlausibleDosShortComponent("VERYLO~1.GCI"));
  EXPECT_FALSE(PathComponentsDefinitelyDistinct("VeryLongName.gci", "VERYLO~1.GCI"));
}

TEST(EmuBankSyncPolicy, FileTargetsRejectAliasCompatibleAncestorPairs)
{
  constexpr std::array<std::string_view, 2> file{"GC", "foo.gci"};
  constexpr std::array<std::string_view, 3> child{"GC", "foo.gci", "bar.gci"};
  constexpr std::array<std::string_view, 2> sibling{"GC", "other.gci"};
  constexpr std::array<std::string_view, 2> case_alias{"gc", "FOO.GCI"};

  EXPECT_TRUE(PathTargetComponentSequencesMayConflict(file, file));
  EXPECT_TRUE(PathTargetComponentSequencesMayConflict(file, child));
  EXPECT_TRUE(PathTargetComponentSequencesMayConflict(child, file));
  EXPECT_TRUE(PathTargetComponentSequencesMayConflict(file, case_alias));
  EXPECT_FALSE(PathTargetComponentSequencesMayConflict(file, sibling));
}

TEST(EmuBankSyncPolicy, UnresolvedTwoWayConflictNeverDownloadsDivergentLocalSave)
{
  Input input = DivergentTwoWay();
  input.server_conflict = true;
  input.conflict_pending = true;
  input.local_matches_conflict = true;
  ExpectDecision(input, Action::KeepLocal);

  input.local_matches_conflict = false;
  input.has_trusted_base = true;
  input.local_matches_base = true;
  ExpectDecision(input, Action::KeepLocal);

  input.conflict_pending = false;
  input.local_matches_base = false;
  ExpectDecision(input, Action::KeepLocal);
}

TEST(EmuBankSyncPolicy, LaterLocalEditDuringOwnConflictUsesGuardedUpload)
{
  Input input = DivergentTwoWay();
  input.server_conflict = true;
  input.conflict_pending = true;
  input.has_trusted_base = true;
  ExpectDecision(input, Action::Upload, UploadBase::TrustedBase);

  input.recency = SaveRecency::LocalNewer;
  ExpectDecision(input, Action::Upload, UploadBase::TrustedBase);

  input.local_matches_base = true;
  ExpectDecision(input, Action::KeepLocal);
  input.local_matches_base = false;

  input.ancestor_invalidated = true;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.ancestor_invalidated = false;
  input.has_trusted_base = false;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.local_matches_conflict = true;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);
}

TEST(EmuBankSyncPolicy, UnknownAncestryUsesRecencyWithoutRiskingUnknownWinner)
{
  Input input = DivergentTwoWay();

  input.recency = SaveRecency::LocalNewer;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);

  input.recency = SaveRecency::CloudNewer;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.recency = SaveRecency::Unknown;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.can_upload = false;
  input.can_download = false;
  ExpectDecision(input, Action::KeepLocal);
}

TEST(EmuBankSyncPolicy, LocalNewerPrelaunchConflictNeverFallsBackToCloudDownload)
{
  Input input = DivergentTwoWay();
  input.recency = SaveRecency::LocalNewer;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);

  // Model the next manifest after that compare-and-swap lost a race and EmuBank retained the
  // upload as this installation's conflict revision. The local bytes remain authoritative on
  // disk; a 409 must never turn into a download of the selected (possibly older) cloud revision.
  input.server_conflict = true;
  input.conflict_pending = true;
  input.local_matches_conflict = true;
  input.recency = SaveRecency::Unknown;
  ExpectDecision(input, Action::KeepLocal);
}

TEST(EmuBankSyncPolicy, HistoricalCloudReactivationCannotReplaceClearlyNewerTrustedLocal)
{
  Input input = DivergentTwoWay();
  input.has_trusted_base = true;
  input.local_matches_base = true;
  input.cloud_matches_base = false;
  input.recency = SaveRecency::LocalNewer;

  // EmuBank may point back to an existing older revision, and its known-hash resolver may then
  // recommend download. Neither signal is revision ancestry or permission to replace local bytes.
  input.server_requests_download = true;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);

  input.server_requests_download = false;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);

  input.can_upload = false;
  input.can_download = false;
  ExpectDecision(input, Action::KeepLocal);
}

TEST(EmuBankSyncPolicy, LaterCloudUploadTimestampAloneNeverAuthorizesLocalOverwrite)
{
  Input input = DivergentTwoWay();
  input.recency = SaveRecency::CloudNewer;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.has_trusted_base = true;
  ExpectDecision(input, Action::Upload, UploadBase::TrustedBase);

  // A download becomes safe only when hashes prove that local is still the common base and only
  // cloud changed. Its upload timestamp is not the evidence authorizing the replacement.
  input.local_matches_base = true;
  ExpectDecision(input, Action::Download);
}

TEST(EmuBankSyncPolicy, ActiveResolverDownloadRequiresUnchangedBaseProof)
{
  Input input = DivergentTwoWay();
  input.server_requests_download = true;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.downloads_open = false;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.downloads_open = true;
  input.recency = SaveRecency::LocalNewer;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);

  input.server_conflict = true;
  input.conflict_pending = true;
  input.local_matches_conflict = true;
  // A proven-newer retained conflict may still be promoted, but the resolver must never turn the
  // 409 into a cloud download.
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);

  input.recency = SaveRecency::Unknown;
  ExpectDecision(input, Action::KeepLocal);

  input.server_conflict = false;
  input.conflict_pending = false;
  input.local_matches_conflict = false;
  input.ancestor_invalidated = true;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.ancestor_invalidated = false;
  input.recency = SaveRecency::CloudNewer;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.has_trusted_base = true;
  ExpectDecision(input, Action::Upload, UploadBase::TrustedBase);

  // Resolver advice becomes safe only when content ancestry proves local is unchanged and cloud
  // alone advanced. Timestamps are not the authorization.
  input.local_matches_base = true;
  ExpectDecision(input, Action::Download);

  input.downloads_open = false;
  ExpectDecision(input, Action::Defer);
}

TEST(EmuBankSyncPolicy, ExplicitServerRevisionSelectionMayOverrideLocalRecency)
{
  Input input = DivergentTwoWay();
  input.recency = SaveRecency::LocalNewer;
  input.server_requests_download = true;
  input.server_explicit_download = true;
  ExpectDecision(input, Action::Download);

  input.downloads_open = false;
  ExpectDecision(input, Action::Defer);

  // Even explicit advice cannot bypass the local safety markers created by a savestate load or
  // an unresolved server conflict.
  input.downloads_open = true;
  input.ancestor_invalidated = true;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.ancestor_invalidated = false;
  input.server_conflict = true;
  ExpectDecision(input, Action::KeepLocal);
}

TEST(EmuBankSyncPolicy, TrustedBaseThreeWayMatrix)
{
  Input input = DivergentTwoWay();
  input.has_trusted_base = true;

  input.local_matches_base = false;
  input.cloud_matches_base = true;
  ExpectDecision(input, Action::Upload, UploadBase::TrustedBase);

  input.local_matches_base = true;
  input.cloud_matches_base = false;
  ExpectDecision(input, Action::Download);

  // The server may move its pointer to an existing older revision. Even when local still matches
  // the recorded base, that pointer move cannot override a clear local-newer comparison.
  input.recency = SaveRecency::LocalNewer;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);
  input.server_requests_download = true;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);
  input.server_requests_download = false;

  input.local_matches_base = false;
  input.cloud_matches_base = false;
  input.recency = SaveRecency::LocalNewer;
  ExpectDecision(input, Action::Upload, UploadBase::CurrentCloud);

  input.recency = SaveRecency::CloudNewer;
  ExpectDecision(input, Action::Upload, UploadBase::TrustedBase);

  input.recency = SaveRecency::Unknown;
  ExpectDecision(input, Action::Upload, UploadBase::TrustedBase);
}

TEST(EmuBankSyncPolicy, SavestateInvalidationNeverTrustsRecordedBase)
{
  Input input = DivergentTwoWay();
  input.has_trusted_base = true;
  input.local_matches_base = true;
  input.cloud_matches_base = false;
  input.ancestor_invalidated = true;
  input.recency = SaveRecency::CloudNewer;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.conflict_pending = true;
  input.local_matches_conflict = true;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);
}

TEST(EmuBankSyncPolicy, ExplicitlyResolvedConflictMayInstallSelectedCloudRevision)
{
  Input input = DivergentTwoWay();
  input.conflict_pending = true;
  input.local_matches_conflict = true;
  ExpectDecision(input, Action::Download);

  input.downloads_open = false;
  ExpectDecision(input, Action::Defer);

  input.downloads_open = true;
  input.local_matches_cloud = true;
  ExpectDecision(input, Action::Current);
}

TEST(EmuBankSyncPolicy, MissingAndMatchingFilesUseSafePositiveControls)
{
  Input input = DivergentTwoWay();
  input.local_present = false;
  ExpectDecision(input, Action::Download);

  input.downloads_open = false;
  ExpectDecision(input, Action::Defer);

  input = DivergentTwoWay();
  input.local_matches_cloud = true;
  ExpectDecision(input, Action::Current);

  input = DivergentTwoWay();
  input.cloud_present = false;
  ExpectDecision(input, Action::Upload, UploadBase::NoAncestor);

  input.local_present = false;
  ExpectDecision(input, Action::Current);
}

TEST(EmuBankSyncPolicy, DownloadOnlyRemainsExplicitlyCloudAuthoritative)
{
  Input input = DivergentTwoWay();
  input.server_conflict = true;
  input.can_upload = false;
  ExpectDecision(input, Action::Download);

  input.downloads_open = false;
  ExpectDecision(input, Action::Defer);
}
}  // namespace
}  // namespace UICommon::EmuBank::Policy
