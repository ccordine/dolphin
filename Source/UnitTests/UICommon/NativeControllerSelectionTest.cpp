// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include <gtest/gtest.h>

#include "Common/Config/Config.h"
#include "Common/FileUtil.h"
#include "Common/IniFile.h"
#include "Core/Config/MainSettings.h"
#include "Core/ConfigLoaders/BaseConfigLoader.h"
#include "Core/ConfigManager.h"
#include "Core/HW/GCPad.h"
#include "Core/HW/GCPadEmu.h"
#include "InputCommon/ControlReference/ControlReference.h"
#include "InputCommon/ControllerInterface/ControllerInterface.h"
#include "InputCommon/InputConfig.h"
#include "UICommon/UICommon.h"

namespace
{
class SelectedDevice : public ciface::Core::Device
{
public:
  class SelectedInput : public Input
  {
  public:
    explicit SelectedInput(std::string name) : m_name(std::move(name)) {}
    std::string GetName() const override { return m_name; }
    ControlState GetState() const override { return 1.0; }

  private:
    std::string m_name;
  };
  explicit SelectedDevice(std::string name) : m_name(std::move(name))
  {
    for (const auto* input :
         {"Button A",  "Button B",  "Button X", "Button Y", "Shoulder R", "Start",    "Left X+",
          "Left X-",   "Left Y+",   "Left Y-",  "Right X+", "Right X-",   "Right Y+", "Right Y-",
          "Trigger L", "Trigger R", "Pad N",    "Pad S",    "Pad W",      "Pad E"})
      AddInput(new SelectedInput(input));
  }
  std::string GetSource() const override { return "SDL"; }
  std::string GetName() const override { return m_name; }

private:
  std::string m_name;
};

class NativeControllerSelectionTest : public testing::Test
{
protected:
  void SetUp() override
  {
    directory = File::CreateTempDir();
    ASSERT_FALSE(directory.empty());
    UICommon::SetUserDirectory(directory);
    UICommon::CreateDirectories();
    Config::Init();
    Config::AddLayer(ConfigLoaders::GenerateBaseConfigLoader());
    SConfig::Init();
    const std::string settings = File::GetUserPath(D_CONFIG_IDX) + "GCPadNew.ini";
    Common::IniFile ini;
    ini.GetOrCreateSection("GCPad1")->Set("Device", std::string("SDL/0/Original physical"));
    ini.GetOrCreateSection("GCPad1")->Set("Buttons/A", std::string("`Button E`"));
    ini.GetOrCreateSection("GCPad1")->Set("Main Stick/Dead Zone", std::string("21.0"));
    ASSERT_TRUE(ini.Save(settings));
    g_controller_interface.Initialize({});
    g_controller_interface.RemoveDevice([](const auto*) { return true; });
    config = Pad::GetConfig();
    ASSERT_TRUE(
        config->SetLaunchDevices({"1=physical", "2=Daemonet own-run Player 2",
                                  "3=Daemonet own-run Player 3", "4=Daemonet own-run Player 4"}));
    Pad::Initialize();
  }
  void TearDown() override
  {
    Pad::Shutdown();
    config->SetLaunchDevices({});
    g_controller_interface.Shutdown();
    SConfig::Shutdown();
    Config::Shutdown();
    File::DeleteDirRecursively(directory);
  }
  std::string directory;
  InputConfig* config = nullptr;
};

TEST_F(NativeControllerSelectionTest, PhysicalLateConnectDoesNotClaimForeignOrOwnedRemotePad)
{
  auto foreign = std::make_shared<SelectedDevice>("Daemonet different-run Player 2");
  ASSERT_TRUE(g_controller_interface.AddDevice(foreign));
  EXPECT_FALSE(config->GetController(0)->IsDefaultDeviceConnected());
  EXPECT_FALSE(config->GetController(1)->IsDefaultDeviceConnected());
  auto owned = std::make_shared<SelectedDevice>("Daemonet own-run Player 2");
  ASSERT_TRUE(g_controller_interface.AddDevice(owned));
  EXPECT_FALSE(config->GetController(0)->IsDefaultDeviceConnected());
  EXPECT_TRUE(config->GetController(1)->IsDefaultDeviceConnected());
  EXPECT_EQ(config->GetController(1)->GetDefaultDevice().name, owned->GetName());
  auto physical = std::make_shared<SelectedDevice>("Physical late-connected controller");
  ASSERT_TRUE(g_controller_interface.AddDevice(physical));
  EXPECT_TRUE(config->GetController(0)->IsDefaultDeviceConnected());
  EXPECT_EQ(config->GetController(0)->GetDefaultDevice().name, physical->GetName());
  EXPECT_EQ(config->GetController(1)->GetDefaultDevice().name, owned->GetName());
  g_controller_interface.RemoveDevice([&](const auto* device) { return device == owned.get(); });
  EXPECT_FALSE(config->GetController(1)->IsDefaultDeviceConnected());
  auto resumed = std::make_shared<SelectedDevice>("Daemonet own-run Player 2");
  ASSERT_TRUE(g_controller_interface.AddDevice(resumed));
  EXPECT_TRUE(config->GetController(1)->IsDefaultDeviceConnected());
  EXPECT_EQ(config->GetController(0)->GetDefaultDevice().name, physical->GetName());
}

TEST_F(NativeControllerSelectionTest, ReloadAndSaveRetainProcessAssignmentAndOriginalBindings)
{
  ASSERT_TRUE(
      g_controller_interface.AddDevice(std::make_shared<SelectedDevice>("Physical controller")));
  ASSERT_TRUE(g_controller_interface.AddDevice(
      std::make_shared<SelectedDevice>("Daemonet own-run Player 2")));
  ASSERT_TRUE(config->LoadConfig());
  EXPECT_EQ(config->GetController(0)->GetDefaultDevice().name, "Physical controller");
  EXPECT_EQ(config->GetController(1)->GetDefaultDevice().name, "Daemonet own-run Player 2");
  config->SaveConfig();
  Common::IniFile saved;
  ASSERT_TRUE(saved.Load(File::GetUserPath(D_CONFIG_IDX) + "GCPadNew.ini"));
  std::string value;
  ASSERT_TRUE(saved.GetOrCreateSection("GCPad1")->Get("Device", &value));
  EXPECT_EQ(value, "SDL/0/Original physical");
  ASSERT_TRUE(saved.GetOrCreateSection("GCPad1")->Get("Buttons/A", &value));
  EXPECT_EQ(value, "`Button E`");
  EXPECT_FALSE(saved.GetOrCreateSection("GCPad2")->Exists("Device"));
  Common::IniFile::Section overlay;
  config->GetController(1)->SaveConfig(&overlay);
  ASSERT_TRUE(overlay.Get("Buttons/A", &value));
  EXPECT_EQ(value, "`Button E`");
}

TEST_F(NativeControllerSelectionTest, KeyboardProfileLoadsExistingSDLStandardBindingsOnlyInMemory)
{
  Common::IniFile saved;
  auto* original = saved.GetOrCreateSection("GCPad1");
  original->Set("Device", std::string("Xlib/0/Keyboard Mouse"));
  original->Set("Buttons/A", std::string("`X`"));
  ASSERT_TRUE(saved.Save(File::GetUserPath(D_CONFIG_IDX) + "GCPadNew.ini"));
  ASSERT_TRUE(config->LoadConfig());
  ASSERT_TRUE(g_controller_interface.AddDevice(
      std::make_shared<SelectedDevice>("8BitDo Ultimate Controller")));
  ASSERT_TRUE(g_controller_interface.AddDevice(
      std::make_shared<SelectedDevice>("Daemonet own-run Player 2")));
  for (int port : {0, 1})
  {
    auto* pad = static_cast<GCPad*>(config->GetController(port));
    EXPECT_TRUE(pad->IsDefaultDeviceConnected());
    for (auto* group : {pad->GetGroup(PadGroup::Buttons), pad->GetGroup(PadGroup::MainStick),
                        pad->GetGroup(PadGroup::CStick), pad->GetGroup(PadGroup::DPad),
                        pad->GetGroup(PadGroup::Triggers)})
    {
      for (const auto& control : group->controls)
      {
        if (!control->control_ref->GetExpression().empty())
        {
          EXPECT_GT(control->control_ref->BoundCount(), 0) << control->control_ref->GetExpression();
        }
      }
    }
    EXPECT_EQ(pad->GetGroup(PadGroup::Buttons)->controls[0]->control_ref->State(), 1.0);
  }
  EXPECT_EQ(config->GetController(0)->GetDefaultDevice().name, "8BitDo Ultimate Controller");
  EXPECT_EQ(config->GetController(1)->GetDefaultDevice().name, "Daemonet own-run Player 2");
  config->SaveConfig();
  ASSERT_TRUE(saved.Load(File::GetUserPath(D_CONFIG_IDX) + "GCPadNew.ini"));
  std::string value;
  ASSERT_TRUE(saved.GetOrCreateSection("GCPad1")->Get("Device", &value));
  EXPECT_EQ(value, "Xlib/0/Keyboard Mouse");
  ASSERT_TRUE(saved.GetOrCreateSection("GCPad1")->Get("Buttons/A", &value));
  EXPECT_EQ(value, "`X`");
}

TEST_F(NativeControllerSelectionTest, InvalidLaunchSelectionCannotReplaceExistingAssignment)
{
  for (const std::list<std::string>& input :
       {std::list<std::string>{"0=x"}, {"5=x"}, {"2="}, {"2=one", "2=other"}, {"2=invalid\nname"}})
  {
    EXPECT_FALSE(config->SetLaunchDevices(input));
    EXPECT_EQ(config->GetController(1)->GetDefaultDevice().name, "Daemonet own-run Player 2");
  }
}
}  // namespace
