// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <QWidget>

class ConfigBool;
class ConfigInteger;
class ConfigText;
class QLabel;
class QPushButton;
class QTimer;

class EmuBankPane final : public QWidget
{
  Q_OBJECT
public:
  explicit EmuBankPane(QWidget* parent = nullptr);

private:
  void StartPairing();
  void UpdateEnabled(bool enabled);
  void UpdateStatus();

  ConfigBool* m_enabled;
  ConfigText* m_server_url;
  ConfigText* m_device_token;
  QPushButton* m_connect;
  ConfigBool* m_allow_insecure;
  ConfigBool* m_live_sync;
  ConfigInteger* m_sync_interval;
  QPushButton* m_sync_now;
  QLabel* m_status;
  QTimer* m_status_timer;
};
