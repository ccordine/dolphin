// Copyright 2026 Dolphin Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#include "DolphinQt/Settings/EmuBankPane.h"

#include <utility>

#include <QDesktopServices>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSysInfo>
#include <QThreadPool>
#include <QTimer>
#include <QUrl>
#include <QVBoxLayout>

#include "Core/Config/MainSettings.h"

#include "DolphinQt/Config/ConfigControls/ConfigBool.h"
#include "DolphinQt/Config/ConfigControls/ConfigInteger.h"
#include "DolphinQt/Config/ConfigControls/ConfigText.h"

#include "UICommon/EmuBankSync.h"

EmuBankPane::EmuBankPane(QWidget* parent) : QWidget(parent)
{
  auto* main_layout = new QVBoxLayout(this);

  auto* introduction = new QLabel(
      tr("Sync EmuBank device bindings directly with Dolphin on desktop and Android. Dolphin "
         "downloads cloud revisions only while save files are closed, uploads stable in-game "
         "changes in the background, and asks EmuBank to retain divergent edits as conflicts."));
  introduction->setWordWrap(true);
  main_layout->addWidget(introduction);

  auto* connection_group = new QGroupBox(tr("Connection"));
  auto* connection_layout = new QFormLayout(connection_group);
  connection_layout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

  m_enabled = new ConfigBool(tr("Enable EmuBank cloud sync"), Config::MAIN_EMUBANK_ENABLED);
  connection_layout->addRow(m_enabled);

  m_server_url = new ConfigText(Config::MAIN_EMUBANK_SERVER_URL);
  m_server_url->setPlaceholderText(QStringLiteral("https://bank.example.com"));
  m_server_url->setToolTip(tr("Paste the EmuBank base URL or this device's manifest URL."));
  connection_layout->addRow(tr("Server URL:"), m_server_url);

  m_connect = new QPushButton(tr("Connect EmuBank Account…"));
  m_connect->setToolTip(
      tr("Open EmuBank in your browser and authorize this Dolphin installation."));
  connection_layout->addRow(m_connect);

  m_device_token = new ConfigText(Config::MAIN_EMUBANK_DEVICE_TOKEN);
  m_device_token->setEchoMode(QLineEdit::Password);
  m_device_token->setPlaceholderText(tr("device-id.secret"));
  m_device_token->setToolTip(
      tr("Advanced fallback: paste a device token created on EmuBank's Devices page."));
  connection_layout->addRow(tr("Device token (advanced):"), m_device_token);

  m_allow_insecure = new ConfigBool(tr("Allow insecure HTTP (credential is sent without TLS)"),
                                    Config::MAIN_EMUBANK_ALLOW_INSECURE);
  connection_layout->addRow(m_allow_insecure);
  main_layout->addWidget(connection_group);

  auto* behavior_group = new QGroupBox(tr("Sync Behavior"));
  auto* behavior_layout = new QFormLayout(behavior_group);
  behavior_layout->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);

  m_live_sync =
      new ConfigBool(tr("Upload live save changes while playing"), Config::MAIN_EMUBANK_LIVE_SYNC);
  behavior_layout->addRow(m_live_sync);

  m_sync_interval = new ConfigInteger(30, 300, Config::MAIN_EMUBANK_SYNC_INTERVAL, 30);
  m_sync_interval->setSuffix(tr(" seconds"));
  behavior_layout->addRow(tr("Check interval:"), m_sync_interval);

  m_sync_now = new QPushButton(tr("Sync Now"));
  behavior_layout->addRow(m_sync_now);
  main_layout->addWidget(behavior_group);

  auto* safety = new QLabel(
      tr("For GameCube games, use GCI Folder memory-card mode and bind paths such as "
         "GC/USA/Card A/game.gci in EmuBank. Raw memory cards can be uploaded, but Dolphin will "
         "never replace one while emulation is active. The device token is stored in Dolphin's "
         "configuration; protect your user directory."));
  safety->setWordWrap(true);
  main_layout->addWidget(safety);

  m_status = new QLabel;
  m_status->setWordWrap(true);
  m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
  main_layout->addWidget(m_status);
  main_layout->addStretch(1);

  connect(m_enabled, &ConfigBool::toggled, this, &EmuBankPane::UpdateEnabled);
  connect(m_connect, &QPushButton::clicked, this, &EmuBankPane::StartPairing);
  connect(m_sync_now, &QPushButton::clicked, this, [] { UICommon::EmuBank::RequestSync(); });

  m_status_timer = new QTimer(this);
  m_status_timer->setInterval(1000);
  connect(m_status_timer, &QTimer::timeout, this, &EmuBankPane::UpdateStatus);
  m_status_timer->start();

  UpdateEnabled(m_enabled->isChecked());
  UpdateStatus();
}

void EmuBankPane::StartPairing()
{
  const QString server_url = m_server_url->text().trimmed();
  if (server_url.isEmpty())
  {
    QMessageBox::warning(this, tr("Connect EmuBank"), tr("Enter your EmuBank server URL first."));
    return;
  }

  QString host_name = QSysInfo::machineHostName().trimmed();
  if (host_name.isEmpty())
    host_name = tr("this computer");
  const std::string device_name = tr("Dolphin on %1").arg(host_name).toStdString();
  const std::string platform = QSysInfo::prettyProductName().toStdString();
  const std::string server = server_url.toStdString();

  m_connect->setEnabled(false);
  m_connect->setText(tr("Starting authorization…"));
  const QPointer<EmuBankPane> pane{this};
  QThreadPool::globalInstance()->start([pane, server, device_name, platform] {
    UICommon::EmuBank::PairingStartResult result =
        UICommon::EmuBank::BeginPairing(server, device_name, platform);
    if (!pane)
      return;

    QMetaObject::invokeMethod(
        pane,
        [pane, result = std::move(result)] {
          if (!pane)
            return;
          if (!result)
          {
            pane->m_connect->setEnabled(true);
            pane->m_connect->setText(pane->tr("Connect EmuBank Account…"));
            QMessageBox::warning(pane, pane->tr("Connect EmuBank"),
                                 QString::fromStdString(result.error));
            return;
          }

          pane->m_connect->setText(pane->tr("Waiting for browser approval…"));
          if (!QDesktopServices::openUrl(QUrl(QString::fromStdString(result.approval_url))))
          {
            QMessageBox::warning(
                pane, pane->tr("Connect EmuBank"),
                pane->tr("Dolphin could not open the authorization link. Copy this URL into your "
                         "browser:\n\n%1")
                    .arg(QString::fromStdString(result.approval_url)));
          }
        },
        Qt::QueuedConnection);
  });
}

void EmuBankPane::UpdateEnabled(bool enabled)
{
  m_live_sync->setEnabled(enabled);
  m_sync_interval->setEnabled(enabled);
  m_sync_now->setEnabled(enabled);
}

void EmuBankPane::UpdateStatus()
{
  const UICommon::EmuBank::PairingState pairing_state = UICommon::EmuBank::GetPairingState();
  if (pairing_state == UICommon::EmuBank::PairingState::Ready &&
      UICommon::EmuBank::FinalizePairing())
  {
    m_connect->setEnabled(true);
    m_connect->setText(tr("Reconnect EmuBank Account…"));
  }
  else if (pairing_state == UICommon::EmuBank::PairingState::Waiting)
  {
    m_connect->setEnabled(false);
    m_connect->setText(tr("Waiting for browser approval…"));
  }
  else if (pairing_state == UICommon::EmuBank::PairingState::Failed)
  {
    m_connect->setEnabled(true);
    m_connect->setText(tr("Connect EmuBank Account…"));
  }
  m_status->setText(QString::fromStdString(UICommon::EmuBank::GetStatus()));
}
