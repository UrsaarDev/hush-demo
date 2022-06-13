// Copyright (c) 2015 The Bitcoin Core developers
// Copyright (c) 2016-2021 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

/**
 * Functionality for communicating with Tor.
 */
#ifndef HUSH_TORCONTROL_H
#define HUSH_TORCONTROL_H

#include "scheduler.h"

extern const std::string DEFAULT_TOR_CONTROL;
// Most users don't have Tor, those that do can turn it on
// This help reduce CPU usage, thread contention and helps
// low resource devices
static const bool DEFAULT_LISTEN_ONION = false;

void StartTorControl(boost::thread_group& threadGroup, CScheduler& scheduler);
void InterruptTorControl();
void StopTorControl();

#endif /* HUSH_TORCONTROL_H */
