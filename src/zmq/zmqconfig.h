// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

#ifndef HUSH_ZMQ_ZMQCONFIG_H
#define HUSH_ZMQ_ZMQCONFIG_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <stdarg.h>
#include <string>

#if ENABLE_ZMQ
#include <zmq.h>
#endif

#include "primitives/block.h"
#include "primitives/transaction.h"

void zmqError(const char *str);

#endif // HUSH_ZMQ_ZMQCONFIG_H
