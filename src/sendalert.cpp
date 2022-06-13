// Copyright (c) 2016-2021 The Hush developers
// Copyright (c) 2016 The Zcash developers
// Original code from: https://gist.github.com/laanwj/0e689cfa37b52bcbbb44
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

/*

To set up a new alert system
----------------------------

Create a new alert key pair:
openssl ecparam -name secp256k1 -genkey -param_enc explicit -outform PEM -out data.pem

Get the private key in hex:
openssl ec -in data.pem -outform DER | tail -c 279 | xxd -p -c 279

Get the public key in hex:
openssl ec -in data.pem -pubout -outform DER | tail -c 65 | xxd -p -c 65

Update the public keys found in chainparams.cpp.


To send an alert message
------------------------

Copy the private keys into alertkeys.h.

Modify the alert parameters, id and message found in this file.

Build and run with -sendalert or -printalert.

./hushd -printtoconsole -sendalert

One minute after starting up, the alert will be broadcast. It is then
flooded through the network until the nRelayUntil time, and will be
active until nExpiration OR the alert is cancelled.

If you make a mistake, send another alert with nCancel set to cancel
the bad alert.

*/

// Copyright (c) 2016-2021 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
#include "main.h"
#include "net.h"
#include "alert.h"
#include "init.h"
#include "util.h"
#include "utiltime.h"
#include "key.h"
#include "clientversion.h"
#include "chainparams.h"
#include "alertkeys.h"

static const int64_t DAYS = 24 * 60 * 60;

void ThreadSendAlert()
{
    if (!mapArgs.count("-sendalert") && !mapArgs.count("-printalert"))
        return;

    fprintf(stderr,"Sending alerts not supported!\n");
    return;

}
