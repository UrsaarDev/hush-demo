// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html

#ifndef HUSH_ZMQ_ZMQNOTIFICATIONINTERFACE_H
#define HUSH_ZMQ_ZMQNOTIFICATIONINTERFACE_H

#include "validationinterface.h"
#include "consensus/validation.h"
#include <string>
#include <map>

class CBlockIndex;
class CZMQAbstractNotifier;

class CZMQNotificationInterface : public CValidationInterface
{
public:
    virtual ~CZMQNotificationInterface();

    static CZMQNotificationInterface* CreateWithArguments(const std::map<std::string, std::string> &args);

protected:
    bool Initialize();
    void Shutdown();

    // CValidationInterface
    void SyncTransaction(const CTransaction &tx, const CBlock *pblock);
    void UpdatedBlockTip(const CBlockIndex *pindex);
    void BlockChecked(const CBlock& block, const CValidationState& state);

private:
    CZMQNotificationInterface();

    void *pcontext;
    std::list<CZMQAbstractNotifier*> notifiers;
};

#endif // HUSH_ZMQ_ZMQNOTIFICATIONINTERFACE_H
