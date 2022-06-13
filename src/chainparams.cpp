// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Copyright (c) 2016-2021 The Hush developers
// Distributed under the GPLv3 software license, see the accompanying
// file COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html
/////////////////////////////////////////////////////////////////////////////////
// We believe in Extreme Privacy and reject surveillance. -- The Hush Developers
/////////////////////////////////////////////////////////////////////////////////
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
#include "key_io.h"
#include "main.h"
#include "crypto/equihash.h"
#include "util.h"
#include "utilstrencodings.h"
#include <assert.h>
#include <boost/assign/list_of.hpp>
#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    // To create a genesis block for a new chain which is Overwintered:
    //   txNew.nVersion = OVERWINTER_TX_VERSION
    //   txNew.fOverwintered = true
    //   txNew.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID
    //   txNew.nExpiryHeight = <default value>
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 520617983 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nSolution = nSolution;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(txNew);
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = genesis.BuildMerkleTree();
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database (and is in any case of zero value).
 *
 * >>> from pyblake2 import blake2s
 * >>> 'Zcash' + blake2s(b'The Economist 2016-10-29 Known unknown: Another crypto-currency is born. BTC#436254 0000000000000000044f321997f336d2908cf8c8d6893e88dbf067e2d949487d ETH#2521903 483039a6b6bd8bd05f0584f9a078d075e454925eb71c1f13eaff59b405a721bb DJIA close on 27 Oct 2016: 18,169.68').hexdigest()
 *
 * CBlock(hash=00040fe8, ver=4, hashPrevBlock=00000000000000, hashMerkleRoot=c4eaa5, nTime=1477641360, nBits=1f07ffff, nNonce=4695, vtx=1)
 *   CTransaction(hash=c4eaa5, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff071f0104455a6361736830623963346565663862376363343137656535303031653335303039383462366665613335363833613763616331343161303433633432303634383335643334)
 *     CTxOut(nValue=0.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: c4eaa5
 */
static CBlock CreateGenesisBlock(uint32_t nTime, const uint256& nNonce, const std::vector<unsigned char>& nSolution, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "Zcash0b9c4eef8b7cc417ee5001e3500984b6fea35683a7cac141a043c42064835d34";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nSolution, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 * + Likes long walks on the blockchain
 */
void *chainparams_commandline();
#include "hush_defs.h"
int32_t ASSETCHAINS_BLOCKTIME = 60;
uint64_t ASSETCHAINS_NK[2];

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));

class CMainParams : public CChainParams {
public:
    CMainParams()
    {

        strNetworkID = "main";
        strCurrencyUnits = "HUSH";
        bip44CoinType = 141; // As registered in https://github.com/satoshilabs/slips/blob/master/slip-0044.md 

        consensus.fCoinbaseMustBeProtected     = false;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow              = 4000;
        consensus.powLimit                     = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate                 = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow          = 17;
        consensus.nMaxFutureBlockTime          = 7 * 60; // 7 mins

        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp   = 16; // 16% adjustment up
        // we are emulating old node behavior at startup, they used 150s
        consensus.nPowTargetSpacing = 150; // 75; // HUSH is 75 seconds, Hush Smart Chains are 60 seconds by default
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = boost::none;
        // HUSH never had Sprout in our blockchain history, but some internals require *knowing* about Sprout
        // or it breaks backward compatibility. We do what we can.
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion         = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight        = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion   = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight  = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion  = 170005;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion     = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight    = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000281b32ff3198a1");

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xee;
        pchMessageStart[2] = 0xe4;
        pchMessageStart[3] = 0x8d;
        vAlertPubKey       = ParseHex("038a1bd41a08f38edda51042988022933c5775dfce81f7bae0b32a9179650352ac");
        nDefaultPort       = 5420;
        nMinerThreads      = 0;
        nMaxTipAge         = 24 * 60 * 60;
        nPruneAfterHeight  = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 50 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock.SetNull();
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1231006505;
        genesis.nBits    = HUSH_MINDIFF_NBITS;
        genesis.nNonce   = uint256S("0x000000000000000000000000000000000000000000000000000000000000000b");
        genesis.nSolution = ParseHex("000d5ba7cda5d473947263bf194285317179d2b0d307119c2e7cc4bd8ac456f0774bd52b0cd9249be9d40718b6397a4c7bbd8f2b3272fed2823cd2af4bd1632200ba4bf796727d6347b225f670f292343274cc35099466f5fb5f0cd1c105121b28213d15db2ed7bdba490b4cedc69742a57b7c25af24485e523aadbb77a0144fc76f79ef73bd8530d42b9f3b9bed1c135ad1fe152923fafe98f95f76f1615e64c4abb1137f4c31b218ba2782bc15534788dda2cc08a0ee2987c8b27ff41bd4e31cd5fb5643dfe862c9a02ca9f90c8c51a6671d681d04ad47e4b53b1518d4befafefe8cadfb912f3d03051b1efbf1dfe37b56e93a741d8dfd80d576ca250bee55fab1311fc7b3255977558cdda6f7d6f875306e43a14413facdaed2f46093e0ef1e8f8a963e1632dcbeebd8e49fd16b57d49b08f9762de89157c65233f60c8e38a1f503a48c555f8ec45dedecd574a37601323c27be597b956343107f8bd80f3a925afaf30811df83c402116bb9c1e5231c70fff899a7c82f73c902ba54da53cc459b7bf1113db65cc8f6914d3618560ea69abd13658fa7b6af92d374d6eca9529f8bd565166e4fcbf2a8dfb3c9b69539d4d2ee2e9321b85b331925df195915f2757637c2805e1d4131e1ad9ef9bc1bb1c732d8dba4738716d351ab30c996c8657bab39567ee3b29c6d054b711495c0d52e1cd5d8e55b4f0f0325b97369280755b46a02afd54be4ddd9f77c22272b8bbb17ff5118fedbae2564524e797bd28b5f74f7079d532ccc059807989f94d267f47e724b3f1ecfe00ec9e6541c961080d8891251b84b4480bc292f6a180bea089fef5bbda56e1e41390d7c0e85ba0ef530f7177413481a226465a36ef6afe1e2bca69d2078712b3912bba1a99b1fbff0d355d6ffe726d2bb6fbc103c4ac5756e5bee6e47e17424ebcbf1b63d8cb90ce2e40198b4f4198689daea254307e52a25562f4c1455340f0ffeb10f9d8e914775e37d0edca019fb1b9c6ef81255ed86bc51c5391e0591480f66e2d88c5f4fd7277697968656a9b113ab97f874fdd5f2465e5559533e01ba13ef4a8f7a21d02c30c8ded68e8c54603ab9c8084ef6d9eb4e92c75b078539e2ae786ebab6dab73a09e0aa9ac575bcefb29e930ae656e58bcb513f7e3c17e079dce4f05b5dbc18c2a872b22509740ebe6a3903e00ad1abc55076441862643f93606e3dc35e8d9f2caef3ee6be14d513b2e062b21d0061de3bd56881713a1a5c17f5ace05e1ec09da53f99442df175a49bd154aa96e4949decd52fed79ccf7ccbce32941419c314e374e4a396ac553e17b5340336a1a25c22f9e42a243ba5404450b650acfc826a6e432971ace776e15719515e1634ceb9a4a35061b668c74998d3dfb5827f6238ec015377e6f9c94f38108768cf6e5c8b132e0303fb5a200368f845ad9d46343035a6ff94031df8d8309415bb3f6cd5ede9c135fdabcc030599858d803c0f85be7661c88984d88faa3d26fb0e9aac0056a53f1b5d0baed713c853c4a2726869a0a124a8a5bbc0fc0ef80c8ae4cb53636aa02503b86a1eb9836fcc259823e2692d921d88e1ffc1e6cb2bde43939ceb3f32a611686f539f8f7c9f0bf00381f743607d40960f06d347d1cd8ac8a51969c25e37150efdf7aa4c2037a2fd0516fb444525ab157a0ed0a7412b2fa69b217fe397263153782c0f64351fbdf2678fa0dc8569912dcd8e3ccad38f34f23bbbce14c6a26ac24911b308b82c7e43062d180baeac4ba7153858365c72c63dcf5f6a5b08070b730adb017aeae925b7d0439979e2679f45ed2f25a7edcfd2fb77a8794630285ccb0a071f5cce410b46dbf9750b0354aae8b65574501cc69efb5b6a43444074fee116641bb29da56c2b4a7f456991fc92b2");


        /*genesis = CreateGenesisBlock(
            1477641360,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000001257"),
            ParseHex("000a889f00854b8665cd555f4656f68179d31ccadc1b1f7fb0952726313b16941da348284d67add4686121d4e3d930160c1348d8191c25f12b267a6a9c131b5031cbf8af1f79c9d513076a216ec87ed045fa966e01214ed83ca02dc1797270a454720d3206ac7d931a0a680c5c5e099057592570ca9bdf6058343958b31901fce1a15a4f38fd347750912e14004c73dfe588b903b6c03166582eeaf30529b14072a7b3079e3a684601b9b3024054201f7440b0ee9eb1a7120ff43f713735494aa27b1f8bab60d7f398bca14f6abb2adbf29b04099121438a7974b078a11635b594e9170f1086140b4173822dd697894483e1c6b4e8b8dcd5cb12ca4903bc61e108871d4d915a9093c18ac9b02b6716ce1013ca2c1174e319c1a570215bc9ab5f7564765f7be20524dc3fdf8aa356fd94d445e05ab165ad8bb4a0db096c097618c81098f91443c719416d39837af6de85015dca0de89462b1d8386758b2cf8a99e00953b308032ae44c35e05eb71842922eb69797f68813b59caf266cb6c213569ae3280505421a7e3a0a37fdf8e2ea354fc5422816655394a9454bac542a9298f176e211020d63dee6852c40de02267e2fc9d5e1ff2ad9309506f02a1a71a0501b16d0d36f70cdfd8de78116c0c506ee0b8ddfdeb561acadf31746b5a9dd32c21930884397fb1682164cb565cc14e089d66635a32618f7eb05fe05082b8a3fae620571660a6b89886eac53dec109d7cbb6930ca698a168f301a950be152da1be2b9e07516995e20baceebecb5579d7cdbc16d09f3a50cb3c7dffe33f26686d4ff3f8946ee6475e98cf7b3cf9062b6966e838f865ff3de5fb064a37a21da7bb8dfd2501a29e184f207caaba364f36f2329a77515dcb710e29ffbf73e2bbd773fab1f9a6b005567affff605c132e4e4dd69f36bd201005458cfbd2c658701eb2a700251cefd886b1e674ae816d3f719bac64be649c172ba27a4fd55947d95d53ba4cbc73de97b8af5ed4840b659370c556e7376457f51e5ebb66018849923db82c1c9a819f173cccdb8f3324b239609a300018d0fb094adf5bd7cbb3834c69e6d0b3798065c525b20f040e965e1a161af78ff7561cd874f5f1b75aa0bc77f720589e1b810f831eac5073e6dd46d00a2793f70f7427f0f798f2f53a67e615e65d356e66fe40609a958a05edb4c175bcc383ea0530e67ddbe479a898943c6e3074c6fcc252d6014de3a3d292b03f0d88d312fe221be7be7e3c59d07fa0f2f4029e364f1f355c5d01fa53770d0cd76d82bf7e60f6903bc1beb772e6fde4a70be51d9c7e03c8d6d8dfb361a234ba47c470fe630820bbd920715621b9fbedb49fcee165ead0875e6c2b1af16f50b5d6140cc981122fcbcf7c5a4e3772b3661b628e08380abc545957e59f634705b1bbde2f0b4e055a5ec5676d859be77e20962b645e051a880fddb0180b4555789e1f9344a436a84dc5579e2553f1e5fb0a599c137be36cabbed0319831fea3fddf94ddc7971e4bcf02cdc93294a9aab3e3b13e3b058235b4f4ec06ba4ceaa49d675b4ba80716f3bc6976b1fbf9c8bf1f3e3a4dc1cd83ef9cf816667fb94f1e923ff63fef072e6a19321e4812f96cb0ffa864da50ad74deb76917a336f31dce03ed5f0303aad5e6a83634f9fcc371096f8288b8f02ddded5ff1bb9d49331e4a84dbe1543164438fde9ad71dab024779dcdde0b6602b5ae0a6265c14b94edd83b37403f4b78fcd2ed555b596402c28ee81d87a909c4e8722b30c71ecdd861b05f61f8b1231795c76adba2fdefa451b283a5d527955b9f3de1b9828e7b2e74123dd47062ddcc09b05e7fa13cb2212a6fdbc65d7e852cec463ec6fd929f5b8483cf3052113b13dac91b69f49d1b7d1aec01c4a68e41ce157"),
            0x1f07ffff, 4, 0);*/

        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x027e3758c3a65b12aa1046462b486d0a63bfa1beae327897f56c5cfb7daaae71"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));
        vFixedSeeds.clear();
        vSeeds.clear();
        // Hush Official DNS Seeds
        vSeeds.push_back(CDNSSeedData("node1", "seed1.hush.is"));
        vSeeds.push_back(CDNSSeedData("node2", "seed2.hush.is"));
        // Community run DNS Seeds
        vSeeds.push_back(CDNSSeedData("node3", "dns.leto.net"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();

        // Unused Sprout stuff, for historical completeness
        // guarantees the first two characters, when base58 encoded, are "zc"
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {22,154};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVK"
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAB,0xD3};
        // guarantees the first two characters, when base58 encoded, are "SK"
        base58Prefixes[ZCSPENDING_KEY] = {171,54};

        // guarantees the first two characters, when base58 encoded, are "zs"
        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zs";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviews";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivks";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-main";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers           = true;
        fDefaultConsistencyChecks      = false;
        fRequireStandard               = true;
        fMineBlocksOnDemand            = false;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
};

static CMainParams mainParams;

void CChainParams::SetCheckpointData(CChainParams::CCheckpointData checkpointData)
{
    CChainParams::checkpointData = checkpointData;
}

/*
 To change the max block size, all that needs to be updated is the #define _MAX_BLOCK_SIZE in utils.h
 
 However, doing that without any other changes will allow forking non-updated nodes by creating a larger block. So, make sure to height activate the new blocksize properly.
 
 Assuming it is 8MB, then:
 #define _OLD_MAX_BLOCK_SIZE (4096 * 1024)
 #define _MAX_BLOCK_SIZE (2 * 4096 * 1024)
 
 change the body of if:
 {
    if ( height < saplinght+1000000 ) // activates 8MB blocks 1 million blocks after saplinght
        return(_OLD_MAX_BLOCK_SIZE);
    else return(_MAX_BLOCK_SIZE);
 }

*/

// Unused Testnet, for completeness. We make testcoins instead.
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID                           = "test";
        strCurrencyUnits                       = "TUSH";
        bip44CoinType                          = 1;
        nDefaultPort                           = 15550;
        nMinerThreads                          = 0;
        consensus.fCoinbaseMustBeProtected     = true;
        consensus.nMajorityEnforceBlockUpgrade = 51;
        consensus.nMajorityRejectBlockOutdated = 75;
        consensus.nMajorityWindow              = 400;
        consensus.nMaxFutureBlockTime          = 5 * 60;
        consensus.powLimit                     = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powAlternate                 = uint256S("07ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowAveragingWindow          = 17; // respect to zawy
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);

        consensus.nPowMaxAdjustDown = 32; // 32% adjustment down
        consensus.nPowMaxAdjustUp   = 16; // 16% adjustment up
        consensus.nPowTargetSpacing = 2.5 * 60;
        consensus.nPowAllowMinDifficultyBlocksAfterHeight = 299187;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::BASE_SPROUT].nActivationHeight = Consensus::NetworkUpgrade::ALWAYS_ACTIVE;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion = 170002;
        consensus.vUpgrades[Consensus::UPGRADE_TESTDUMMY].nActivationHeight = Consensus::NetworkUpgrade::NO_ACTIVATION_HEIGHT;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nProtocolVersion = 170003;
        consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = 207500;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nProtocolVersion = 170007;
        consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = 280000;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000000000000001d0c4d9cd");

        pchMessageStart[0] = 0x5A;
        pchMessageStart[1] = 0x1F;
        pchMessageStart[2] = 0x7E;
        pchMessageStart[3] = 0x62;
        vAlertPubKey       = ParseHex("038a1bd41a08f38edda51042988022933c5775dfce81f7bae0b32a9179650352ac");
        nMaxTipAge = 24 * 60 * 60;

        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1296688602;
        genesis.nBits = HUSH_MINDIFF_NBITS;
        genesis.nNonce = uint256S("0x0000000000000000000000000000000000000000000000000000000000000009");
        genesis.nSolution = ParseHex("003423da3e41f916bf3ff0ee770eb844a240361abe08a8c9d46bd30226e2ad411a4047b6ddc230d173c60537e470e24f764120f5a2778b2a1285b0727bf79a0b085ad67e6266fb38fd72ef17f827315c42f921720248c983d4100e6ebd1c4b5e8762a973bac3bec7f7153b93752ebbb465f0fc9520bcfc30f9abfe303627338fed6ede9cf1b9173a736cf270cf4d9c6999ff4c3a301a78fd50dab6ccca67a0c5c2e41f216a1f3efd049a74bbe6252f9773bc309d3f9e554d996913ce8e1cec672a1fa4ea59726b61ea9e75d5ce9aa5dbfa96179a293810e02787f26de324fe7c88376ff57e29574a55faff7c2946f3e40e451861c32bf67da7377de3136858a18f34fab1bc8da37726ca2c25fc7b312a5427554ec944da81c7e27255d6c94ade9987ff7daedc2d1cc63d7d4cf93e691d13326fb1c7ee72ccdc0b134eb665fc6a9821e6fef6a6d45e4aac6dca6b505a0100ad56ea4f6fa4cdc2f0d1b65f730104a515172e34163bdb422f99d083e6eb860cf6b3f66642c4dbaf0d0fa1dca1b6166f1d1ffaa55a9d6d6df628afbdd14f1622c1c8303259299521a253bc28fcc93676723158067270fc710a09155a1e50c533e9b79ed5edba4ab70a08a9a2fc0eef0ddae050d75776a9804f8d6ad7e30ccb66c6a98d86710ca7a4dfb4feb159484796b9a015c5764aa3509051c87f729b9877ea41f8b470898c01388ed9098b1e006d3c30fc6e7c781072fa3f75d918505ee8ca75840fc62f67c57060666aa42578a2dd022eda62e3f1e447d7364074d34fd60ad9b138f60422afa6cfcb913fd6c213b496144dbfda7bfc7c24540cfe40ad0c0fd5a8c0902127f53d3178ba1b2a87bf1224d53d3a15e49ccdf121ae872a011c996d1b9793153cdcd4c0a7e99f8a35669788551cca2b62769eda24b6b55e2f4e0ac0d30aa50ecf33c6cdb24adfc922006a7bf434ced800fefe814c94c6fc8caa37b372d5088bb31d2f6b11a7a67ad3f70abbac0d5c256b637828de6cc525978cf151a2e50798e0c591787639a030291272c9ced3ab7d682e03f8c7db51f60163baa85315789666ea8c5cd6f789a7f4a5de4f8a9dfefce20f353cec606492fde8eab3e3b487b3a3a57434f8cf252a4b643fc125c8a5948b06744f5dc306aa587bdc85364c7488235c6edddd78763675e50a9637181519be06dd30c4ba0d845f9ba320d01706fd6dd64d1aa3cd4211a4a7d1d3f2c1ef2766d27d5d2cdf8e7f5e3ea309d4f149bb737305df1373a7f5313abe5986f4aa620bec4b0065d48aafac3631de3771f5c4d2f6eec67b09d9c70a3c1969fecdb014cb3c69832b63cc9d6efa378bff0ef95ffacdeb1675bb326e698f022c1a3a2e1c2b0f05e1492a6d2b7552388eca7ee8a2467ef5d4207f65d4e2ae7e33f13eb473954f249d7c20158ae703e1accddd4ea899f026618695ed2949715678a32a153df32c08922fafad68b1895e3b10e143e712940104b3b352369f4fe79bd1f1dbe03ea9909dbcf5862d1f15b3d1557a6191f54c891513cdb3c729bb9ab08c0d4c35a3ed67d517ffe1e2b7a798521aed15ff9822169c0ec860d7b897340bc2ef4c37f7eb73bd7dafef12c4fd4e6f5dd3690305257ae14ed03df5e3327b68467775a90993e613173fa6650ffa2a26e84b3ce79606bf234eda9f4053307f344099e3b10308d3785b8726fd02d8e94c2759bebd05748c3fe7d5fe087dc63608fb77f29708ab167a13f32da251e249a544124ed50c270cfc6986d9d1814273d2f0510d0d2ea335817207db6a4a23ae9b079967b63b25cb3ceea7001b65b879263f5009ac84ab89738a5b8b71fd032beb9f297326f1f5afa630a5198d684514e242f315a4d95fa6802e82799a525bb653b80b4518ec610a5996403b1391");
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {20,81};
        // guarantees the first 4 characters, when base58 encoded, are "ZiVt"
        base58Prefixes[ZCVIEWING_KEY]  = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY] = {177,235};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "ztestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivktestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-test";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        //fRequireRPCPassword = true;
        fMiningRequiresPeers = false;//true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;


        checkpointData = (CCheckpointData) {
            boost::assign::map_list_of
            (0, consensus.hashGenesisBlock)
            (38000, uint256S("0x001e9a2d2e2892b88e9998cf7b079b41d59dd085423a921fe8386cecc42287b8")),
            1486897419,  // * UNIX timestamp of last checkpoint block
            47163,       // * total number of transactions between genesis and last checkpoint
                         //   (the tx=... number in the SetBestChain debug.log lines)
            715          //   total number of tx / (checkpoint block height / (24 * 24))
        };
    }
};
static CTestNetParams testNetParams;
#define NUNU Consensus::NetworkUpgrade

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        auto ups                               = consensus.vUpgrades;
        strNetworkID                           = "regtest";
        strCurrencyUnits                       = "REG";
        bip44CoinType                          = 1;
        consensus.fCoinbaseMustBeProtected     = false;
        consensus.nMajorityEnforceBlockUpgrade = 750;
        consensus.nMajorityRejectBlockOutdated = 950;
        consensus.nMajorityWindow              = 1000;
        consensus.powLimit                     = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.powAlternate                 = uint256S("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f");
        consensus.nPowAveragingWindow          = 17;
        consensus.nMaxFutureBlockTime          = 7 * 60; // 7 mins
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown                          = 0;  // Turn off adjustment down
        consensus.nPowMaxAdjustUp                            = 0;  // Turn off adjustment up
        consensus.nPowTargetSpacing                          = 60; // HSC's default to 60 seconds so a theoretical testnet should as well
        consensus.nPowAllowMinDifficultyBlocksAfterHeight    = 0;
        ups[Consensus::BASE_SPROUT].nProtocolVersion         = 170002;
        ups[Consensus::BASE_SPROUT].nActivationHeight        = NUNU::ALWAYS_ACTIVE;
        ups[Consensus::UPGRADE_TESTDUMMY].nProtocolVersion   = 170002;
        ups[Consensus::UPGRADE_TESTDUMMY].nActivationHeight  = NUNU::NO_ACTIVATION_HEIGHT;
        ups[Consensus::UPGRADE_OVERWINTER].nProtocolVersion  = 170003;
        ups[Consensus::UPGRADE_OVERWINTER].nActivationHeight = NUNU::NO_ACTIVATION_HEIGHT;
        ups[Consensus::UPGRADE_SAPLING].nProtocolVersion     = 170006;
        ups[Consensus::UPGRADE_SAPLING].nActivationHeight    = NUNU::NO_ACTIVATION_HEIGHT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        pchMessageStart[0] = 0xaa;
        pchMessageStart[1] = 0x8e;
        pchMessageStart[2] = 0xf3;
        pchMessageStart[3] = 0xf5;
        nMinerThreads      = 1;
        nMaxTipAge         = 24 * 60 * 60;
        nPruneAfterHeight  = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(
            1296688602,
            uint256S("0x0000000000000000000000000000000000000000000000000000000000000009"),
            ParseHex("01936b7db1eb4ac39f151b8704642d0a8bda13ec547d54cd5e43ba142fc6d8877cab07b3"),


            HUSH_MINDIFF_NBITS, 4, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x029f11d80ef9765602235e1bc9727e3eb6ba20839319f761fee920d63401e327"));
        assert(genesis.hashMerkleRoot == uint256S("0xc4eaa58879081de3c24a7b117ed2b28300e7ec4c4c1dff1d3f1268b7857a4ddb"));

        nDefaultPort      = 15420;
        nPruneAfterHeight = 1000;

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();  //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers           = false;
        fDefaultConsistencyChecks      = true;
        fRequireStandard               = false;
        fMineBlocksOnDemand            = true;
        fTestnetToBeDeprecatedFieldRPC = false;

        checkpointData = (CCheckpointData){
            boost::assign::map_list_of
            ( 0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")),
            0,
            0,
            0
        };
        // These prefixes are the same as the testnet prefixes
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,60);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,188);
        //base58Prefixes[PUBKEY_ADDRESS]     = {0x1D,0x25};
        //base58Prefixes[SCRIPT_ADDRESS]     = {0x1C,0xBA};
        //base58Prefixes[SECRET_KEY]         = {0xEF};
        // do not rely on these BIP32 prefixes; they are not specified and may change
        base58Prefixes[EXT_PUBLIC_KEY]     = {0x04,0x35,0x87,0xCF};
        base58Prefixes[EXT_SECRET_KEY]     = {0x04,0x35,0x83,0x94};
        base58Prefixes[ZCPAYMENT_ADDRRESS] = {0x16,0xB6};
        base58Prefixes[ZCVIEWING_KEY]      = {0xA8,0xAC,0x0C};
        base58Prefixes[ZCSPENDING_KEY]     = {0xAC,0x08};

        bech32HRPs[SAPLING_PAYMENT_ADDRESS]      = "zregtestsapling";
        bech32HRPs[SAPLING_FULL_VIEWING_KEY]     = "zviewregtestsapling";
        bech32HRPs[SAPLING_INCOMING_VIEWING_KEY] = "zivkregtestsapling";
        bech32HRPs[SAPLING_EXTENDED_SPEND_KEY]   = "secret-extended-key-regtest";

    }

    void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
    {
        assert(idx > Consensus::BASE_SPROUT && idx < Consensus::MAX_NETWORK_UPGRADES);
        consensus.vUpgrades[idx].nActivationHeight = nActivationHeight;
    }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = 0;

const CChainParams &Params() {
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams &Params(CBaseChainParams::Network network) {
    switch (network) {
        case CBaseChainParams::MAIN:
            return mainParams;
        case CBaseChainParams::TESTNET:
            return testNetParams;
        case CBaseChainParams::REGTEST:
            return regTestParams;
        default:
            assert(false && "Unimplemented network");
            return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network) {
    SelectBaseParams(network);
    pCurrentParams = &Params(network);

    // Some python qa rpc tests need to enforce the coinbase consensus rule
    if (network == CBaseChainParams::REGTEST && mapArgs.count("-regtestprotectcoinbase")) {
        regTestParams.SetRegTestCoinbaseMustBeProtected();
    }
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);

    return true;
}

void UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex idx, int nActivationHeight)
{
    regTestParams.UpdateNetworkUpgradeParameters(idx, nActivationHeight);
}

int32_t MAX_BLOCK_SIZE(int32_t height)
{
    int32_t saplinght = pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight;
    //fprintf(stderr,"MAX_BLOCK_SIZE %d vs. %d\n",height,mainParams.consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight);
    if ( height <= 0 || (saplinght > 0 && height >= saplinght) )
    {
        return(_MAX_BLOCK_SIZE);
    }
    else return(2000000);
}

// Change the Hush blocktime at run-time(!)
void hush_changeblocktime()
{
    pCurrentParams->consensus.nMaxFutureBlockTime = 7 * ASSETCHAINS_BLOCKTIME;
    pCurrentParams->consensus.nPowTargetSpacing   = ASSETCHAINS_BLOCKTIME;
    fprintf(stderr,"HUSH blocktime changing to %d seconds\n",ASSETCHAINS_BLOCKTIME);
}

void hush_setactivation(int32_t height)
{
    pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight    = height;
    pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = height;
    ASSETCHAINS_SAPLING = height;
    fprintf(stderr,"SET SAPLING ACTIVATION height.%d\n",height);
}

void *chainparams_commandline() {
    CChainParams::CCheckpointData checkpointData;
    //if(fDebug) {
        fprintf(stderr,"chainparams_commandline called with port=%u\n", ASSETCHAINS_P2PPORT);
    //}
    if ( SMART_CHAIN_SYMBOL[0] != 0 )
    {
        if (strcmp(SMART_CHAIN_SYMBOL,"HUSH3") == 0) {
            ASSETCHAINS_P2PPORT = 18030;
        }

        if ( ASSETCHAINS_BLOCKTIME != 60 )
        {
            pCurrentParams->consensus.nMaxFutureBlockTime = 7 * ASSETCHAINS_BLOCKTIME; // 7 blocks
            pCurrentParams->consensus.nPowTargetSpacing   = ASSETCHAINS_BLOCKTIME;
        }
        pCurrentParams->SetDefaultPort(ASSETCHAINS_P2PPORT);
        if ( ASSETCHAINS_NK[0] != 0 && ASSETCHAINS_NK[1] != 0 )
        {
            //BOOST_STATIC_ASSERT(equihash_parameters_acceptable(ASSETCHAINS_NK[0], ASSETCHAINS_NK[1]));
            pCurrentParams->SetNValue(ASSETCHAINS_NK[0]);
            pCurrentParams->SetKValue(ASSETCHAINS_NK[1]);
        }
        if ( HUSH_TESTNODE != 0 ) {
            fprintf(stderr,"%s: This is a test node, mining will not require peers!\n", __func__);
            pCurrentParams->SetMiningRequiresPeers(false);
        }

        if ( ASSETCHAINS_RPCPORT == 0 )
            ASSETCHAINS_RPCPORT = ASSETCHAINS_P2PPORT + 1;
        pCurrentParams->pchMessageStart[0] = ASSETCHAINS_MAGIC & 0xff;
        pCurrentParams->pchMessageStart[1] = (ASSETCHAINS_MAGIC >> 8) & 0xff;
        pCurrentParams->pchMessageStart[2] = (ASSETCHAINS_MAGIC >> 16) & 0xff;
        pCurrentParams->pchMessageStart[3] = (ASSETCHAINS_MAGIC >> 24) & 0xff;
        fprintf(stderr,">>>>>>>>>> %s: p2p.%u rpc.%u magic.%08x %u %u coins\n",SMART_CHAIN_SYMBOL,ASSETCHAINS_P2PPORT,ASSETCHAINS_RPCPORT,ASSETCHAINS_MAGIC,ASSETCHAINS_MAGIC,(uint32_t)ASSETCHAINS_SUPPLY);

        pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight = ASSETCHAINS_SAPLING;
        pCurrentParams->consensus.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight = ASSETCHAINS_OVERWINTER;
		// Generated at 1575831755 via hush3 contrib/checkpoints.pl by Duke Leto
        if (strcmp(SMART_CHAIN_SYMBOL,"HUSH3") == 0) {
                // Generated at 1596199654 via hush3 contrib/checkpoints.pl by Duke Leto
                checkpointData = //(Checkpoints::CCheckpointData)
                {
                        boost::assign::map_list_of
                                (0, pCurrentParams->consensus.hashGenesisBlock)
                                // Last updated at 1613482505 via hush3 contrib/checkpoints.pl by Duke Leto
                                (5000,     uint256S("0x000000018f8543066baa9c5f83e981749da4cb625fad02c187b4a9c4693ebd60"))
                                (10000,     uint256S("0x00000002d177d1cbfeaf7c27a2a32766ea9063d222cbcc7623dc08355b07a3ad"))
                                (15000,     uint256S("0x000000008dbfbd5d5e27d819bf2989c5658c3494608bfa1320ad0b090660cd44"))
                                (20000,     uint256S("0x00000000a7840e1fccedb13672804e94fcaa87c0360ee4f7353a6b93e5a59da8"))
                                (25000,     uint256S("0x0000000519d6ab6ca9c705ebafa9946bce34934709621bc22227567e90608667"))
                                (30000,     uint256S("0x0000000240de901e9e70d2db5badf62886ab0e8c442107d571bc04b3bdd43052"))
                                (35000,     uint256S("0x00000000ad1ef91eb70011a94646c148f1b8949b464a0de82adf1ba1ce6175a5"))
                                (40000,     uint256S("0x000000013b65e22d0bb6a9103dc71da5a1b7fa2acbc1c7d7a4d8f7730c37d4ab"))
                                (45000,     uint256S("0x00000004da449923c218bd3e69745ebafca41c32e0c81ab6b485ae6c4c80df18"))
                                (50000,     uint256S("0x000000027470e84cd195242f199b90fde40b70f80fac7a7080b1517c95cf56c6"))
                                (55000,     uint256S("0x00000000a20b276ed95b261a51681fb2d0d58e528cc8cd2e5fb7fdeb732b1861"))
                                (60000,     uint256S("0x000000060382850eadef184b67f38c0b2de27157296f3d9d8e2b7b70b1f76127"))
                                (65000,     uint256S("0x0000000618eb1c909301585f6b8f17ee6d09da97c580fe70d59babcd7864b556"))
                                (70000,     uint256S("0x00000006d11cf168399c719b2bb036eadd09e740c98764d82adf75f5a800e90d"))
                                (75000,     uint256S("0x00000007abb9cb521244c988f0ace53bf230bdf9c9db75d0102472a721c6b038"))
                                (80000,     uint256S("0x000000031c23c3a1828b3a432ab27c6b34a93741f5711507abeb34a822ba5311"))
                                (85000,     uint256S("0x00000006fc5823857bdd44f89f4a97838a9f735c7bdf81bd89f50110dc16fbab"))
                                (90000,     uint256S("0x00000003e62dcb81fe33178e2dc45c70ca04733542179ac5d93bceb7c456f365"))
                                (95000,     uint256S("0x00000002a22cae35b32e31ffbe55d2d56ef04f010aebd19f1536b7582c1ea4d9"))
                                (100000,     uint256S("0x00000001bc1c40d120bf2df1654f3fb5e4d28d4ff292d05667cf5610042c794a"))
                                (105000,     uint256S("0x0000000175182a7f9c46aaae8723a664168af4be37c5d73e8f773df6b67a458b"))
                                (110000,     uint256S("0x000000030ba3cdbb85d5028379dfe50fbf28c04f8add3300814c2f649ec53594"))
                                (115000,     uint256S("0x000000019fd1a317c649c83c6b2a3f6bca7e82fac2fc89ce69de4b6d5715050b"))
                                (120000,     uint256S("0x0000000217decb42c4ea26cbee700e728a558ae648393b8014f035566ef2a456"))
                                (125000,     uint256S("0x000000002aeab45f5e399d027976c49f4c7732ddbb78d7dc729fb226346ea3f1"))
                                (130000,     uint256S("0x000000001c4a5aa11e6c142931463fcf7a9f5b9fb41061d26c18ff1860431881"))
                                (135000,     uint256S("0x000000025f9502fc7474d62a0a23417cc5b77f3a049260e65b5b810d71074743"))
                                (140000,     uint256S("0x00000000ea91b31e677db9f506e9de4ce03b609275212072759aada24b4654bf"))
                                (145000,     uint256S("0x000000003f623cfbe83830077ce9d79f692cb1cd39f027d2bbfba0861dc050d7"))
                                (150000,     uint256S("0x00000001850c65319eb4048f175e9540091dad9e4a7f8aeb5c989137e15a8524"))
                                (155000,     uint256S("0x00000003c30e0e03841c63a47e934c0ba7f42578c6065ca03436dca8c99918da"))
                                (160000,     uint256S("0x0000000553274de0e5f07bf3a63bdb6ab71158a3506829fd6f7df2cd51d5b2a3"))
                                (165000,     uint256S("0x00000002c72ab9752b4f605b303f5c006600eb8e62baab7016af2e0454894c9b"))
                                (170000,     uint256S("0x0000000191d6e3c5473215ab1e28a8fa8db6172eb4ec6fed371d4bd71224adb0"))
                                (175000,     uint256S("0x00000000ac73f67cdc92b225e0895054ba4349d68ddca707ba536d9946f14a2b"))
                                (180000,     uint256S("0x00000003119d28eed1fd0c2e2a33510b2b740c1227a9e0e59157228f8e9e1666"))
                                (185000,     uint256S("0x000000032f71875bf21794a8aa44720e10bef77c12af1aec30951999a4d190d7"))
                                (190000,     uint256S("0x000000002beb4cc8e79a3aed7b1b8329b31a55a3e1556b0933953450a0c185b9"))
                                (195000,     uint256S("0x00000001f2fec10089b395c2df2edbfd15e67077ea48706a43bedaf5eae0e5ca"))
                                (200000,     uint256S("0x00000003d57cdb7fba2f3b641d288737945de2434adeb0b3b3f2ef35a66e45ab"))
                                (205000,     uint256S("0x000000011c8311c289958290444111ffc33261773cc171bfe9a492f59dd2be01"))
                                (210000,     uint256S("0x000000006e43c9650b62ae15d05ada7d12be75df37a8b600b636268b144e2aab"))
                                (215000,     uint256S("0x0000000385861debdf375a584fc33c6da0a13b9ae41cb904483903f29b8f423c"))
                                (220000,     uint256S("0x00000000dd40d7372e60da03205bfc9bd796cc467737e093a58ab08b688014a4"))
                                (225000,     uint256S("0x0000000216ec6bc7a702846ac429ff9e9b1dc14c0528689e810f663a05045f24"))
                                (230000,     uint256S("0x000000015b0545acc87aa652a8d8d5aac1ecfc5e15d9e3a9e4171d472fdfa9b4"))
                                (235000,     uint256S("0x00000000b841e412b8828fe64693bec0a6922d048f8ae061ba547fcad93f7e8f"))
                                (240000,     uint256S("0x000000013e22209c4587e7fce090b7219f2d96640172697d276b606cf53ce07b"))
                                (245000,     uint256S("0x00000002c0b1deff663826669c4a5bbfcba9cf7029598a35bb999afb27cce854"))
                                (250000,     uint256S("0x00000003cba3713646dc533b75fba6f6fe02779e4fb934cda4fe2109c9403268"))
                                (255000,     uint256S("0x00000000b76f444f3f5258a2d20d2639c0bffebb6ee0217caa56fcd0404337d5"))
                                (260000,     uint256S("0x00000001f2dc5f292d9ee232d463faf1bc59362b9b3432f5bd1f72ffc76716f8"))
                                (265000,     uint256S("0x00000003c2dc488c16fc1d73b288065e89bfb9e38dd08cc543867b0b7aa26047"))
                                (270000,     uint256S("0x000000026cc545eed18b508c3368cd20256c012bfa10f5f115b21ad0101c02cb"))
                                (275000,     uint256S("0x0000000376ee6074814c8274238f88e48f96a87ee6ba63e7d349554128087014"))
                                (280000,     uint256S("0x000000036b2c0edb762736b4243cdba4d5b576456cc4c6b6a29ed69d27f0c4d9"))
                                (285000,     uint256S("0x000000064ca1b27d679ffc9e25af53d531d9f80bc00fd130f5a71054b2f96124"))
                                (290000,     uint256S("0x00000000c9bd5248099f4caca2a5b1da88548cd1824bb22a0efa6c30cf6ccfce"))
                                (295000,     uint256S("0x00000002fb6bbf41e4f17f88301895c9143ea93e628523b97e5bd5765070d803"))
                                (300000,     uint256S("0x000000033322d90275a09f4094e5c43db1f7017f788145d5a0edfa8200ecedad"))
                                (305000,     uint256S("0x0000000181e2c1fe3c7ba072a24d19887d814116ecec829af5c49aa6476e14db"))
                                (310000,     uint256S("0x000000003d2d0705590072e4ce94faf7a6ef44218ddd712e9a27bd16ecdfc996"))
                                (315000,     uint256S("0x000000021bbae1442c0ddbfdc9d00b626429ac2643bfe52554487a8db1a82a41"))
                                (320000,     uint256S("0x00000001817aa03c05285c9fcd76cc1f310b1590d92085037626ce590e957cb1"))
                                (325000,     uint256S("0x000000082760f1e42a0473c89b2afe3f1117d50764d0f5a033e0133938c330d2"))
                                (330000,     uint256S("0x000000044b96efd3eb077a516e6bb84f1c4ad5440e779801124071001bdf42fc"))
                                (335000,     uint256S("0x0000000339873b1fa07de5210d45e204be9cd1aacb9e82c135696187d8ea9485"))
                                (340000,     uint256S("0x0000000051649db14dd1557ef4c5cc2bd8ea110e3f0c453f491efe4d21a31356"))
                                (341000,     uint256S("0x0000000c5f55bf23437210f797ebf188a6457f1a4eca47de821a668c2fad8e25"))
                                (342000,     uint256S("0x0000000a2ce9f59248a544d7d53bba47065430e748ce98f8f942847f7396b887"))
                                (343000,     uint256S("0x0000000b186a3e4883076a0771a44a019c35a6844293fb03aad121195d8f6af3"))
                                (344000,     uint256S("0x0000000313abd30aa3828b9b6e5ff312fa3dfa161c47f7e8a10d01d17c877fb4"))
                                (345000,     uint256S("0x00000001d2160a1a6873e7bb8507d4cdd3961398cf73820b1480611812f3eb53"))
                                (346000,     uint256S("0x0000000114bcd5b0b4a3c6dd175ee4c2173c7408edba61fc40826209044b717f"))
                                (347000,     uint256S("0x00000007ab3ec746a2e279a784cc6710d41a518d2b27941d231a7ff4e4a834ea"))
                                (348000,     uint256S("0x0000000c0b772a11bb41c362b74890d4538c325386aea4abbaae15d6789e6acc"))
                                (349000,     uint256S("0x0000000138e50eded6f2f3cf8048d0332209c2b0f8093c6bf2695ce6e6e1c149"))
                                (350000,     uint256S("0x0000000656e29123cd550fc58eebacc37e77e61783d32d0235cde81796a033ac"))
                                (351000,     uint256S("0x000000031517a325e1d9c838c81d88263f7fe0362ede1091a2230c9bf730b21e"))
                                (352000,     uint256S("0x000000026a80af033ac7be8f45fcfc5c0665be0073cc773daf584d6f03af7dae"))
                                (353000,     uint256S("0x00000006cfc77e91f9656fb115b2a1cc75b3def543103e3181aeb5c064929ba1"))
                                (354000,     uint256S("0x00000000488c19fd232d9f524b76480d40621e475f9d07de567323e895ea2d77"))
                                (355000,     uint256S("0x00000006a09508363685c036bbf97abddf1102d7e364a82f4e74139ca185c53a"))
                                (356000,     uint256S("0x000000075259426ff06e73fc17a784d9b8a4a932b95e28a769cc51192c096299"))
                                (357000,     uint256S("0x00000009133b5a079dac92de7371f73af077ca43ce0e435ac727cce95716bf6b"))
                                (358000,     uint256S("0x00000019790c7a510bb1368a512d2056eec1d2c84deccd9fd02fadfcd12f49c8"))
                                (358250,     uint256S("0x00000008c3da7ef9b47fbbc3840721bb29728a266e76e3997958f3ed702def9b"))
                                (358500,     uint256S("0x00000000feb463a7f39261cb2a011f4f0907641c8475c50963a69ec9924b44f4"))
                                (358750,     uint256S("0x00000014d8187303fa9d01e664d8afb4b9dc4ea3fb9b726393c78d5d43d6bfcb"))
                                (359000,     uint256S("0x0000000d1ab129167aadf79236d085d64912254559e3b349cddbd9d8e2cc9699"))
                                (360000,     uint256S("0x00000007f1fbbe7b1e4061d92c3d4823bf82fe1340e7c833ca18c385d08759b9"))
                                (361000,     uint256S("0x00000009b104e5910e4cd859de917fbc5824d77cda00a8f369afdfcb654bc6ac"))
                                (362000,     uint256S("0x00000007307665b04c003201896cb81ee03a987e9bf5f1ec1caf1d1d2ce0877f"))
                                (363000,     uint256S("0x0000000ad4a8891fd8b2566190b6620fb70249ea5dd4d8d72a10c819fb258968"))
                                (364000,     uint256S("0x00000006da9c8a55b102b0a83dbae0e638fab460e9a4a97a67ca16ed7680da6e"))
                                (365000,     uint256S("0x000000118670f8e8f170505c8104650af36ecbb23d19f4a7fc32c4d575934f17"))
                                (366000,     uint256S("0x000000040e90d9092d349ce587c8754e6388737f40db566d9f2075eb9965f534"))
                                (367000,     uint256S("0x00000008c5ca790b031aaf386041aa51948c8b9ef8817b1e4e650bd59d52a8ff"))
                                (368000,     uint256S("0x00000011af9b5aacf71f6e1327a3b90c80b6fb30bf8a028c7f1f10d0e10afaab"))
                                (369000,     uint256S("0x00000008b7e4fec7bc9b367a33dbc80d5614df739519484f39fd9b87bc416241"))
                                (370000,     uint256S("0x0000000a06b9be5e3e785e56246388c8c0f391ee6982d365a626297059eca778"))
                                (371000,     uint256S("0x000000074f03656add0838c5e1f0c2083e0adf7c098029427b80d594f6385d07"))
                                (372000,     uint256S("0x00000003622ee0f44cf93129fcd8754ef503e0301605096776e7cd8746df7a05"))
                                (373000,     uint256S("0x000000016118cb7aac144c8793d5a8c65df545555af3f853e8324b9e225601b2"))
                                (374000,     uint256S("0x00000008dbef76003738a42febb77ca76d72a3315595cf97be686df8fbf93b15"))
                                (375000,     uint256S("0x000000094b84c9ed3eeeceda2840547916793452639d40234b6c8aeb1d4faf3d"))
                                (376000,     uint256S("0x0000000d4e4fb6f7677e71dd7f978043e5db359e008d4c87581735ae537e6f68"))
                                (377000,     uint256S("0x00000002dc382acb83c6da3bc2d5f70e5202a25117936cd451d71897da3e52a3"))
                                (378000,     uint256S("0x0000001047390953f5175e4b159452a7647ccb064997bf296e4577fac8fd44eb"))
                                (379000,     uint256S("0x00000018708d63c2f52a97a579b079a54781583c8f736d07cb6ba47db8e67bad"))
                                (380000,     uint256S("0x00000028e72f85dfcfd618bf2bd518b7325fa55e4c1fd677a165bd02e1552b8e"))
                                (381000,     uint256S("0x0000001cfc4942f776071bcd6ef48ad683c17cef58d64c1a9467cac1caef2c24"))
                                (382000,     uint256S("0x0000001af4337bac1fc8ab2d0ecc05d7d481b7319eac30c8863d983862afe32f"))
                                (383000,     uint256S("0x00000011eb9b3489a3e6c2f8a486de851bfab897b1fbc0141a4e256ac8538015"))
                                (384000,     uint256S("0x0000000963e41b5f9dfd1fec9567bbaa9507302f27fedbe17b6280ea7355bc82"))
                                (385000,     uint256S("0x0000000c95a14770005748f0687448c76d0ff1b91b40626b4177d5340d226742"))
                                (386000,     uint256S("0x000000066f6624e8f14e064726fe05a4dd4534409ce587a9d7df436203cda601"))
                                (387000,     uint256S("0x000000203caf0d35efc4fef301ffe8cf8af5d2524208d7a2127192ebadd9963e"))
                                (388000,     uint256S("0x00000015e49a4d84c5aaed6ba9c59b5dc4f1a8e33c1aad8cbe41bd67472914a6"))
                                (389000,     uint256S("0x00000004470951a99fb556ab07ecb8524ce919435d89d2a8db5616db739a2858"))
                                (390000,     uint256S("0x000000033d0c2ec3165c652756d63eabf60a036be6c5f80d0e5c9d8a24ddc168"))
                                (391000,     uint256S("0x00000006a019c2e6519f93a5c00cb22c1e9e7ef6148241842a707a167c12f9ec"))
                                (392000,     uint256S("0x000000121954ff00030e57b202505b9ed02f14008f9057704054e06fbdeb2c79"))
                                (393000,     uint256S("0x00000008bc99e86d3a9176c251c05f1eb40418f45b6a66cca75db802b2502273"))
                                (394000,     uint256S("0x000000062025be624a42799c0695dcd3b592a61782d66d5ba2f7bd7810ad6cdf"))
                                (395000,     uint256S("0x0000001f0c7abbad99e9cf466c9a75c3ba257ab71148def483ae5a0b1624f081"))
                                (396000,     uint256S("0x0000000789e9fa74b4d8a2b808da7a38b403cc0c4f92c473c5a1ab0ab9b36e1a"))
                                (397000,     uint256S("0x00000016de2b464bc51780358f295da676e46510df4305bf932ff6817231ccc0"))
                                (398000,     uint256S("0x000000146bd7a6a6798698c7239117fdfd8b5a819e37a7f9adfa79cbc9e17996"))
                                (399000,     uint256S("0x0000000d6741914a85e696364cda252340747a3b47f955b99c29e8163192c4cb"))
                                (400000,     uint256S("0x00000004956ccd26d7532b6bf229777675f326523b904f4e1f40b9535a124641"))
                                (401000,     uint256S("0x0000000a974824aa14a61c3b442a15d6bdf0aaa75f5c280d94e43898ef143463"))
                                (402000,     uint256S("0x0000000c071f67605a6764573fd6524fd90628f9ea339ff55c7a20567093251e"))
                                (403000,     uint256S("0x00000000532805ef6cb2c755149a7fbf8b855528fcb513942fa7f5463bfc6cc4"))
                                (404000,     uint256S("0x00000000a2638bf8b0a48d705b117f9ce7457e6fab16b16f70c66d9a50390a53"))
                                (405000,     uint256S("0x0000001cb3b08ce66003deb4d05182ef6f74e4e17dceaf3fd272184cbc6118a4"))
                                (406000,     uint256S("0x0000001292e18ce355fd9c608b029cf16ef459c47503899db896ea5aebf78e34"))
                                (407000,     uint256S("0x0000000efdeebe216c58ac94d9d9bc5aa0d772509e98a256014ecfe1002d31d3"))
                                (408000,     uint256S("0x00000009a0d66c11cc08a8f1d96c7acbd0a97165176045421eba3bc017a42e93"))
                                (409000,     uint256S("0x00000001df73a93028f836593d32511b047e3f4abd73fb92db02809c751457cb"))
                                (410000,     uint256S("0x0000000306911b54cfec6f566e0b8bed99a177ed10e4cc4ca9ff855c906e4b73"))
                                (411000,     uint256S("0x0000000b273b786e21e636c40d4c979b754e97eb3ce9e76d22b8a1901f74a46a"))
                                (412000,     uint256S("0x0000000e850a5c492e1aa8137a721b650297bc599886167def5663abe5804315"))
                                (413000,     uint256S("0x00000005d8c4d2404a301aa254302e70d7f74dde1661279a1f55c0009c48bc94"))
                                (414000,     uint256S("0x000000197263852a1d5f46fa495853723393a36e9c35230c681619aeb9935bf9"))
                                (415000,     uint256S("0x000000119792e3de106d9cd0a91bb922ca1e2717816cd3d3b350578c99985698"))
                                (416000,     uint256S("0x00000005b112e5e5adc86b0dd453cf55038656c0fad340c3a5177923d2f4b0cd"))
                                (417000,     uint256S("0x0000001e947478180ca348d8b6ae653727092327d592d25dbde33fd1cf4ed8cb"))
                                (418000,     uint256S("0x00000018ea0c59fcb9ef2946f6b44eae6794da0a9fa2327258748c5ff0d1ad0d"))
                                (419000,     uint256S("0x0000001dee9250903e8c2bea76ac144dc2dbbeca60d7041dcd5706597ddd5e38"))
                                (420000,     uint256S("0x000000047d784123e1ac2a5b7687b72a8bcf0ff43b02d71db52f7c8f967e3179"))
                                (421000,     uint256S("0x00000015f35a10a8baefd4f0291742f68f84ce0417491c4be3a006cb4c3959e9"))
                                (422000,     uint256S("0x00000004f8fb248fc0e9bf3d99e5379a8e8120c18357f52eabc74553deb7b1c5"))
                                (423000,     uint256S("0x00000010239e5fc5489d350496950b27ab5f34e3774c424a12353bba7440d78e"))
                                (424000,     uint256S("0x0000000a43a0a4a68b2cd61d20065eea7d8a27c20d64555c8320cd4a45d769e7"))
                                (425000,     uint256S("0x000000104d409a2b87617ad6f7638d5000b6ec8aad5f54dee6d6b13e0f7f66b3"))
                                (426000,     uint256S("0x0000000bdddcaaa58568a7d5da4380c5735b9d9374e8e393e14303fca51e374f"))
                                (427000,     uint256S("0x00000002195dafd6ba01b4089c55e35521fed90bf95420abdb73e9edb0c7e779"))
                                (428000,     uint256S("0x00000002ea968e35749a7f41c52e61b0f4635384020a82282d997594b017d446"))
                                (429000,     uint256S("0x00000007e213a5778b3a942016a7d7576c6c141f913342a1f627417c4f334224"))
                                (430000,     uint256S("0x0000000f827d7a004367c15c973814cc47e32287b727ebe3a4cb581703979593"))
                                (431000,     uint256S("0x0000000d709ec810da6a2f55ff5d10bff9a5580ffe4fee8ce27abaf175cb6312"))
                                (432000,     uint256S("0x000000007d91ea56e7e129991aa33e57224d0f898a5a46b02efb81f40aae5ed8"))
                                (433000,     uint256S("0x00000009da7df1aad22c96ed458fa7feae1216811568fb0e9c2f09db25dee3f0"))
                                (434000,     uint256S("0x0000001003f3460d4b0414f94e35025c76f72b8607e0ea00c7790e10172ef8e3"))
                                (435000,     uint256S("0x0000001c399778d54b821c0622087149f39ee688e80bb88b6960ec6e42788918"))
                                (436000,     uint256S("0x0000000c4e21e0ac0f9541357c1a3ce483fd2dd210874ca930dc5b271c7e6b21"))
                                (437000,     uint256S("0x00000003ce6d4b0ea02f483633abae9da2b71e62e14e08f20af13452ab6814a7"))
                                (438000,     uint256S("0x0000000d845b717aec3b273f9cb2d894d3caa05f91b3ad41b6581adfd90b267c"))
                                (439000,     uint256S("0x000000099a44794ccf54bcba10780b163b6a369292263df1d8d62d2d58cc7cea"))
                                (440000,     uint256S("0x0000000b741bda60e14a5d668581f60bfb852b09249428ca7c3a59b01db31af0"))
                                (441000,     uint256S("0x000000150189ff4e6b3292d9feaebc1ed741a6c0534f1050cc152ad65d30906a"))
                                (442000,     uint256S("0x0000000fd26b6822fbda02990619e1729b7f8e7cf1c39178b6040893b92a2cc9"))
                                (443000,     uint256S("0x0000000ce6172397f985d9e3bec3d06c87d5606969a602eff9bae3a6a0e0eeae"))
                                (444000,     uint256S("0x00000011997fb375389ecaecca589e722f9e6fbc147570cb39e88db51811d2fb"))
                                (445000,     uint256S("0x0000000643bf6fd35088aecbebca66d313c4e153176b5da42102197164fef65c"))
                                (446000,     uint256S("0x0000000441b5fb7d9c59fc75fb77cbf9b455dc5b4562bae0ce356500d7f422fd"))
                                (447000,     uint256S("0x0000001978b57b5c4e49a03687a9e002a782548263918b6636cdcc36cdb11627"))
                                (448000,     uint256S("0x0000001f1aa382c9ff75b41da17185a61db07569a4d1afa5040b836dbf7e38b0"))
                                (449000,     uint256S("0x0000001bd53db30e282b94504a8fdb36ede55e3d3ce71336ef844df45b25d51a"))
                                (450000,     uint256S("0x0000001648e3028682b133bc209c2538c6c776bd7d3d4b275dffef75db7bb9f4"))
                                (451000,     uint256S("0x0000001c60e7abdebf883831bd899c5dbd8cac1ea68bb0957701e5595c8011b5"))
                                (452000,     uint256S("0x0000000add6e6c36ec20a4e3091195c052a8f9d6498e1e85dbb10c45b70c08d3"))
                                (453000,     uint256S("0x0000000a2bb73fff81add4d521655fe4566b6c656a9790cd2846f6f1ac7061d1"))
                                (454000,     uint256S("0x000000059a0f7d5f1a381c20d485a1ce2bb41cfc8bc5abcbbf736a236732c3e8"))
                                (455000,     uint256S("0x00000008542e9c1e83fdf4f71ad758ae0d372f95d486d93aaa1c448c529f1e6b"))
                                (456000,     uint256S("0x000000093c40dcbb7152bc2561fdee97d0ddd202348db723755e8e47e10a1cf1"))
                                (457000,     uint256S("0x000000176c7bd888c00198072ff533dd5daa7f0dd1991ee478c97ce2576a544f"))
                                (458000,     uint256S("0x00000012f38a317148fa969062776ad7b30362b1901565f07af3045a324df8c5"))
                                (459000,     uint256S("0x00000008f68f2b3b355f3d6c94d3eb2979e000a3817ae8089b4994d0a04ae13e"))
                                (460000,     uint256S("0x0000001220f5bd3de5167b332268f52d056c5943b9334513d4ee138b97782759"))
                                (461000,     uint256S("0x000000017d7c3a8b03f0b761ad56c1f6678d2642fb1d6a1a286e95fb47a43235"))
                                (462000,     uint256S("0x00000001adb35a7234f02de06199ecd27f857b1304655ff9c37bd2c80c7e82c5"))
                                (463000,     uint256S("0x00000015ee085765078c7c32770f4f6d8c38e25b1f16d3e4f3cea6da27a9e026"))
                                (464000,     uint256S("0x000000165b10b74fa665df705954d8eae919bf6e8912fc8a9a4adb90179a4858"))
                                (465000,     uint256S("0x000000051bd8d780ce69151738f6d4a81ea8b93305dd873396bff24835e9e6fb"))
                                (466000,     uint256S("0x00000006cea7acd52ca5e0bbe0b759b5e26ee1d1f65eddd6b545020c4bd5f4a0"))
                                (467000,     uint256S("0x00000018df5117519d46a4b825c2603927fd62a13d180474135a97af6b5a02dd"))
                                (468000,     uint256S("0x0000000acb30c045fa367e947e1785b9bd65c06d5b67494529450f1ebff3f303"))
                                (469000,     uint256S("0x000000097152a491ad065423de4324ada41f3612de5b80ffb585e28d2a11d2c6"))
                                (470000,     uint256S("0x000000043ed32a85a784f1adf8328f80350b3960698c73345951d99ab369275f"))
                                (471000,     uint256S("0x0000000dabe6173ccc2e8be79774c0aed930c8f24a311e466e543b3bbf36be3f"))
                                (472000,     uint256S("0x0000001f727ffbe5b1ad17206c060aa77e9b20257f1764f1ac018a0f64f19bd1"))
                                (473000,     uint256S("0x0000000b7ee1e1d0f6b577c02a924733d2c4d6d5805daa51e44e543eadacba8b"))
                                (474000,     uint256S("0x0000001260b7935e520244a3591cb6b37de3b36c45dae5318f0bb7eda6847e17"))
                                (475000,     uint256S("0x0000000db956f0dcecc58ccfc8463f49910d455fc3c223ab36a93c5c468513cc"))
                                (476000,     uint256S("0x00000014b1ab6d1690231cbda442ba650ef0935b8b4af0729916ecc1c1a2989c"))
                                (477000,     uint256S("0x0000000c36226af290a2a7744dbcf63b11db9461a7d33b189015b3d751d6acec"))
                                (478000,     uint256S("0x00000002a5d3126c1b40cce8e8e0cf704a8738a04779e79fc056c67ac581178b"))
                                (479000,     uint256S("0x0000000c4f9d596db63f21d129b2662cfe557960493ab625791c770ed53cc80e"))
                                (480000,     uint256S("0x00000009cc852a3483357b3dcecffc2b3beb84c0eec3d884839260d296425d2c"))
                                (481000,     uint256S("0x00000004d3235fe96cd4081679233c82849864be5125e96b4a9c4c0b48bd6e4f"))
                                (482000,     uint256S("0x00000015c6231287c336bf35531a1e92e2e987d8b03e0cc1f1bc5beace0fc980"))
                                (483000,     uint256S("0x0000000a047732481649fce4cdb762cc227963932788ef656ea522d8c719c9c5"))
                                (484000,     uint256S("0x0000001305ab52bdcf98f484e06d8307d82f29dca0597483961e93035f93419f"))
                                (485000,     uint256S("0x00000004a70f2cedfcc478b72666ef04f4831d1498bf859c79eec3314d35f373"))
                                (486000,     uint256S("0x0000000299f0350d0740cd83357be1e9cb9b655169711964dbcf93948e1f1d67"))
                                (487000,     uint256S("0x00000001b4c71614b8a18f5f4948be6e401026ebf02ddf0126541da4e3fb3772"))
                                (488000,     uint256S("0x0000003a3d4e5cb180917aba3f8261a149de3bfd6f6b735caeb3d925c3f9a09d"))
                                (489000,     uint256S("0x00000007be9b81960082d683f138bc12f8d8c4cd16fec1ff35858e57372778bf"))
                                (490000,     uint256S("0x00000001f5787442f49129b71532a0571c5779bbd47e16e68515146e9084fbc6"))
                                (491000,     uint256S("0x00000009cf0c34a427174b044d3c6648574d55d1e6fa4f21d3e74df9374b9713"))
                                (492000,     uint256S("0x00000013bbbff98ddab19a3178a0088a20628791e94963e5d1ea635015dfa9c6"))
                                (493000,     uint256S("0x00000001ed829c061ba14f6953e79d99577079adf5526f1e43e6dc9d9f9571bf"))
                                (494000,     uint256S("0x00000018dfeced2d1584a1003fefa4349810239bade096e53b4fa6bbc38a1685"))
				(495000,     uint256S("0x0000001816af55724cd49c0bfe02c9eac29b4a73db2b7d868b958218a03e6c94"))
				(496000,     uint256S("0x000000007e2019c5246db5a75122c6826822fa154d68a51eee2ff23f54ec668e"))
				(497000,     uint256S("0x0000000aa5803c0825cfa1a34227d0ecb80be191674365a372f71611eacdc742"))
				(498000,     uint256S("0x000000166385022d4b4ade0921a5f6c7d4aec56257cd679f7c441aeb0552b28c"))
				(499000,     uint256S("0x0000002ce5e48efb664e936c9551b2781c742416e519d3a023d087036519507b"))
				(500000,     uint256S("0x0000000cdfe9389bde0e9f1d649dd2f19ee69d765b00907aa681c3cdaad0bdb6"))
				(501000,     uint256S("0x00000028736fd4ce6995a46d217c0022d2882165b5f716e94f255877c73f474a"))
				(502000,     uint256S("0x000000459520215ade21db91a83ad47a806320ba3e290d686149bcf5672e132a"))
				(503000,     uint256S("0x000000086aee5827d0254e1176a4dfd5c8a7958ee1f61458bdb1eb4d6ffbc131"))
				(504000,     uint256S("0x000000474906b6ad537fe14eca1316c7be23f181bc554a2244c97634a6d361a7"))
				(505000,     uint256S("0x00000035db569efc139988b7d506529bb482284bf2dfc40060159b321883974d"))
				(506000,     uint256S("0x0000000c55ddd54e1f0aa6a59abe774f0e14501743c2594184772031f5bf51fd"))
				(507000,     uint256S("0x000000061ca0ea34d5d3ddd5d8ceb0dcf9a0720483efd98155c0aa3774387e60"))
				(508000,     uint256S("0x00000004bd6cdfbbee3945b897c4d6b6f49199d788151fe5536417d31d2f36ab"))
				(509000,     uint256S("0x0000000b73f9dd08528827a8224decf6635462d2adabac9301e5c17b7a24a5f4"))
				(510000,     uint256S("0x00000004c41a5b61302564abc741195c915fdf9edd12669f93ac5d4443613664"))
				(511000,     uint256S("0x000000094319bb7199e5697e458520e95639dcec5180d4442e1470f48feaf125"))
				(512000,     uint256S("0x00000014516f2d52467edd913c52e1742ca8a767debd9294bbbf8f39bdbae506"))
				(513000,     uint256S("0x000000177739b5379d196b74faeaabf35dbb9d3f6f9e172f659f68b3288a71c3"))
				(514000,     uint256S("0x0000000940533509d21f249ab0b0144923e65050a24dbf53863c9c07fd21fd6b"))
				(515000,     uint256S("0x000000007d256fc4cbfff1c05f83550b8dfdf093b060a98fafac6a090e349bc1"))
				(516000,     uint256S("0x000000029ee7abc14842e22b4f3e7e3c640c55fa2a898773c83ff34ceb2a5482"))
				(517000,     uint256S("0x00000019ca7705b4a8b35ae1aa4071401ed1de7449306ef8a34716637f43c2f1"))
				(518000,     uint256S("0x00000013f4aa06fca6c2a57e80c3950d0e7613f3bcba0b52887d4c7579e5b20a"))
				(519000,     uint256S("0x0000000b7d1e4efbbb38c91e838a50876be93a6549fdaeb534ec1d8657117e69"))
				(520000,     uint256S("0x00000000c2fb98b56bf9c549406710b57308081663230a477c7b5983720a456a"))
				(521000,     uint256S("0x0000000d48660709c9fd60f01b71260e0e6ba3875cdb109b7b037ec6b80f3098"))
				(522000,     uint256S("0x00000019d0ad6bdebc9d39a5b9a6ae4d844b45bbfcdd97885841a1d8033c956f"))
				(523000,     uint256S("0x000000121da004ec14c89b67151439765a19aadbdf4d4feca701cce7c3820efb"))
				(524000,     uint256S("0x00000003d3445c4cb6e980751cd8119679d572f57bbaa3b9c9114e397841827e"))
				(525000,     uint256S("0x0000000b2a079f083c86f9ab8b0f73dc511c20f6aa44d7735f29409df966f026"))
				(526000,     uint256S("0x00000004d3ae427a98336ee4bc5e60f00ebd4c88f9ffdd18003f17535465888a"))
				(527000,     uint256S("0x000000057e5cb13f42332f59b6c2d6f333369b8e4d9bdf6fa9bb441e2ddb5c51"))
				(528000,     uint256S("0x000000045f51825c19aab9d1d620d7073c2114ccf3e40f63d66c729c71c2bc05"))
				(529000,     uint256S("0x000000116ac2795cdbde2d3af6d804d9dbf445d2ed12d7cf13c155540f10c119"))
				(530000,     uint256S("0x0000000be4932b469923d826991810109f2c2ca50d5fa0133c765b5ab96bf315"))
				(531000,     uint256S("0x0000000a7fdd8ce073da5d95fcbefba5d0366c9b834cac914889108094d0cd18"))
				(532000,     uint256S("0x0000000600d2ea28f32220c054e2ae66ec8471a2f755ef219a0c81e4a4296135"))
				(533000,     uint256S("0x0000000a5f4a460970f6dcd3a271315f936648c854c1a7bb251dbc7996f90e92"))
				(534000,     uint256S("0x00000009b5d0615eb98f06820cc6d66af542b8bbde0cabe5b54b6e7625e77803"))
				(535000,     uint256S("0x0000000ac06f5d79b927f2dfb54eecd72f9ada28fa59092f5c3c83627b281605"))
				(536000,     uint256S("0x000000037a51adb2cccf29b9c164386c8418959db16606b70a1389fb8755829f"))
				(537000,     uint256S("0x0000000a129157792e233e233f85693625abb14be90362ff727ab97e8d5ec340"))
				(538000,     uint256S("0x00000015e13085045c090a51e9c1114749fa7b465009f2ad70ff278d9ae05b5c"))
				(539000,     uint256S("0x00000001953384069e477f7e1839dc0498cbeb951adb32bcbf3b96ef487fce4a"))
				(540000,     uint256S("0x0000000281246b5d2e845aa711b6af76c8cc0d1f39ba25fe414f83bbe47544bb"))
				(541000,     uint256S("0x0000000f27b777a942d6317438836258c4e34bd3761736a2b32cc2b7c8305d71"))
				(542000,     uint256S("0x00000005d4667fb45a862d91ba843acbaee033915bf75536c67aeca1a2a3a5ff"))
				(543000,     uint256S("0x0000000509b08619049b1aec8e715d971b8dbc2175acf7874a37b9ce13dfb137"))
				(544000,     uint256S("0x0000000582563d79bf72a925ae3bc5c6f0eacbdb317c92fa89eb56d570427fd7"))
				(545000,     uint256S("0x0000000ff9df3d3a00d682f069819acbc5697b42da69a78f6e07486ac68f0e49"))
				(546000,     uint256S("0x00000004653460c603fa7a70292a85e286272b587f0b9cea7e73b765e8b0ef7b"))
				(547000,     uint256S("0x000000074c5f411190c5bf788a37a00506935015df4872cc5471416abadb757d"))
				(548000,     uint256S("0x00000005444a4ecd1eea940ad5395f2f7839967ee5b01be4a9b68755de4395ac"))
				(549000,     uint256S("0x0000000216eafee0e40374b8e8db63118cb4e3adc3159068bdafff1f0e0d9deb"))
				(550000,     uint256S("0x0000000056b84bc88604b9df668b60c020a6926b2dfdcd09955e5d8d3e7a5ca7"))
				(551000,     uint256S("0x0000000adaaeb79c5c6c49038d7206f88d5b4ecaaf21aaca09b5a7d548f76b25"))
				(552000,     uint256S("0x00000004185669b566e62cbebc9c50930c8ae0d5c42f23280262a7f55b726553"))
				(553000,     uint256S("0x00000010112434cdb0203a053e0c22ef16b9d39b8feed2328d7ff97013b216be"))
				(554000,     uint256S("0x00000006dacee96c0f48fc7250c71cc1e746befa84af8cd2ed0499d8d24cc6cb"))
				(555000,     uint256S("0x00000001b3b2c149029d5a2e7cedb0683c97692a52cbc91bb532cb78bbcadcc0"))
				(556000,     uint256S("0x0000000397bdd61939cc3d2c39360c5e3713ef9dd82b8cedac17075b8e177304"))
				(557000,     uint256S("0x0000000414bb81b82a2e71608086ac585dba19ca249067c9e967d6f44a1d3163"))
				(558000,     uint256S("0x00000003516d27423b1b5b60eab97d425e7be3f08f14bafd935666b1e955608e"))
				(559000,     uint256S("0x00000005c44ef4543da5924e65f0fd2d2c8fe926b2f3995b83ccfd1463b443d7"))
				(560000,     uint256S("0x00000002eb33454ba48e61a50351686115c47cb59b8fb0496432ad58e0484acf"))
				(561000,     uint256S("0x00000004172d5940c07ec6d493e410fbab8a05dc73e350505e1540d7336eb353"))
				(562000,     uint256S("0x00000000d9caaf66ad7782046886d3bfdf966c0a015dbae64042cd0c35e516e4"))
				(563000,     uint256S("0x000000000d953e53c65145bfb41ba544a9ce9e5432c9ed8eabd39873dfcb8ab0"))
				(564000,     uint256S("0x0000000d49258678c42bc2ea6f9e5d1206c578da8dc564d1a6114ce68bf77817"))
                (565000,     uint256S("0x0000000124077b644281fe8b904a84773cc69ff75cc1a337a7d8b7a8b60f4948"))
                (566000,     uint256S("0x0000000569218dbcbf107acfa0ee400185a67699cb9ab33ba6342a518548a4bd"))
                (567000,     uint256S("0x00000003d6b00efbf21aa135d0c05c4e5389d37ca1f0bc27f93ca0ad40df5d7e"))
                (568000,     uint256S("0x000000075d6bfd54e9f5df8e3e3416f31f7080823d943452a801d6dfe2e009c4"))
                (569000,     uint256S("0x000000157ae620dfd5a4eda2fae481b38c1c8487d0a08419faaf85dad04e710a"))
                (570000,     uint256S("0x00000003cb99686983e1298491d554b3b368a65c8f20ff66e5f973cf72c95060"))
                (571000,     uint256S("0x00000008b76fe3a819ea810206f2c368f04e06e299cf8a00cbc0b419b6f184db"))
                (572000,     uint256S("0x0000000c20bbb828e25309964ea14c238ff617f2e97de2a0ca1c15b0f18f3496"))
                (573000,     uint256S("0x00000004b9b9bb2b972d7faf6abb529b4ed5e69efe516ea72c4e202426fbc142"))
                (574000,     uint256S("0x000000035646917f7350d27d1031a105b373e0009943925c86347c0ac944c8cc"))
                (575000,     uint256S("0x0000000a6699cfd656d9e1530f497a3258c4ed4bea80f5bcbe3d666d0edf482d"))
                (576000,     uint256S("0x00000005e0ed2dea3cb2d8666227c0e7375f4da8bd7045e915a087b5662f179b"))
                (577000,     uint256S("0x00000009009599f27a22da268316f2d20669a8886a1fa3f2e4e7806c03b441a5"))
                (578000,     uint256S("0x0000000aece28967d3a83a3008e7dec96d525c7cb5eb0d9942e11d81a263e487"))
                (579000,     uint256S("0x00000000cdae1d8f9ff55f9a0848ee7ed2c9634ef876be74c0136598ab3f11a3"))
                (580000,     uint256S("0x00000004b8e4f7d23de574ffe97b22334b33fb15a58e91b5689c02a7c024cdc7"))
                (581000,     uint256S("0x00000003d8e78ee3716bb52274a1ea80228b4014ddff201bc69a4cd200f6fa17"))
                (582000,     uint256S("0x000000060c8ecbc2535c7a6c88795ee8b4ca35047a2a2c620ff5d1e9c77487d7"))
                (583000,     uint256S("0x00000004bf3dd01180d59a167e23fdab0ab50e8a9f8ce16542e0a01387c400b6"))
                (584000,     uint256S("0x0000000720f29b0d72469739e9d94607e67b48eb9957b45c2fd5a34b86df039a"))
                (585000,     uint256S("0x00000001409c395b2e37e2b88110b320996996241bfb489103db9e17aaf2ddc7"))
                (586000,     uint256S("0x00000006ff6509d260f66af2fc4fc1769d56394333f3ad5a19bbd10c8c26742b"))
                (587000,     uint256S("0x00000003866d330ac5448e07eb5e95d2e1860203f2e0ca568161d04ea5c5deb8"))
                (588000,     uint256S("0x0000000247f3b1c8f60b82a1dc5b86ead3adb023a6e3508d1c732c88bceae666"))
                (589000,     uint256S("0x00000000d9108a0e811622919777fb929986966034bb53678d431dd50f0b3640"))
                (590000,     uint256S("0x00000006a7699d8fb948cc67dd2427ee25fbfa2a8e02517aad45880658eab983"))
                (591000,     uint256S("0x00000004f6746a57c60ab45b5d0a30375e635bb8b564c85b92e8b34afbb82077"))
                (592000,     uint256S("0x000000023987ca4c3454b0fd17fe64febcc2c1b75d2820e0368084c59d71cbb3"))
                (593000,     uint256S("0x00000006e05b247fa1a4b99e5292d4c696e2627ed5b64263ceb2a985d98cb446"))
                (594000,     uint256S("0x000000010f20489639e7ec3a3694b2c1def345f2bf7804fadbd1ee92813a020d"))
                (595000,     uint256S("0x00000008fda549361df97ddac7f495fdb629c4c6a646c91e5535f96d12d98dee"))
                (596000,     uint256S("0x0000000512d08ea2cd501bb2132dec8dd997e0332e5d0a51bf9d0992451030da"))
                (597000,     uint256S("0x00000006384749ab79ee12dd46e068634254354c511f535278d54b8efd41e29e"))
                (598000,     uint256S("0x000000031ba9be6704d352002cfb763dc7123e93911796159ef8d2d0328da348"))
                (599000,     uint256S("0x00000005bf47be7b949ff5217ae980fcea48d9d25e824c68367ce934447ef0bd"))
                (600000,     uint256S("0x00000000a721ce253a2c130fec44c581810dfb9448a46ef524a16f1ef3920bec"))
                (601000,     uint256S("0x00000007cdbdfd7f1c9bf8c20ff4f35c2c25a21558a5e70ea139bd50d2421fab"))
                (602000,     uint256S("0x0000000708ba8ec93c022184d3258cd4956f82e2edd0b67c2493f74a3bf6afef"))
                (603000,     uint256S("0x00000005a7b51fd94b80f51ae2b0d0dc8f7285eb418914bd177f6f2fcc68e745"))
                (604000,     uint256S("0x00000010bd1bce0ed2c83f8860b5201a700c535dfc6d6af2c15ee7de4e2e0cba"))
                (605000,     uint256S("0x00000002cac498bb995a395d52a41a48372e57b494de023cd4e2eb70c5616b1b"))
                (606000,     uint256S("0x0000000269e7256e93648c29f72e169767af626c7db95fa8ac853be6072a7942"))
                (607000,     uint256S("0x000000073e07d2a4757b93641c318dbdc784067b02d4cc9f0be4747c80319f3b"))
                (608000,     uint256S("0x00000001613776b53c2060529996e64d24fa5874879b7457aee20430ab2bc87f"))
                (609000,     uint256S("0x0000000acd03e99bfe60d8a5d5023b373aa13f71a5d577c813141b3b714cc95a"))
                (610000,     uint256S("0x0000000aa64b831908eb621b6e2c548620d29146b0c8dae951dd84daef0e63d1"))
                (611000,     uint256S("0x0000000736b273fdf7d8df9bddba568e71547a79e0b14c71027e61dae6a83443"))
                (612000,     uint256S("0x00000012a5b000bcb8606acb628c46d49157bc97189fc8e37dfaaf280b05f8a1"))
                (613000,     uint256S("0x00000006bb698faba83d28b958cd9a242fa9baadb2efa510e2e27b1eebedb951"))
                (614000,     uint256S("0x000000007c66271651afb1468d0546f3ea1b9720d42e3597c9277429d43765f1"))
                (615000,     uint256S("0x00000015a141ae1feec020f529a3e5dea51d29efdef8d0425677e5126c850f73"))
                (616000,     uint256S("0x0000000967c92b77c884fc58d7973a8d78ea47c2ec8e68e1619f6b92f3db2c05"))
                (617000,     uint256S("0x0000000a7eb3e594474d545752f35a70965c17e497c2201fa8f38943bebb8756"))
                (618000,     uint256S("0x0000000ca0f1eb16ed72e5ea4e77cb165fb87384e4c3e0064d5faac7f49c91b9"))
                (619000,     uint256S("0x00000006da3e4a2e36342593090efb0fdf19e77d4ce8663a54df0dd7109b178b"))
                (620000,     uint256S("0x0000000d7c987adbdbf3742c6cebd55b7c8fe213362385f1e24e6eecf7dd4ea0"))
                (621000,     uint256S("0x00000003009cf1ac25864d6997dd9c9ce76cf6cb58f0e61700bb52ec72f54cc6"))
                (622000,     uint256S("0x0000000cf25b9a537ea61d548979003dde28155b73b26d53cf2a7b69036926cb"))
                (623000,     uint256S("0x00000007da399943d00f84c9e190e9968f3f456de70060ad17b6b63606287db0"))
                (624000,     uint256S("0x0000000cab9f7f9e6e5223eda1bee8de7384b6dbed3bfe807818871d78f9594f"))
                (625000,     uint256S("0x0000000266b471c7ee107a85080792531d7dc91c23d7b42b46e44728c3d9ea8c"))
                (626000,     uint256S("0x00000003fe1af9fffd32fae9b809c916d7484024021053c09286c763fd2fc1e6"))
                (627000,     uint256S("0x00000006f9bbef0362e0e99bb4061b4d386c82477d64d84850e4a1b6fce85093"))
                (628000,     uint256S("0x0000000d9afb9e78eac960bc5b7aaa8356ac6660e5147175117ed53f6d41215e"))
                (629000,     uint256S("0x000000071ee3b95304b4df78e66c56f8f1deb557b57ed7716c389b0e04344d87"))
                (630000,     uint256S("0x00000002ed362482e0bc5d03d07e406748590d01871f91e03ed86d15737d1e2f"))
                (631000,     uint256S("0x0000000e55845a96afa1359c6aaac5e66c84daf56ccea33d9127a66e6162736d"))
                (632000,     uint256S("0x0000000fb180307499ce6d21f2308ffdf20b0d03ed45ba0de3420fac71434b95"))
                (633000,     uint256S("0x00000010ddf5569109d8a405eedac88f2ae9f56838dcf279cd9ca32185cf5d55"))
                (634000,     uint256S("0x0000000781805d9c573380c22215cf83280c4d0688bbd730adb0821c89b2a3d0"))
                (635000,     uint256S("0x0000000fa1d7aba218223517de8ceeecfcda087b7e549b0537a986465520e040"))
                (636000,     uint256S("0x00000010eb125169e1e9cbe061564c9c663389b6a68a06445d18c4346601ce78"))
                (637000,     uint256S("0x0000000c85df82c1ade3c311e5673c294d97858ea23dac5d5f03aaf32b374b1b"))
                (638000,     uint256S("0x00000002aa16a3abc3ae9739609eddaf805fce5d0f7b0ae8d9494381843ab5a2"))
                (639000,     uint256S("0x00000012eb63468724acc222e45889a9bf54c1a5e0152ad1fc9c57cdb7bcb460"))
                (640000,     uint256S("0x0000000bf6a31eec79a36c5423f52069e5d6858bfc566081556ba9487a5ef36f"))
                (641000,     uint256S("0x000000065414f1d2a543687ee4c0137ca5d66d5d35f9dbf9b4fe73e59ecc5af7"))
                (642000,     uint256S("0x00000005fe35f60661760b7ca027a73e6915f6add12e736018357a1e782310a4"))
                (643000,     uint256S("0x000000076e77c3e0a2a1890a5bea2d92aa720a08bb4e5571e76bb05c93f40c98"))
                (644000,     uint256S("0x0000001054093374a3a414047113ab882d092f012c1c17cf3d98ca8006b8e8bc"))
                (645000,     uint256S("0x0000000cb0c07c2325e8162e58f3fcc14323450274a1d69aff06ac799cf72f53"))
                (646000,     uint256S("0x0000000252d31029d2e96406697ada40ca3afb3d9fe2a2f67cdad2462e8fe00d"))
                (647000,     uint256S("0x0000001155755f0718b6cc3474e44748358e5328c2c0c32c97cfd3842bf22510"))
                (648000,     uint256S("0x000000173c2e63d658263c1c28e1e0a1b2ce30f2d3d4eba2f540836315a9d5ea"))
                (649000,     uint256S("0x00000002044331ebe095ea838da367fed1495be4ad69b0c655df653ccb1923dd"))
                (650000,     uint256S("0x00000010afad2d800c397557a9cbe501f32cd09f18f89c2f3f11e0e38ae45843"))
                (651000,     uint256S("0x0000000b6a9630f3a2334d4529ba013480104e54fc59dc4cabc3a8869ad17a01"))
                (652000,     uint256S("0x00000004d22aa00fb4c8266b0304f43bc7bec8e18850e764a431438a9fdfd141"))
                (653000,     uint256S("0x0000000a248721cef01783838a5b53547b12273ddf57a2bc3ba708ea987f8937"))
                (654000,     uint256S("0x00000004c95adc9e17e429c35cc4c8ffd130e23228245e29f150896ab66ffdfd"))
                (655000,     uint256S("0x0000001428523dbe3cf9338753a42c579a669df7bbd8d6fa667f4daf2c4c749f"))
                (656000,     uint256S("0x0000001704429a9b902d4cddee708bd0ae7b758c6bd9ed634c143931e15ac337"))
                (657000,     uint256S("0x00000007b376e2c197b21a2eacac81847f401f92ed50213e845e039d3516458c"))
                (658000,     uint256S("0x00000026e751010b1135052b105f2be464702b040d76610bfeae1b1a2bcab15c"))
                (659000,     uint256S("0x00000005d784a9cf7b60bc6908234052c29a555dcf1d4f8a82663aabbc2e0c83"))
                (660000,     uint256S("0x00000015cdf576c284ad93912955194f6764a16d562308bb82bcfdc7a27ad20b"))
                (661000,     uint256S("0x0000000af126a5261626bc10a6cf2a8a07ea145f6aa33539e4d434033411c4db"))
                (662000,     uint256S("0x00000011c4659f0bbe3559c32ff24588d78a3822e8b0e31bb9298a16213fe154"))
                (663000,     uint256S("0x000000076756708535e3daeaca6bc32aa1dc360228af6a0c5e5e07b5d9f5f00b"))
                (664000,     uint256S("0x000000181806c17b47bb843537cc91c95ca1e3596bb9e049d18c2e73c1026258"))
                (665000,     uint256S("0x0000001e966c9edae76c40262e65a6c9ab764a09154eb802fb892ceebc2d1935"))
                (666000,     uint256S("0x0000000b7594c1e8f6ccdf1559e230fdc6c276e8df0a800b7f7c82a237a6c14e"))
                (667000,     uint256S("0x000000101801a801c21a2e50d4a5173e494f2e9ee604cec5886a8547680accaa"))
                (668000,     uint256S("0x00000001ee22e21a6d5a5b322ea1ec69231b35d72d54f9fbdfa5dfdc5c7e2f4a"))
                (669000,     uint256S("0x0000000f8fa48f7244099f17c8dbf79982f5dec586b5b32d0fa30f18540081ca"))
                (670000,     uint256S("0x00000008d3b0a1f5286574ba5fe05c3151144cd7f330f2f1ec3f2009d4b82687"))
                (671000,     uint256S("0x0000000dd430c9a8e3d83f123f0bc6b6ba11e774ec6bdcf1a13c216b8e071d3e"))
                (672000,     uint256S("0x0000000326bd2c2465754ee03f2a9d82d902a19e7d92aef3c9967cbbbdd37da9"))
                (673000,     uint256S("0x000000053e15e2ee0f6fdb5d6a096fb3b785f82165f5126805fb785d884bef7c"))
                (674000,     uint256S("0x0000000472c24f87b24de8e091ae9b191d0a114ecaecf7487c5ccd88680b4799"))
                (675000,     uint256S("0x00000007bc716ae47620f86f7f38010b43a92560b4d901cd4fa945c20ffeee4a"))
                (676000,     uint256S("0x00000011506c87f327448ff75a37168ee0a31f199dc8f42499247f4af5f84a71"))
                (677000,     uint256S("0x00000007e26fe6537984fc6f7d9164a6edcd9fa1c92a0ba1f2bafed491c50976"))
                (678000,     uint256S("0x00000013a790e855c1722c648e930302366b15c78f6f2a9d0bc01ce0c8faec69"))
                (679000,     uint256S("0x0000000f8519548ca86c8689fc4282e1ce7ab34a39680c7dde40846e49235299"))
                (680000,     uint256S("0x000000060f172b876390a65c27ad87360e16b8710a4b184b11ed09844b5327fd"))
                (681000,     uint256S("0x00000001a43cafd9c0858e23c62e629609f9e73905fe8f6de14b0db5c8811f31"))
                (682000,     uint256S("0x0000000b8330e95dc616e2b455de087d541e4ab8f17bff162b08d66b113ccee0"))
                (683000,     uint256S("0x000000082fdac13fff52ef28e0b288963b091b991be5fec2684092664340d05b"))
                (684000,     uint256S("0x00000037cde1f403c7fadb6042d63bec2b04de94d6a9c6202dc371146d4c4745"))
                (685000,     uint256S("0x00000010795f12db65a60d307bedf42692c1b09a909cc0963bf73df8960c6d3d"))
                (686000,     uint256S("0x0000000b1aec6e706333d02892de401375820a71a307b49671667b10738f92fb"))
                (687000,     uint256S("0x00000014ba8dc2c0e5a40a4787ca257a220627ebc183ee460d8ae7fb6ddd3ce0"))
                (688000,     uint256S("0x0000000edade4f635276a397c9704ea83bdf006d6ee8c8a2fe0f2a41b1e1a2c7"))
                (689000,     uint256S("0x0000001834d62f37506d7729df7784ff6aa082f227a8c248bfc7d646856cfb2d"))
                (690000,     uint256S("0x00000007f1fc92391ef45142f537991b974151eff532aa3832adadf3b46bcb95"))
                (691000,     uint256S("0x0000000ef2ee7f7801125026414f2e1b98571f8a5f74615447ba2f62c24b4a22"))
                (692000,     uint256S("0x0000000b4640658900c7265b94dae90370de8d1673a909239629b26bd2fd5b06"))
                (693000,     uint256S("0x00000012c16de95e8a827c6337de6ab2e04c94eb12a97aa20fac3acc479bd703"))
                (694000,     uint256S("0x0000000a6ccfa9999373584068cab8a9670b287905d7f095d8144ca03694bbf8"))
                (695000,     uint256S("0x000000132069bbd8a9dd0cec996879b949b2a9862fdfa907c3559929865372ce"))
                (696000,     uint256S("0x00000005dc30a87aafed1a5703403573234529a8fc0e7f4cb789d3b22406476e"))
                (697000,     uint256S("0x00000004f7fc3367c3483d0ac17ef6c30148c31d0dd7ec14503c69e79212aaf2"))
                (698000,     uint256S("0x000000116f56e8cf6e7ed759f8095f0b7bd48c5aec6d35615bfd479a042cf094"))
                (699000,     uint256S("0x000000096cc740eada81deca2d6a2f2fb30e5a5f15bce44f206e9a15c374ee84"))
                (700000,     uint256S("0x0000000ebb5da3d51a7897c9224fc236bd8085fbd0e1ac4eb08063eef04c1326"))
                (701000,     uint256S("0x000000032acf386d4ac320303d8d3d5e6885dd384417a5d0b994c8fe101405c5"))
                (702000,     uint256S("0x00000000f135d58892ddb7f17a7d1d34d108b177152bce2adde48d58a72480cd"))
                (703000,     uint256S("0x0000000a469db4ff74c9bdf7903981a3247cb11cbc6ece12fb0e8d34206ba583"))
                (704000,     uint256S("0x000000024f09cabdd6fbdd379b74d4535c20d5bc78f78725f2d87b257ab3a64d"))
                (705000,     uint256S("0x0000000c122244118777ca474fe3f30151849ff253ae730dc433900aea5616c5"))
                (706000,     uint256S("0x000000044ac2724bdc4a6b2280e56f39bff25a974f0a5dd5254ae485e159a442"))
                (707000,     uint256S("0x00000000f78f57e7ddb7791529ae2cafcbface8b84dd73cca05b1ee0a39e805d"))
                (708000,     uint256S("0x0000001103a4845c38a3f66fdd58f9d94374f30ab8c0733d4078d8dcd3d3e26f"))
                (709000,     uint256S("0x0000000c99f7c770acf46982e474ec975b8553f6cb7280c8aa4dc8ecfd4502e1"))
                (710000,     uint256S("0x0000001a51c2e34893cc22a3b971bedb378bd67ca72ec7c3ed4d23525adabff4"))
                (711000,     uint256S("0x00000002c448af5f17a48d7f05af47603b75c630a09e04fef2b9f0f21945aebf"))
                (712000,     uint256S("0x0000001e0056b9ebeb5243761efeeb0664eaa0ff89abc36dafcf7f71be8193b1"))
                (713000,     uint256S("0x0000001517c5c0baba314bd145724a2bbf5216263a5c8ce49ca340bebe1599cc"))
                (714000,     uint256S("0x000000004029d0f2c3e7ec91d2aef9e81d1cf77285f9171c54385ef35c02b6b2"))
                (715000,     uint256S("0x000000006e564468d95f88cea7cb129d5ec9471d8926899cba01d0983032bf3b"))
                (716000,     uint256S("0x0000001da54ab2dc4117a35bbfc2338f61baa512e33f34ff18eaa55fc319c586"))
                (717000,     uint256S("0x0000002259b8ca50a1e7f9b9af40806c985a3132ff6dfd31e6d01bbab5403918"))
                (718000,     uint256S("0x000000220342ec4cf63c780ce8d08a5af38bfa8b5bb64c972c8a2329610056be"))
                (719000,     uint256S("0x00000037b81377ae13ce1b04a4404aaeaf495583da0a861f39ce189eabe7d5a7"))
                (720000,     uint256S("0x0000000eb0b2819480c099e6cca141b798bcf07c66bedd04f5850f86c0b8878b"))
                (721000,     uint256S("0x0000000865b0212e22de923d8f4bef23c8ce246daeddefabb6241a1eb41da109"))
                (722000,     uint256S("0x0000000e716a800aedd611b6314c78ac20aefe48fa47573cb70f381160e0db23"))
                (723000,     uint256S("0x00000011424c16a23f43d2d38a3bbcfab3d821517edd4d57f02ec3a6746db787"))
                (724000,     uint256S("0x00000023868c6026b6d9b1e409ba4e89815799f04e56dcf9069533ae1822d87d"))
                (725000,     uint256S("0x0000000ce2234cb1cab7b1f14f0645d8583bcd6577bbc6ce55917bc2e48605b1"))
                (726000,     uint256S("0x0000000b7d068029b3dc7c3b5b20b5385c440e3fce25f22af01e2f340803e953"))
                (727000,     uint256S("0x0000001397b76c4d49c4fab404e601125a0339973ddc14d40614a55f54c9d139"))
                (728000,     uint256S("0x00000021f973a90b8d3056997fae4c623f73af904872aed33f63d5ebce94b315"))
                (729000,     uint256S("0x0000000316dfae7d3e960e6da972733b97c73f2bba07fc97441d86a1f2632cf7"))
                (730000,     uint256S("0x0000000c9187c64cad22d367596ee5437ffd41fed4330bcf74fff1ce549f3d9b"))
                (731000,     uint256S("0x000000041deda86540d5cb4511dd940a683f6bba285e2c89928835101886901c"))
                (732000,     uint256S("0x000000052705093cb4bcea0f465d0a532b9e9d61ab78be0bc985ebf66187903e"))
                (733000,     uint256S("0x0000000e5e84cd1dc70734ed8c6befb320cb32840f77d9419d7dfc4471ec6485"))
                (734000,     uint256S("0x0000000d3fe5f94dc80adfc50d38292d0f94a75d639be4d841b5f77975078102"))
                (735000,     uint256S("0x000000101579eee0e2ffe5e23626404792cfa337e87cf0375139cd928042244a"))
                (736000,     uint256S("0x00000011f37e135c1bffb0825f2cf88c3c248daddc3223b1b3fb4138d9f77654"))
                (737000,     uint256S("0x0000000d96401f6a82ac6d443c99a65e880d79aefac3801d5080c927dbbca761"))
                (738000,     uint256S("0x0000000d0983a0a7959cf28b2697e3f5902693279f598df70c61906099c38747"))
                (739000,     uint256S("0x0000000c4614c2dabe3069cbaae5f79509547f632744ed007e96928e3bec6d1c"))
                (740000,     uint256S("0x0000001370fc0baaf711be451a2b9a5a2d5d59cedde84e69067e060df6cd3778"))
                (741000,     uint256S("0x0000000c81a032b51c07f7f33979d694c4f563a25de843c3d48201960369712b"))
                (742000,     uint256S("0x00000016521be5ffa22b2a53f52aaccd1f3c3bfbfd7b3351107bb701934cf2c0"))
                (743000,     uint256S("0x0000001557b93d2d702c46f80f8a447867bbe2cbd0a9b316561adb01e491276e"))
                (744000,     uint256S("0x00000004967284091afe656b8224e4da1aa4a5964d1bac02070c89a49534d237"))
                (745000,     uint256S("0x0000001a96bdfcb7e55584fc9159e7b4c88c6a64892fef3036179135bc49013d"))
                (746000,     uint256S("0x0000000b44163c78a309335f1ac87d969ff53e38b6994a428b61a192422b32c4"))
                (747000,     uint256S("0x00000022ba85723a6fc37817c9a5b911c805e9da7296dc4183f642641e14b39b"))
                (748000,     uint256S("0x000000239b4649133efc60534ce96f3d99974609f3bfce8129cb5f46ec9d3081"))
                (749000,     uint256S("0x0000001f9228fb3382e0e6f4c12717e8178c2fbd4778844169144676c177b87e"))
                (750000,     uint256S("0x0000001a4cbef7572c4a65f60b60698030b578076ea9975dd0824373ce2c4183"))
                (751000,     uint256S("0x000000022106ddb102cdc9b469c396bde3f72193bcf015f40bf6608e72a2c11e"))
                (752000,     uint256S("0x000000042593732f28182b5ea47ced401b38b9284d9f146be69c46db2740d34b"))
                (753000,     uint256S("0x000000235270b26418f0794246aa0dd87e5e6f8200737fbb59a0549fbaad9a60"))
                (754000,     uint256S("0x000000102687d9069e5c4947c438e8a1463c6ca5c790071fce9bea89aabd496c"))
                (755000,     uint256S("0x000000262e22ed0adb3f0cc209d9f8b1240ff71c7f29e8baec7ce4fdcb0e14c9"))
                (756000,     uint256S("0x0000001e8d1e8c70ed915ef61dcbb8c2fe10ed0b8e8762085a6bc3e6630b4e87"))
                (757000,     uint256S("0x0000000501487876ac71c5a07fbeaeaaa636362f671fd067c552350d2ef6fa3b"))
                (758000,     uint256S("0x000000154c7b0267c5bbbaeb33a84c53fe34781a556d23e26578f12083ff6e04"))
                (759000,     uint256S("0x0000000aec8ac88a0b28c58b0329bac0091ad68f730ec55f82f2edcc1cce946f"))
                (760000,     uint256S("0x00000018df2e264ef0fc15bb4ad1fa12e818625f9e095ac6003aaa1f4060ce89"))
                (761000,     uint256S("0x0000000c78d9666e517303dd7a4b00ec34229f9f429cfe51717a581ea26e67f8"))
                (762000,     uint256S("0x0000000c3b416775bb8994ce58ae6bae5ce684cc79674f09e36929e76fa4ce07"))
                (763000,     uint256S("0x00000004383f6ba79fb60065e1c95b3ff98dd1aceb8d49fbe03c350324e5046f"))
                (764000,     uint256S("0x00000023a90688247c20fd9e74c5a2b3130fb84ee09a5c0a141364bfe760958b"))
                (765000,     uint256S("0x00000005c59ad86d2fcaca989c59e13bcfd3d63e3130daa5328210ea031109fb"))
                (766000,     uint256S("0x000000041f64eb49c7d081105daf6d271bc1c1ed9e3d183c843c472045ab94ce"))
                (767000,     uint256S("0x00000001795f0383cbfd09e28deb4428b6bf336c464c98e843863dbcdee4c025"))
                (768000,     uint256S("0x0000001834285286165f94ba31da2fbd7e4abe4bfff2713dea4e276b27d6ee93"))
                (769000,     uint256S("0x000000151c6b74ea90a8948b53d0819c3503429cd6066bfcc7d8b7df283da7aa"))
                (770000,     uint256S("0x000000085b03765792e28df72ca455c6b286753dc9830198d7fac6e8de9b20f3"))
                (771000,     uint256S("0x0000000fee1601dd6576b2a79dc44f1c3953102f95428f32db5034148a3c64e0"))
                (772000,     uint256S("0x000000126b0e3189b7855022476f58dcfe115ee4c70b54ea4f433853f33fd33b"))
                (773000,     uint256S("0x00000009e4dddde6d966fffd07e28c980b825a3415d60e324e02e30b82a07a50"))
                (774000,     uint256S("0x0000000402c75136d79a96872dba53464c059732751896df53f332a493a34b31"))
                (775000,     uint256S("0x00000013cd3e6bf1a13d67849c27538b9aca293fb2f33d9bdbfc038bc8b78186"))
                (776000,     uint256S("0x000000034bb0753d3ec0f888ac767d0664aab9a62716d2f8e09310b3dfb69589"))
                (777000,     uint256S("0x0000001a66c05603c01ea5e70050bb3045e49933b2da1f68a089e953fca1cc58"))
                (778000,     uint256S("0x00000016a6f7b684c02fe3f7d15fc6606410b5ba194b895d99a39aaf766d3d0a"))
                (779000,     uint256S("0x00000007b84369e550415cd9cbf9b218d7f6c0ab8ce2fd6c3c14d83c24b8c831"))
                (780000,     uint256S("0x0000001bc54272022faf7cf4c0d7191b59f351c27dbc3e27af61d56adf9f8db8"))
                (781000,     uint256S("0x0000000422000e5283a68d4b4455f9499095be3c4435499105e2c2e4462042d7"))
                (782000,     uint256S("0x0000000e8665d4347064e1b5356e12e45ba8777d895c6db62ff1a9d54353d4c5"))
                (783000,     uint256S("0x0000001596b5ba5abae70e0577fa2d0b9923b137f95c46d9e4e24f9f75408e83"))
                (784000,     uint256S("0x00000009d64751d77720a9e53afc5772de4b038ffa91b7f01198faf8f92948ba"))
                (785000,     uint256S("0x00000018491e220d32dd46eb630493cf5b5d3510ead86fccdd24941a096fdffc"))
                (786000,     uint256S("0x00000009b3bba2ff0ce705eac99fd25cdf57c8e10f562a30c8b7d536dc25f807"))
                (787000,     uint256S("0x00000001713c2458ca82591e673efdfdec1351c65e948cac6596d567b014d5a4"))
                (788000,     uint256S("0x0000000fcc283f93d198e9af8ebeaf352004aa176ee1343b67167f3fc5b7fca0"))
                (789000,     uint256S("0x000000126872b709595db5a70d1ed1734824c7975a910d76c32e8c5339f7e66f"))
                (790000,     uint256S("0x0000001759742e4eed5989c313b0de4309155e131dcdd1d2c08506c72d3ae39d"))
                (791000,     uint256S("0x0000001cf3dd31bdcdbeee12a7fe7771f9a4c4e8536e6c3da9a0f9657c6b1233"))
                (792000,     uint256S("0x00000013718aa22f069d05e7bf02e7c7f534b739f3561d9beaa3c6d4f07e89b7"))
                (793000,     uint256S("0x0000000d5f13600d80b55d0d6ef495c97a33ee81794682336d6a161add5aa6f1"))
                (794000,     uint256S("0x000000125c3875745f5afb75b60a9d378bd707d6e36020e4a9462e0a3078851a"))
                (795000,     uint256S("0x00000016aaa27a9b6dc0b2e2192417fc202185ca52f47bb34dbad624163c32c2"))
                (796000,     uint256S("0x00000016fa029c2e10941d5f59930047e02ea3cf0f4960bcf0ab0b3e02ec1c47"))
                (797000,     uint256S("0x0000000e250a69c6c8a1b7d86bc1a69c1f9c20ef78fe90902d581add6e7725c9"))
                (798000,     uint256S("0x0000000bb74902f5d5a6ecf084bbf1b9bf00c2ee0db935942df8278b1e9e98df"))
                (799000,     uint256S("0x0000000bdf0fd1c93e8e105d87e0fa93b80cb46b7fe8775975df4f696ca496ec"))
                (800000,     uint256S("0x0000000f0fb98bf6890d4fcae25128c10e6b8956fd5672dad3aa8cb50d7e1caf"))
                (801000,     uint256S("0x000000114369a780ce7f71b8482036d1897e9d798a67b8a3933628391b6af27a"))
                (802000,     uint256S("0x0000000342e0f9b65b257046b0581d0701ffa639b7c67cc0573e3825590f291b"))
                (803000,     uint256S("0x00000012460bda352fde2c8ef056ef266532fbf10902882b405c5bc9ae9a846f"))
                (804000,     uint256S("0x0000001fc3769dbbf3877a52ff39316e2132d81f8f0d0376927b64d94e4f7b63"))
                (805000,     uint256S("0x000000053cb85ac301727f883cbff748da578d69f2206026afa3a82cce2274eb"))
                (806000,     uint256S("0x00000001e56632c584ade9824907b1edf792cbdef8152466fd6d78792da295b4"))
                (807000,     uint256S("0x00000013511a9e9871f33543489892e0abc81e942b7c234496f0ad228fd71908"))
                (808000,     uint256S("0x00000025d48985adb86510fc873ec49c1013daa8baa5bb6d1b9f27fb64d1c557"))
                (809000,     uint256S("0x0000001cf14358b8ec250c36882add7327d1683311dfe616803ea7dfb4c4fa0b"))
                (810000,     uint256S("0x00000025015c9b84da2768de29734421ea62eeec748707e5e71072544808f890"))
                (811000,     uint256S("0x000000135b3c8688693605a5878f5ffc9c486e13e4f12846e27b20da6486df29"))
                (812000,     uint256S("0x000000130932327eb52b9229cb8574b552f39a83d8def5bd2ce12a6094f26093"))
                (813000,     uint256S("0x0000000236505351e3ed94c075d7ab4f91cec65b4d15d8e47338833c744eaf00"))
                (814000,     uint256S("0x000000025cdfe869ed1ab7cf74c5fdad85e7c2b1b946b2c618d4035db2ae25cb")),
                (int64_t)  1643000155, // time of last checkpointed block
                (int64_t) 1256633,      // total txs
                (double)  1264        // txs in the last day before block 814560
                };
        } else {
            checkpointData = //(Checkpoints::CCheckpointData)
                   {
                            boost::assign::map_list_of
                            (0, pCurrentParams->consensus.hashGenesisBlock),
                            (int64_t)1231006505,
                            (int64_t)1,
                            (double)2555
                    };
        }
    }

    pCurrentParams->SetCheckpointData(checkpointData);
    fprintf(stderr,"%s: Checkpoint data loaded\n", __func__);

    ASSETCHAIN_INIT = 1;
    return(0);
}
