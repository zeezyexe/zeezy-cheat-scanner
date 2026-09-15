#include "scanner/MemoryScanner.hpp"

#include "scanner/BypassScanner.hpp"
#include "scanner/ClasspathScanner.hpp"
#include "scanner/PEIntegrityScanner.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <queue>
#include <cctype>
#include <ctime>
#include <iomanip>
#include <intrin.h>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace scanner {

using HitFn = std::function<void(int)>;

struct AhoCorasick {
    struct State {
        int next[256];
        int fail;
        std::vector<int> output;
        State() : fail(0) { std::fill(next, next + 256, -1); }
    };

    std::vector<State> states;

    AhoCorasick() {
        states.emplace_back();
    }

    void AddPattern(const std::string& pat, int patternIndex) {
        int cur = 0;
        for (unsigned char c : pat) {
            if (states[cur].next[c] == -1) {
                states[cur].next[c] = static_cast<int>(states.size());
                states.emplace_back();
            }
            cur = states[cur].next[c];
        }
        states[cur].output.push_back(patternIndex);
    }

    void Build() {
        std::queue<int> q;
        for (int c = 0; c < 256; c++) {
            int s = states[0].next[c];
            if (s == -1) {
                states[0].next[c] = 0;
            } else {
                states[s].fail = 0;
                q.push(s);
            }
        }
        while (!q.empty()) {
            int r = q.front(); q.pop();
            for (int idx : states[states[r].fail].output)
                states[r].output.push_back(idx);

            for (int c = 0; c < 256; c++) {
                int s = states[r].next[c];
                if (s == -1) {
                    states[r].next[c] = states[states[r].fail].next[c];
                } else {
                    states[s].fail = states[states[r].fail].next[c];
                    q.push(s);
                }
            }
        }
    }

    bool Search(const char* buf, size_t len, HitFn hit) const {
        int cur = 0;
        bool any = false;
        for (size_t i = 0; i < len; i++) {
            cur = states[cur].next[static_cast<unsigned char>(buf[i])];
            if (!states[cur].output.empty()) {
                for (int idx : states[cur].output) {
                    hit(idx);
                    any = true;
                }
            }
        }
        return any;
    }
};

namespace {

struct CpuInfo {
    int cores;
    int logicalProcessors;
    bool hasSSE2;
    bool hasAVX;
    bool hasAVX2;
    bool hasAVX512;
    size_t cacheSizeL3;
};

CpuInfo DetectCpuInfo() {
    CpuInfo info = {};

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.logicalProcessors = sysInfo.dwNumberOfProcessors;

    info.cores = info.logicalProcessors;

    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 0);
    int maxLeaf = cpuInfo[0];

    if (maxLeaf >= 1) {
        __cpuid(cpuInfo, 1);
        info.hasSSE2 = (cpuInfo[3] & (1 << 26)) != 0;
        info.hasAVX = (cpuInfo[2] & (1 << 28)) != 0;
    }

    if (maxLeaf >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        info.hasAVX2 = (cpuInfo[1] & (1 << 5)) != 0;
        info.hasAVX512 = (cpuInfo[1] & (1 << 16)) != 0;
    }

    if (maxLeaf >= 4) {
        for (int i = 0; i < 4; ++i) {
            __cpuidex(cpuInfo, 4, i);
            int cacheType = (cpuInfo[0] >> 5) & 0x7;
            if (cacheType == 3) {
                int ways = ((cpuInfo[1] >> 22) & 0x3FF) + 1;
                int partitions = ((cpuInfo[1] >> 12) & 0x3FF) + 1;
                int lineSize = (cpuInfo[1] & 0xFFF) + 1;
                int sets = cpuInfo[2] + 1;
                info.cacheSizeL3 = ways * partitions * lineSize * sets;
                break;
            }
        }
    }

    if (info.cacheSizeL3 == 0) {
        info.cacheSizeL3 = 8 * 1024 * 1024;
    }

    return info;
}

} // end anonymous namespace

struct ScanConfig {
    size_t chunkSize;
    int threadCount;
    bool useSIMD;
};

ScanConfig OptimizeScanConfig(const CpuInfo& cpu) {
    ScanConfig config = {};

    size_t optimalChunk = cpu.cacheSizeL3 / 4;
    config.chunkSize = std::clamp(optimalChunk, size_t(1 * 1024 * 1024), size_t(64 * 1024 * 1024));

    config.threadCount = std::min(cpu.logicalProcessors, cpu.cores * 2);
    config.threadCount = std::clamp(config.threadCount, 1, 16);

    config.useSIMD = cpu.hasAVX2 || cpu.hasAVX || cpu.hasSSE2;

    return config;
}

constexpr SIZE_T kDefaultChunkSize = 16 * 1024 * 1024;

std::string NormalizeFullwidthUnicode(const std::string& str) {
    std::string result;
    result.reserve(str.size());
    
    size_t i = 0;
    while (i < str.size()) {
        unsigned char byte1 = static_cast<unsigned char>(str[i]);
        
        if (byte1 == 0xEF && i + 2 < str.size()) {
            unsigned char byte2 = static_cast<unsigned char>(str[i + 1]);
            unsigned char byte3 = static_cast<unsigned char>(str[i + 2]);
            
            if (byte2 == 0xBC && byte3 >= 0xA1 && byte3 <= 0xBA) {
                result += static_cast<char>('A' + (byte3 - 0xA1));
                i += 3;
                continue;
            }
            if (byte2 == 0xBD && byte3 >= 0x81 && byte3 <= 0x9A) {
                result += static_cast<char>('a' + (byte3 - 0x81));
                i += 3;
                continue;
            }
            if (byte2 == 0xBC && byte3 >= 0x90 && byte3 <= 0x99) {
                result += static_cast<char>('0' + (byte3 - 0x90));
                i += 3;
                continue;
            }
        }
        
        result += str[i];
        i++;
    }
    
    return result;
}

const std::vector<std::string> kRedDetections = {
    "arsenic.injection.accessor.IMixinS12PacketEntityVelocity",
    "dev.lvstrng.argon.mixin.EndCrystalItemMixin",
    "ares-fabric-1.16.src.main.dev.tigr.ares.fabric.event.player.AntiHitboxEvent",
    "com.apollo.api.event.events.TotemPopEvent",
    "com.obamabob.apeclient.clickgui.windows.AuraSettings",
    "DTool.command.impl.ArmorStand",
    "me.ritomg.ananta.module.modules.combat.AutoXp",
    "allah.owns.me.allahware.guiscreen.hud.ArmorDurabilityWarner",
    "dev.luminous.api.events.impl.EntityVelocityUpdateEvent",
    "1.8.9-Forge.src.main.me.kiras.aimwhere.modules.combat.TPAura",
    "me.mrhakan.agalarhack.Main",
    "com.wms.abstractclient.mixin.mixins.MixinRenderEnderCrystal",
    "fifthcolumn.n.modules.AntiAim",
    "me.earth.earthhack.impl.commands.MacroCommand",
    "com.elementars.eclient.command.commands.AntiVoidCommand",
    "bdf08be35c68e969d",
    "lol/lwes/voilloader/VoilLoader",
    "(JLcn/gov/vape/util/jvmti/ClassLoadHook;)I",
    "icetea_dx9_final.pdb",
    "MoonDLL.pdb",
    "Monolith Lite",
    "UwU Client",
    "sugma-cheat.pdb",
    "AutoClicker.class",
    "AutoClicker.pdb",
    "Crim v1.01",
    "Destructed Succesfully",
    "Injector.pdb",
    "rg/core/e/e/AttackEntity",
    "thunderhack/module",
    "assets/catlean",
    "smoothboot/client/module/combat/AimAssist",
    "dev/zprestige/prestige/api/mixin/MixinLightmapTextureManager.classPK",
    "bre2el/fpsreducer/feature/module/modules/client/SelfDestruct",
    "ops/ec/base/aopthngt",
    "slinkyhook.dll",
    "slinkyhooks.class",
    "org/appleskin/module/combat",
    "Stray Bypass",
    "Only Crit Axe",
    "Stop at Target Vert",
    "Stop at Target Horiz",
    "ahc.class",
    "Anch0r Macr0",
    "L3g1t R3t0t3m",
    "Breaking shield with axe...",
    "7hr0w P0t",
    "Aut0 Jump R3s3t",
    "4ut0 Jump r3s3t",
    "M4c3 Sw4p",
    "Mac3 Sw4p",
    "Aut0 Cryst3l",
    "Aut0 H1t Cryst3l",
    "Aut0 H1t Cryst4l M4cr0",
    "Anch0r M4cr0",
    "D0ubl3 4nch0r",
    "S4fe Anch0r",
    "4nch0r M4cr0",
    "Aut0 T0t3m",
    "Aut0 D0ubl3 H4nd",
    "Aut0 Stun",
    "4ctivat K3y",
    "D4m4ge T1ck",
    "Sw1tch D3lay",
    "Ch4rg3 D3l4y",
    "Expl0d3 D3l4y",
    "T0t3m Sl0t",
    "Ch4rge D3l4y",
    "M1ss Ch4nce",
    "Expl0de Sl0t",
    "Expl0d3 Sl0t",
    "N0 Dglwst0ne",
    "Clk Sim",
    "P34rl C4tch3r",
    "Aut0 XP",
    "Thr0w3 XP f4st",
    "W1nd Ch4rg3",
    "4c7 K3y",
};

const std::vector<std::string> kYellowDetections = {
    "B.fagg0t0",
    "aimassist",
    "MAX_ESPERA_TICKS",
    "esperandoCristal",
    "posCristal",
    "buscarCristal",
    "kanPlaceKrystalServer",
    "modifyDecrementAmount",
    "preventSwordFromBlockAttack",
    "preventSwordFromBlockBreaking",
    "shouldBlockBlockHit",
    "lwfh",
    "stickyAim",
    "stopAtTargetVertical",
    "lookAtNearest",
    "OtherClientPlayerEntityAccessor",
    "Only gets triggered if holding",
    "Checks if the player is blocking your hits",
    "After you move your mouse",
    "triggerbot",
    "killaura",
    "selfdestruct",
    "strafe",
    "pingspoof",
    "meteorclient",
    "prestige",
    "s3lfd3struct",
    "playerreach",
    "jumpreset",
    "fakelag",
    "autoclick",
    "hotbarswap",
    "switchdelay",
    "switch_delay_ms",
    "swapBackToOriginalSlot",
    "attackRegisteredThisClick",
    "findKnockbackSword",
    "lvstrng",
    "safe anchor",
    "safe_anchor",
    "auto crystal",
    "anchor macro",
    "auto totem",
    "autototem",
    "auto_hit_crystal",
    "auto_inventory_totem",
    "EndCrystalItemMixin",
    "isDeadBodyNearby",
    "POT_CHEATS",
    "getBlockBreakingCooldown",
    "Aut0H1tCryst4l",
    "Anchor_Macro",
    "Auto_crystal",
    "hookCancelBlockBreaking",
    "canPlaceCrystalServer",
    "onSwapLastAttackedTicksReset",
    "redirectSelectedSlot",
    "getHandSwingDuration",
    "onBeginRenderTick",
    "PlayerMoveC2SPacketAccessor",
    "clickSimulation",
    "switchDelay",
    "switchChance",
    "placeChance",
    "glowstoneDelay",
    "glowstoneChance",
    "explodeDelay",
    "explodeChance",
    "explodeSlot",
    "antiWeakness",
    "damageTick",
    "breakChance",
    "breakDelay",
    "stopOnCrystal",
    "processCrystal",
    "swapToWeapon",
    "isObsidianOrBedrock",
    "isValidCrystalPosition",
    "processAnchorPvP",
    "isValidAnchorPosition",
    "AutoCrystal",
    "autocrystal",
    "AutoHitCrystal",
    "autohitcrystal",
    "dontPlaceCrystal",
    "dontBreakCrystal",
    "autoCrystalPlaceClock",
    "AutoAnchor",
    "autoanchor",
    "auto anchor",
    "DoubleAnchor",
    "safeanchor",
    "anchortweaks",
    "AutoTotem",
    "InventoryTotem",
    "inventorytotem",
    "HoverTotem",
    "hover totem",
    "legittotem",
    "AutoPot",
    "autopot",
    "auto pot",
    "speedPotSlot",
    "strengthPotSlot",
    "AutoArmor",
    "autoarmor",
    "auto armor",
    "preventSwordBlockBreaking",
    "preventSwordBlockAttack",
    "AutoDoubleHand",
    "autodoublehand",
    "auto double hand",
    "AutoClicker",
    "AimAssist",
    "aim assist",
    "trigger bot",
    "shieldbreaker",
    "shield breaker",
    "axespam",
    "axe spam",
    "FakeLag",
    "ping spoof",
    "FakeInv",
    "pushOutOfBlocks",
    "onPushOutOfBlocks",
    "webmacro",
    "web macro",
    "JumpReset",
    "setBlockBreakingCooldown",
    "setItemUseCooldown",
    "onBlockBreaking",
    "invokeDoAttack",
    "invokeDoItemUse",
    "setSelectedSlot",
    "getSelectedSlot",
    "blockBreakingCooldown",
    "invokeOnMouseButton",
    "getVisualAttackCooldownProgressPerTick",
    "endcrystalitemmixin",
    "WalksyCrystalOptimizerMod",
    "arrayOfString",
    "dqrkis",
    "StringObfuscator",
    "onShouldRenderBlockOutline",
    "predictCrystals",
    "noOffhandTotem",
    "getNearByCrystals",
    "slotExplode",
    "needToPlaceRails",
    "findTotemSlot",
    "activateOnRightClick",
    "crystalPlaceClock",
    "CrystalTwiceClock",
    "mainHandStack",
    "attackInAir",
    "attackOnJump",
    "onDestruct",
    "getGlowstoneChance",
    "isAutoCharge",
    "getPlaceChance",
    "getSwitchDelay",
    "getGlowstoneDelay",
    "getExplodeDelay",
    "getExplodeSlotIndex",
    "getPlaceDelayTicks",
    "getBreakDelayTicks",
    "getBreakChance",
    "isSpawnersEnabled",
    "isShulkersEnabled",
    "onModuleDisabled",
    "switchToBestTool",
    "switchToBestWeapon",
    "isLootProtect",
    "getMinHunger",
    "isTracersEnabled",
    "getSelectedBlocks",
    "isChestsEnabled",
    "inventoryToMenuSlot",
    "throwPearl",
    "isLeftHoldOnly",
    "Automatically switches to sword when hitting with totem",
    "Failed to switch to mace after axe!",
    "TrilliumSolutions",
    "self destruct",
    "tr1gg3rb0t",
    "trigg3rb0t",
    "D0uble4nch0r",
    "D0ubl34nch0r",
    "4nch0rM4cr0",
    "Anch0rMacr0",
    "Anc0rM4cr0",
    "тriggerbot",
    "tr​iggerbot",
    "кillaura",
    "ki​llaura",
    "ѕelfdеstruct",
    "ѕtrafe",
    "str​afe",
    "аimаssist",
    "аіmаѕѕіѕт",
    "aim​assist",
    "jumрreset",
    "jum​preset",
    "fаkelag",
    "fа​kelag",
    "аutoclick",
    "аutосlick",
    "аu​toclick",
    "hotbаrswap",
    "swіtchDеlаy",
    "ѕаfe аnсhor",
    "аutо сrуstаl",
    "аnсhоr mасrо",
    "аuto totem",
    "аutototem",
    "аutоtоtеm",
    "РlаyerМоvеС2SРаcketАcсessоr",
    "сlickЅimulаtion",
    "click​Simulation",
    "аntiWeаkness",
    "аntіWеаknеss",
    "АutоСrуstаl",
    "Аuto​Crystal",
    "аutосrуstаl",
    "аu​tocrystal",
    "АutoАnсhоr",
    "АutoТotem",
    "АutоАrmоr",
    "АimАssist",
    "АіmАssіst",
    "аіmаssіst",
    "pedroisgay",
    "krloader",
    "Aut0Cryst3l",
    "Aut0H1tCryst3l",
    "K3yAHC",
    "S4fe4nch0r",
    "Aut0H1tCyst4l",
    "Pr3Ch3ck",
    "4ctiv4tK3y",
    "d4m4geT1ck",
    "sw1tchD3lay",
    "ch4rg3D3l4y",
    "expl0d3D3l4y",
    "t0t3mSl0t",
    "simulateClicks",
    "P34rl",
};

const std::vector<std::string> kFullwidthObfuscatedCheats = {
    "ＡｕｔｏＣｒｙｓｔａｌ",
    "Ａｕｔｏ Ｃｒｙｓｔａｌ",
    "ＡｕｔｏＨｉｔＣｒｙｓｔａｌ",
    "Ａ．ｕｔｏ Ｃｒｙｓｔａｌ",
    "Ａ．ｕｔｏＣｒｙｓｔａｌＬＶ２",
    "Ａ．ｕｔｏ Ｈｉｔ Ｃｒｙｓｔａｌ",
    "ＡｕｔｏＡｎｃｈｏｒ",
    "Ａｕｔｏ Ａｎｃｈｏｒ",
    "ＤｏｕｂｌｅＡｎｃｈｏｒ",
    "Ｄｏｕｂｌｅ Ａｎｃｈｏｒ",
    "ＳａｆｅＡｎｃｈｏｒ",
    "Ｓａｆｅ Ａｎｃｈｏｒ",
    "Ａｎｃｈｏｒ Ｍａｃｒｏ",
    "Ａ．ｎｃｈｏｒ Ｍａｃｒｏ",
    "Ａ．ｎｃｈｏｒ Ｍａｃｒｏ Ｖ２",
    "Ｄ．ｏｕｂｌｅ Ａｎｃｈｏｒ",
    "Ｓ．ａｆｅＡｎｃｈｏｒ",
    "ＡｕｔｏＴｏｔｅｍ",
    "Ａｕｔｏ Ｔｏｔｅｍ",
    "Ａｕｔｏ Ｔｏｔｅｍ Ｈｉｔ",
    "Ａ．ｕｔｏ Ｔｏｔｅｍ Ｈｉｔ",
    "ＨｏｖｅｒＴｏｔｅｍ",
    "Ｈｏｖｅｒ Ｔｏｔｅｍ",
    "ＩｎｖｅｎｔｏｒｙＴｏｔｅｍ",
    "Ｈ．ｏｖｅｒ Ｔｏｔｅｍ",
    "Ａ．ｕｔｏ Ｉｎｖｅｎｔｏｒｙ Ｔｏｔｅｍ",
    "Ｆ．ｏｒｃｅ Ｔｏｔｅｍ",
    "Ｔ．ｏｔｅｍ Ｆｉｒｓｔ",
    "Ｔ．ｏｔｅｍ Ｏｆｆｈａｎｄ",
    "Ｔ．ｏｔｅｍ Ｓｌｏｔ",
    "Ｈ．ｏｖｅｒ",
    "Ｗ．ｏｒｋ Ｗｉｔｈ Ｔｏｔｅｍ",
    "ＡｕｔｏＤｏｕｂｌｅＨａｎｄ",
    "Ａｕｔｏ Ｄｏｕｂｌｅ Ｈａｎｄ",
    "Ａ．ｕｔｏ Ｄｏｕｂｌｅ Ｈａｎｄ",
    "Ａ．ｃｔｉｖａｔｅ Ｋｅｙ",
    "Ｗ．ｈｉｌｅ Ｕｓｅ",
    "Ｓ．ｔｏｐ ｏｎ Ｋｉｌｌ",
    "Ｃ．ｌｉｃｋ Ｓｉｍｕｌａｔｉｏｎ",
    "Ｓ．ｗｉｔｃｈ Ｄｅｌａｙ",
    "Ｓ．ｗｔｃｈ Ｃｈａｎｃｅ",
    "Ｐ．ｌａｃｅ Ｃｈａｎｃｅ",
    "Ｇ．ｌｏｗｓｔｏｎｅ Ｄｅｌａｙ",
    "Ｇ．ｌｏｗｓｔｏｎｅ Ｃｈａｎｃｅ",
    "Ｅ．ｘｐｌｏｄｅ Ｄｅｌａｙ",
    "Ｅ．ｘｐｌｏｄｅ Ｃｈａｎｃｅ",
    "Ｅ．ｘｐｌｏｄｅ Ｓｌｏｔ",
    "Ｏ．ｎｌｙ Ｏｗｎ",
    "Ｏ．ｎｌｙ Ｃｈａｒｇｅ",
    "Ｒ．ａｎｄｏｍ Ｇｌｏｗｓｔｏｎｅ",
    "ｔｒｉｇｇｅｒｂｏｔ",
    "ｋｉｌｌａｕｒａ",
    "ｓｅｌｆｄｅｓｔｒｕｃｔ",
    "ｓｔｒａｆｅ",
    "ａｉｍａｓｓｉｓｔ",
    "ｊｕｍｐｒｅｓｅｔ",
    "ｆａｋｅｌａｇ",
    "ｈｏｔｂａｒｓｗａｐ",
    "ｓｗｉｔｃｈＤｅｌａｙ",
    "ｓａｆｅ ａｎｃｈｏｒ",
    "ａｕｔｏ ｃｒｙｓｔａｌ",
    "ａｎｃｈｏｒ ｍａｃｒｏ",
    "ａｕｔｏ ｔｏｔｅｍ",
    "ａｕｔｏｔｏｔｅｍ",
    "ａｕｔｏｃｒｙｓｔａｌ",
    "ａｕｔｏａｎｃｈｏｒ",
    "ａｕｔｏａｒｍｏｒ",
    "ａｉｍ ａｓｓｉｓｔ",
    "ｔｒｉｇｇｅｒ·ｂｏｔ",
    "ｔｒｉｇｇｅｒ‧ｂｏｔ",
    "ｔｒｉｇｇｅｒ∙ｂｏｔ",
    "ｔｒｉｇｇｅｒ•ｂｏｔ",
    "ｔｒｉｇｇｅｒ⋅ｂｏｔ",
    "ｋｉｌｌ·ａｕｒａ",
    "ｋｉｌｌ‧ａｕｒａ",
    "ｋｉｌｌ∙ａｕｒａ",
    "ｋｉｌｌ•ａｕｒａ",
    "ｋｉｌｌ⋅ａｕｒａ",
    "ｓｅｌｆ·ｄｅｓｔｒｕｃｔ",
    "ｓｅｌｆ‧ｄｅｓｔｒｕｃｔ",
    "ｓｅｌｆ∙ｄｅｓｔｒｕｃｔ",
    "ｓｅｌｆ•ｄｅｓｔｒｕｃｔ",
    "ｓｅｌｆ⋅ｄｅｓｔｒｕｃｔ",
    "ａｉｍ·ａｓｓｉｓｔ",
    "ａｉｍ‧ａｓｓｉｓｔ",
    "ａｉｍ∙ａｓｓｉｓｔ",
    "ａｉｍ•ａｓｓｉｓｔ",
    "ａｉｍ⋅ａｓｓｉｓｔ",
    "ｐｌａｙｅｒ·ｒｅａｃｈ",
    "ｐｌａｙｅｒ‧ｒｅａｃｈ",
    "ｐｌａｙｅｒ∙ｒｅａｃｈ",
    "ｐｌａｙｅｒ•ｒｅａｃｈ",
    "ｐｌａｙｅｒ⋅ｒｅａｃｈ",
    "ｊｕｍｐ·ｒｅｓｅｔ",
    "ｊｕｍｐ‧ｒｅｓｅｔ",
    "ｊｕｍｐ∙ｒｅｓｅｔ",
    "ｊｕｍｐ•ｒｅｓｅｔ",
    "ｊｕｍｐ⋅ｒｅｓｅｔ",
    "ｆａｋｅ·ｌａｇ",
    "ｆａｋｅ‧ｌａｇ",
    "ｆａｋｅ∙ｌａｇ",
    "ｆａｋｅ•ｌａｇ",
    "ｆａｋｅ⋅ｌａｇ",
    "ａｕｔｏ·ｃｌｉｃｋ",
    "ａｕｔｏ‧ｃｌｉｃｋ",
    "ａｕｔｏ∙ｃｌｉｃｋ",
    "ａｕｔｏ•ｃｌｉｃｋ",
    "ａｕｔｏ⋅ｃｌｉｃｋ",
    "ｈｏｔ·ｂａｒ·ｓｗａｐ",
    "ｈｏｔ‧ｂａｒ‧ｓｗａｐ",
    "ｈｏｔ∙ｂａｒ∙ｓｗａｐ",
    "ｈｏｔ•ｂａｒ•ｓｗａｐ",
    "ｈｏｔ⋅ｂａｒ⋅ｓｗａｐ",
    "ｓｗｉｔｃｈ·ｄｅｌａｙ",
    "ｓｗｉｔｃｈ‧ｄｅｌａｙ",
    "ｓｗｉｔｃｈ∙ｄｅｌａｙ",
    "ｓｗｉｔｃｈ•ｄｅｌａｙ",
    "ｓｗｉｔｃｈ⋅ｄｅｌａｙ",
    "ｓｗｉｔｃｈ·ｄｅｌａｙ·ｍｓ",
    "ｓｗｉｔｃｈ‧ｄｅｌａｙ‧ｍｓ",
    "ｓｗｉｔｃｈ∙ｄｅｌａｙ∙ｍｓ",
    "ｓｗｉｔｃｈ•ｄｅｌａｙ•ｍｓ",
    "ｓｗｉｔｃｈ⋅ｄｅｌａｙ⋅ｍｓ",
    "ｓｗａｐ·ｂａｃｋ·ｔｏ·ｏｒｉｇｉｎａｌ·ｓｌｏｔ",
    "ｓｗａｐ‧ｂａｃｋ‧ｔｏ‧ｏｒｉｇｉｎａｌ‧ｓｌｏｔ",
    "ａｔｔａｃｋ·ｒｅｇｉｓｔｅｒｅｄ·ｔｈｉｓ·ｃｌｉｃｋ",
    "ａｔｔａｃｋ‧ｒｅｇｉｓｔｅｒｅｄ‧ｔｈｉｓ‧ｃｌｉｃｋ",
    "ｆｉｎｄ·ｋｎｏｃｋｂａｃｋ·ｓｗｏｒｄ",
    "ｆｉｎｄ‧ｋｎｏｃｋｂａｃｋ‧ｓｗｏｒｄ",
    "ｌｖｓｔｒｎｇ",
    "ｓａｆｅ·ａｎｃｈｏｒ",
    "ｓａｆｅ‧ａｎｃｈｏｒ",
    "ｓａｆｅ∙ａｎｃｈｏｒ",
    "ｓａｆｅ•ａｎｃｈｏｒ",
    "ｓａｆｅ⋅ａｎｃｈｏｒ",
    "ａｕｔｏ·ｃｒｙｓｔａｌ",
    "ａｕｔｏ‧ｃｒｙｓｔａｌ",
    "ａｕｔｏ∙ｃｒｙｓｔａｌ",
    "ａｕｔｏ•ｃｒｙｓｔａｌ",
    "ａｕｔｏ⋅ｃｒｙｓｔａｌ",
    "ａｎｃｈｏｒ·ｍａｃｒｏ",
    "ａｎｃｈｏｒ‧ｍａｃｒｏ",
    "ａｎｃｈｏｒ∙ｍａｃｒｏ",
    "ａｎｃｈｏｒ•ｍａｃｒｏ",
    "ａｎｃｈｏｒ⋅ｍａｃｒｏ",
    "ａｕｔｏ·ｔｏｔｅｍ",
    "ａｕｔｏ‧ｔｏｔｅｍ",
    "ａｕｔｏ∙ｔｏｔｅｍ",
    "ａｕｔｏ•ｔｏｔｅｍ",
    "ａｕｔｏ⋅ｔｏｔｅｍ",
    "ａｕｔｏ·ｈｉｔ·ｃｒｙｓｔａｌ",
    "ａｕｔｏ‧ｈｉｔ‧ｃｒｙｓｔａｌ",
    "ａｕｔｏ·ｉｎｖｅｎｔｏｒｙ·ｔｏｔｅｍ",
    "ａｕｔｏ‧ｉｎｖｅｎｔｏｒｙ‧ｔｏｔｅｍ",
    "ｅｎｄ·ｃｒｙｓｔａｌ·ｉｔｅｍ·ｍｉｘｉｎ",
    "ｅｎｄ‧ｃｒｙｓｔａｌ‧ｉｔｅｍ‧ｍｉｘｉｎ",
    "ｉｓ·ｄｅａｄ·ｂｏｄｙ·ｎｅａｒｂｙ",
    "ｉｓ‧ｄｅａｄ‧ｂｏｄｙ‧ｎｅａｒｂｙ",
    "ｈｏｏｋ·ｃａｎｃｅｌ·ｂｌｏｃｋ·ｂｒｅａｋｉｎｇ",
    "ｈｏｏｋ‧ｃａｎｃｅｌ‧ｂｌｏｃｋ‧ｂｒｅａｋｉｎｇ",
    "ｃａｎ·ｐｌａｃｅ·ｃｒｙｓｔａｌ·ｓｅｒｖｅｒ",
    "ｃａｎ‧ｐｌａｃｅ‧ｃｒｙｓｔａｌ‧ｓｅｒｖｅｒ",
    "ｏｎ·ｓｗａｐ·ｌａｓｔ·ａｔｔａｃｋｅｄ·ｔｉｃｋｓ·ｒｅｓｅｔ",
    "ｏｎ‧ｓｗａｐ‧ｌａｓｔ‧ａｔｔａｃｋｅｄ‧ｔｉｃｋｓ‧ｒｅｓｅｔ",
    "ｒｅｄｉｒｅｃｔ·ｓｅｌｅｃｔｅｄ·ｓｌｏｔ",
    "ｒｅｄｉｒｅｃｔ‧ｓｅｌｅｃｔｅｄ‧ｓｌｏｔ",
    "ｇｅｔ·ｈａｎｄ·ｓｗｉｎｇ·ｄｕｒａｔｉｏｎ",
    "ｇｅｔ‧ｈａｎｄ‧ｓｗｉｎｇ‧ｄｕｒａｔｉｏｎ",
    "ｏｎ·ｂｅｇｉｎ·ｒｅｎｄｅｒ·ｔｉｃｋ",
    "ｏｎ‧ｂｅｇｉｎ‧ｒｅｎｄｅｒ‧ｔｉｃｋ",
    "ｐｌａｙｅｒ·ｍｏｖｅ·ｃ２ｓ·ｐａｃｋｅｔ·ａｃｃｅｓｓｏｒ",
    "ｐｌａｙｅｒ‧ｍｏｖｅ‧ｃ２ｓ‧ｐａｃｋｅｔ‧ａｃｃｅｓｓｏｒ",
    "ｃｌｉｃｋ·ｓｉｍｕｌａｔｉｏｎ",
    "ｃｌｉｃｋ‧ｓｉｍｕｌａｔｉｏｎ",
    "ｓｗｉｔｃｈ·ｃｈａｎｃｅ",
    "ｓｗｉｔｃｈ‧ｃｈａｎｃｅ",
    "ｐｌａｃｅ·ｃｈａｎｃｅ",
    "ｐｌａｃｅ‧ｃｈａｎｃｅ",
    "ｇｌｏｗ·ｓｔｏｎｅ·ｄｅｌａｙ",
    "ｇｌｏｗ‧ｓｔｏｎｅ‧ｄｅｌａｙ",
    "ｇｌｏｗ·ｓｔｏｎｅ·ｃｈａｎｃｅ",
    "ｇｌｏｗ‧ｓｔｏｎｅ‧ｃｈａｎｃｅ",
    "ｅｘｐｌｏｄｅ·ｄｅｌａｙ",
    "ｅｘｐｌｏｄｅ‧ｄｅｌａｙ",
    "ｅｘｐｌｏｄｅ·ｃｈａｎｃｅ",
    "ｅｘｐｌｏｄｅ‧ｃｈａｎｃｅ",
    "ｅｘｐｌｏｄｅ·ｓｌｏｔ",
    "ｅｘｐｌｏｄｅ‧ｓｌｏｔ",
    "ａｎｔｉ·ｗｅａｋｎｅｓｓ",
    "ａｎｔｉ‧ｗｅａｋｎｅｓｓ",
    "ｄａｍａｇｅ·ｔｉｃｋ",
    "ｄａｍａｇｅ‧ｔｉｃｋ",
    "ｂｒｅａｋ·ｃｈａｎｃｅ",
    "ｂｒｅａｋ‧ｃｈａｎｃｅ",
    "ｂｒｅａｋ·ｄｅｌａｙ",
    "ｂｒｅａｋ‧ｄｅｌａｙ",
    "ｓｔｏｐ·ｏｎ·ｃｒｙｓｔａｌ",
    "ｓｔｏｐ‧ｏｎ‧ｃｒｙｓｔａｌ",
    "ｐｒｏｃｅｓｓ·ｃｒｙｓｔａｌ",
    "ｐｒｏｃｅｓｓ‧ｃｒｙｓｔａｌ",
    "ｓｗａｐ·ｔｏ·ｗｅａｐｏｎ",
    "ｓｗａｐ‧ｔｏ‧ｗｅａｐｏｎ",
    "ｉｓ·ｏｂｓｉｄｉａｎ·ｏｒ·ｂｅｄｒｏｃｋ",
    "ｉｓ‧ｏｂｓｉｄｉａｎ‧ｏｒ‧ｂｅｄｒｏｃｋ",
    "ｉｓ·ｖａｌｉｄ·ｃｒｙｓｔａｌ·ｐｏｓｉｔｉｏｎ",
    "ｉｓ‧ｖａｌｉｄ‧ｃｒｙｓｔａｌ‧ｐｏｓｉｔｉｏｎ",
    "ｐｒｏｃｅｓｓ·ａｎｃｈｏｒ·ｐｖｐ",
    "ｐｒｏｃｅｓｓ‧ａｎｃｈｏｒ‧ｐｖｐ",
    "ｉｓ·ｖａｌｉｄ·ａｎｃｈｏｒ·ｐｏｓｉｔｉｏｎ",
    "ｉｓ‧ｖａｌｉｄ‧ａｎｃｈｏｒ‧ｐｏｓｉｔｉｏｎ",
    "ｄｏｎｔ·ｐｌａｃｅ·ｃｒｙｓｔａｌ",
    "ｄｏｎｔ‧ｐｌａｃｅ‧ｃｒｙｓｔａｌ",
    "ｄｏｎｔ·ｂｒｅａｋ·ｃｒｙｓｔａｌ",
    "ｄｏｎｔ‧ｂｒｅａｋ‧ｃｒｙｓｔａｌ",
    "ａｕｔｏ·ｃｒｙｓｔａｌ·ｐｌａｃｅ·ｃｌｏｃｋ",
    "ａｕｔｏ‧ｃｒｙｓｔａｌ‧ｐｌａｃｅ‧ｃｌｏｃｋ",
    "ａｕｔｏ·ａｎｃｈｏｒ",
    "ａｕｔｏ‧ａｎｃｈｏｒ",
    "ｄｏｕｂｌｅ·ａｎｃｈｏｒ",
    "ｄｏｕｂｌｅ‧ａｎｃｈｏｒ",
    "ａｎｃｈｏｒ·ｔｗｅａｋｓ",
    "ａｎｃｈｏｒ‧ｔｗｅａｋｓ",
    "ｉｎｖｅｎｔｏｒｙ·ｔｏｔｅｍ",
    "ｉｎｖｅｎｔｏｒｙ‧ｔｏｔｅｍ",
    "ｈｏｖｅｒ·ｔｏｔｅｍ",
    "ｈｏｖｅｒ‧ｔｏｔｅｍ",
    "ｌｅｇｉｔ·ｔｏｔｅｍ",
    "ｌｅｇｉｔ‧ｔｏｔｅｍ",
    "ａｕｔｏ·ｐｏｔ",
    "ａｕｔｏ‧ｐｏｔ",
    "ｓｐｅｅｄ·ｐｏｔ·ｓｌｏｔ",
    "ｓｐｅｅｄ‧ｐｏｔ‧ｓｌｏｔ",
    "ｓｔｒｅｎｇｔｈ·ｐｏｔ·ｓｌｏｔ",
    "ｓｔｒｅｎｇｔｈ‧ｐｏｔ‧ｓｌｏｔ",
    "ａｕｔｏ·ａｒｍｏｒ",
    "ａｕｔｏ‧ａｒｍｏｒ",
    "ｐｒｅｖｅｎｔ·ｓｗｏｒｄ·ｂｌｏｃｋ·ｂｒｅａｋｉｎｇ",
    "ｐｒｅｖｅｎｔ‧ｓｗｏｒｄ‧ｂｌｏｃｋ‧ｂｒｅａｋｉｎｇ",
    "ｐｒｅｖｅｎｔ·ｓｗｏｒｄ·ｂｌｏｃｋ·ａｔｔａｃｋ",
    "ｐｒｅｖｅｎｔ‧ｓｗｏｒｄ‧ｂｌｏｃｋ‧ａｔｔａｃｋ",
    "ａｕｔｏ·ｄｏｕｂｌｅ·ｈａｎｄ",
    "ａｕｔｏ‧ｄｏｕｂｌｅ‧ｈａｎｄ",
    "ａｕｔｏ·ｃｌｉｃｋｅｒ",
    "ａｕｔｏ‧ｃｌｉｃｋｅｒ",
};

const std::vector<std::string> kJVMInjectionDetections = {
    // Strings of JVMInjections go here // Example: "-XX:+EnableDynamicAgentLoading"
};

const std::vector<std::string> kDNSCacheDetections = {
    "www.koid.es",
    "Exodus.codes",
    "lithiumclient.wtf",
    "doomsdayclient.com",
};

// SysMain, DPS, EventLog, Bam and DcomLaunch are checked (with the more
// precise "Disabled" start-type signal) by ScanForBypassMethods() instead,
// alongside the other anti-forensic bypass checks.
const std::vector<std::string> kWindowsServiceChecks = {
    "PcaSvc", "Schedule",
    "Dusmsvc", "Appinfo", "CDPSvc", "PlugPlay", "wsearch"
};

const std::vector<std::string> kSystemTamperingDetections = {
    "ScriptBlockLogging", "EnableScriptBlockLogging", "ModuleLogging",
    "EnableModuleLogging", "EnableTranscripting", "Transcription",
    "wevtutil", "Clear-EventLog",
    "AppCompatCache", "ShimCache",
    "ExclusionPath",
    "JumpList", "AutomaticDestinations",
    "Start Menu\\Programs\\Startup"
};

const std::vector<std::string> kNormalScanStrings = [] {
    std::vector<std::string> all = kRedDetections;
    all.insert(all.end(), kYellowDetections.begin(), kYellowDetections.end());
    return all;
}();

const std::vector<std::string> kDeepScanStrings = [] {
    std::vector<std::string> all = kRedDetections;
    all.insert(all.end(), kYellowDetections.begin(), kYellowDetections.end());
    return all;
}();

struct ClientSignatureGroup {
    const char* label;
    std::vector<std::string> signatures;
};

const std::vector<ClientSignatureGroup> kClientSignatureGroups = {
    // like this { "Argon Client", { "dev/lvstrng/argon/", "another-string-if-needed-for-better-detection" }},
    // same goes for ofuscators
};

const std::unordered_set<std::string> kYellowLookup = [] {
    std::unordered_set<std::string> out;
    for (const auto& s : kYellowDetections) {
        out.insert(s);
    }
    return out;
}();

bool IsReadableProtection(DWORD protect) {
    constexpr DWORD mask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (protect & PAGE_GUARD) {
        return false;
    }
    return (protect & mask) != 0;
}

bool IsObfuscationSignature(const std::string& low) {
    return low.find("obfuscator") != std::string::npos ||
        low.find("mixin") != std::string::npos ||
        low.find("json") != std::string::npos;
}

struct CompiledSignature {
    std::string original;
    std::string lowered;
    Severity severity;
    char first{0};
};


const std::vector<std::string>& NormalScanStrings() { return kNormalScanStrings; }
const std::vector<std::string>& DeepScanStrings() { return kDeepScanStrings; }

MemoryScanner::MemoryScanner() = default;

MemoryScanner::~MemoryScanner() {
    Cancel();
    if (m_worker.joinable()) {
        m_worker.join();
    }
}

void MemoryScanner::Start(uint32_t pid, const ScanOptions& options, std::string processStartTime) {
    Cancel();
    if (m_worker.joinable()) {
        m_worker.join();
    }

    m_cancel.store(false);
    m_running.store(true);
    m_progress.store(0.0f);
    m_lastError.clear();
    m_summary = {};
    m_summary.pid = pid;
    m_summary.processStartTime = std::move(processStartTime);
    m_summary.scanType = "Full";
    m_summary.generatedBy = options.generatedBy;

    m_worker = std::thread(&MemoryScanner::Worker, this, pid, options, m_summary.processStartTime);
}

void MemoryScanner::Cancel() {
    m_cancel.store(true);
}

bool MemoryScanner::IsRunning() const {
    return m_running.load();
}

float MemoryScanner::Progress() const {
    return m_progress.load();
}

const ScanSummary& MemoryScanner::Summary() const {
    return m_summary;
}

std::string MemoryScanner::LastError() const {
    return m_lastError;
}

void MemoryScanner::RegisterDetection(ScanSummary& summary, std::string key, Severity severity, uintptr_t address, uintptr_t baseAddress) {
    for (auto& d : summary.detections) {
        if (d.message == key) {
            d.hits += 1;
            d.hitAddresses.push_back(address);
            if (d.baseAddress == 0) {
                d.baseAddress = baseAddress;
            }
            return;
        }
    }

    Detection d{};
    d.timestamp = NowTimestamp();
    d.message = std::move(key);
    d.severity = severity;
    d.address = address;
    d.baseAddress = baseAddress;
    d.hitAddresses.push_back(address);
    d.hits = 1;
    summary.detections.push_back(std::move(d));
}

static std::string ReadRemoteUnicodeString(HANDLE process, PVOID ustrAddr) {
    struct RemoteUStr {
        USHORT Length;
        USHORT MaximumLength;
        PVOID Buffer;
    };
    RemoteUStr us{};
    SIZE_T br = 0;
    if (!ReadProcessMemory(process, ustrAddr, &us, sizeof(us), &br) || !us.Buffer || us.Length == 0)
        return {};
    std::wstring w(static_cast<size_t>(us.Length / sizeof(wchar_t)), L'\0');
    if (!ReadProcessMemory(process, us.Buffer, w.data(), us.Length, &br))
        return {};
    std::string out;
    out.reserve(w.size());
    for (wchar_t c : w) out += (c > 0 && c < 128) ? static_cast<char>(c) : '?';
    return out;
}

static std::string ReadJvmCommandLine(HANDLE process) {
    using NtQIP_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto NtQIP = reinterpret_cast<NtQIP_t>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQIP) return {};

    struct PBI {
        PVOID ExitStatus;
        PVOID PebBaseAddress;
        PVOID AffinityMask;
        PVOID BasePriority;
        PVOID UniqueProcessId;
        PVOID InheritedFromUniqueProcessId;
    };
    PBI pbi{};
    ULONG retLen = 0;
    if (NtQIP(process, 0, &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress)
        return {};

    PVOID procParams = nullptr;
    SIZE_T br = 0;
    if (!ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(pbi.PebBaseAddress) + 0x20,
            &procParams, sizeof(procParams), &br) || !procParams)
        return {};

    std::string result = ReadRemoteUnicodeString(process,
        reinterpret_cast<BYTE*>(procParams) + 0x70);

    PVOID envPtr = nullptr;
    if (ReadProcessMemory(process,
            reinterpret_cast<BYTE*>(procParams) + 0x80,
            &envPtr, sizeof(envPtr), &br) && envPtr) {

        SIZE_T envSize = 0;
        if (!ReadProcessMemory(process,
                reinterpret_cast<BYTE*>(procParams) + 0x3F0,
                &envSize, sizeof(envSize), &br) || envSize == 0 || envSize > 512 * 1024)
            envSize = 64 * 1024;

        std::vector<wchar_t> env(envSize / sizeof(wchar_t), L'\0');
        if (ReadProcessMemory(process, envPtr, env.data(), envSize, &br) && br > 0) {
            for (size_t i = 0; i < env.size(); ++i) {
                if (env[i] == L'\0') {
                } else {
                    result += (env[i] > 0 && env[i] < 128) ? static_cast<char>(env[i]) : '?';
                }
            }
        }
    }

    return result;
}

void MemoryScanner::Worker(uint32_t pid, ScanOptions options, std::string processStartTime) {
    (void)processStartTime;

    HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) {
        m_lastError = "Access denied or process not found.";
        m_running.store(false);
        return;
    }

    CpuInfo cpu = DetectCpuInfo();
    ScanConfig config = OptimizeScanConfig(cpu);

    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    uintptr_t address = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t endAddress = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    const auto& signatures = DeepScanStrings();

    std::vector<CompiledSignature> compiled;
    compiled.reserve(signatures.size() + kClientSignatureGroups.size() * 8 +
                     kJVMInjectionDetections.size() + kDNSCacheDetections.size() +
                     kSystemTamperingDetections.size());

    for (const auto& sig : signatures) {
        Severity sev = Severity::Detect;
        const std::string low = ToLower(sig);
        if (IsObfuscationSignature(low)) {
            sev = Severity::Suspicious;
        } else if (kYellowLookup.find(sig) != kYellowLookup.end()) {
            sev = Severity::Warning;
        } else if (low.find("mixin") != std::string::npos || low.find("json") != std::string::npos) {
            sev = Severity::Suspicious;
        } else if (low.find("injector") != std::string::npos) {
            sev = Severity::Warning;
        }
        if (low.empty()) {
            continue;
        }
        compiled.push_back({sig, low, sev, low[0]});
    }

    for (const auto& group : kClientSignatureGroups) {
        bool isObfuscationGroup = (std::string(group.label).find("Obfuscator") != std::string::npos);
        Severity groupSeverity = isObfuscationGroup ? Severity::Suspicious : Severity::Detect;
        for (const auto& sig : group.signatures) {
            const std::string low = ToLower(sig);
            if (!low.empty()) {
                compiled.push_back({group.label, low, groupSeverity, low[0]});
            }
        }
    }

    for (const auto& sig : kDNSCacheDetections) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (DNS Cache)", low, Severity::Detect, low[0]});
        }
    }

    for (const auto& sig : kSystemTamperingDetections) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (System Tampering)", low, Severity::Suspicious, low[0]});
        }
    }

    for (const auto& sig : kFullwidthObfuscatedCheats) {
        const std::string low = ToLower(sig);
        if (!low.empty()) {
            compiled.push_back({sig + " (Fullwidth Obfuscated)", low, Severity::Warning, low[0]});
        }
    }

    struct MemoryRegion {
        uintptr_t baseAddress;
        size_t size;
    };
    std::vector<MemoryRegion> regions;

    double totalBytes = 0.0;
    for (uintptr_t addr = address; addr < endAddress;) {
        MEMORY_BASIC_INFORMATION info{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &info, sizeof(info)) != sizeof(info)) {
            break;
        }
        if (info.State == MEM_COMMIT && IsReadableProtection(info.Protect) && info.Type == MEM_PRIVATE) {
            regions.push_back({reinterpret_cast<uintptr_t>(info.BaseAddress), info.RegionSize});
            totalBytes += static_cast<double>(info.RegionSize);
        }
        addr += info.RegionSize;
    }

    if (totalBytes <= 0.0 || regions.empty()) {
        m_summary = ScanSummary{pid, processStartTime, "full"};
        m_summary.generatedBy = options.generatedBy;
        m_progress.store(1.0f);
        m_running.store(false);
        CloseHandle(process);
        return;
    }

    std::vector<std::thread> threads;
    std::vector<ScanSummary> threadSummaries(config.threadCount, ScanSummary{pid, processStartTime, "full"});
    for (auto& summary : threadSummaries) {
        summary.generatedBy = options.generatedBy;
    }

    std::atomic<double> doneBytes{0.0};

    AhoCorasick ac;
    for (size_t i = 0; i < compiled.size(); i++)
        ac.AddPattern(compiled[i].lowered, static_cast<int>(i));
    ac.Build();

    std::atomic<size_t> nextRegion{0};

    auto scanRegion = [&](int threadId) {
        ScanSummary& localSummary = threadSummaries[threadId];

        std::vector<char> buffer(config.chunkSize);
        std::string lowerChunk;
        std::string normalizedChunk;
        lowerChunk.reserve(config.chunkSize);
        normalizedChunk.reserve(config.chunkSize);

        std::vector<bool> hitFlags(compiled.size(), false);

        size_t idx;
        while ((idx = nextRegion.fetch_add(1, std::memory_order_relaxed)) < regions.size()) {
            if (m_cancel.load()) break;

            const auto& region = regions[idx];
            uintptr_t regionAddr = region.baseAddress;
            size_t remaining = region.size;

            while (remaining > 0 && !m_cancel.load()) {
                size_t toRead = std::min(config.chunkSize, remaining);
                SIZE_T bytesRead = 0;

                if (ReadProcessMemory(process,
                    reinterpret_cast<LPCVOID>(regionAddr),
                    buffer.data(), toRead, &bytesRead) && bytesRead > 0) {

                    lowerChunk.resize(bytesRead);
                    for (SIZE_T i = 0; i < bytesRead; ++i)
                        lowerChunk[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(buffer[i])));

                    normalizedChunk = NormalizeFullwidthUnicode(lowerChunk);

                    std::fill(hitFlags.begin(), hitFlags.end(), false);

                    ac.Search(lowerChunk.data(), lowerChunk.size(), [&](int i) {
                        if (!hitFlags[i]) {
                            hitFlags[i] = true;
                            RegisterDetection(localSummary,
                                compiled[i].original + " Found",
                                compiled[i].severity,
                                regionAddr, region.baseAddress);
                        }
                    });

                    if (lowerChunk != normalizedChunk) {
                        ac.Search(normalizedChunk.data(), normalizedChunk.size(), [&](int i) {
                            if (!hitFlags[i]) {
                                hitFlags[i] = true;
                                RegisterDetection(localSummary,
                                    compiled[i].original + " Found",
                                    compiled[i].severity,
                                    regionAddr, region.baseAddress);
                            }
                        });
                    }

                    if (lowerChunk.find(".client.mixins.json") != std::string::npos &&
                        (lowerChunk.find("fabric-events-interaction-v0") != std::string::npos ||
                         lowerChunk.find("mixin") != std::string::npos)) {
                        RegisterDetection(localSummary, "Client mixin JSON file Found", Severity::Suspicious,
                            regionAddr, region.baseAddress);
                    }
                }

                regionAddr += toRead;
                remaining -= toRead;

                doneBytes.fetch_add(static_cast<double>(toRead), std::memory_order_relaxed);
                const double p = doneBytes.load(std::memory_order_relaxed) / totalBytes;
                m_progress.store(static_cast<float>(std::clamp(p, 0.0, 1.0)));
            }
        }
    };

    for (int t = 0; t < config.threadCount; ++t)
        threads.emplace_back(scanRegion, t);

    for (auto& thread : threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }

    ScanSummary finalSummary = threadSummaries[0];
    for (size_t i = 1; i < threadSummaries.size(); ++i) {
        finalSummary.detections.insert(
            finalSummary.detections.end(),
            threadSummaries[i].detections.begin(),
            threadSummaries[i].detections.end()
        );
    }

    for (const auto& d : finalSummary.detections) {
        if (d.severity == Severity::Detect) {
            finalSummary.detectCount += d.hits;
        } else if (d.severity == Severity::Warning) {
            finalSummary.warningCount += d.hits;
        } else {
            finalSummary.suspiciousCount += d.hits;
        }
    }

    {
        std::string cmdLine = ReadJvmCommandLine(process);
        if (!cmdLine.empty()) {
            std::string cmdLineLower = cmdLine;
            for (auto& c : cmdLineLower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            for (const auto& sig : kJVMInjectionDetections) {
                std::string sigLower = ToLower(sig);
                if (cmdLineLower.find(sigLower) != std::string::npos) {
                    RegisterDetection(finalSummary, sig, Severity::Warning, 0, 0);
                }
            }
        }
    }

    std::vector<std::string> serviceIssues = CheckWindowsServices();
    for (const auto& issue : serviceIssues) {
        RegisterDetection(finalSummary, issue + " (System Integrity)", Severity::Suspicious, 0, 0);
    }

    for (const auto& finding : ScanClasspath(pid)) {
        RegisterDetection(finalSummary, finding.reason + ": " + finding.path + " (Classpath)",
            Severity::Suspicious, 0, 0);
    }

    for (const auto& finding : ScanForBypassMethods()) {
        RegisterDetection(finalSummary, finding.name + ": " + finding.detail + " (Bypass Method)",
            Severity::Suspicious, 0, 0);
    }

    for (const auto& finding : ScanForErasedPEHeaders(pid)) {
        RegisterDetection(finalSummary, finding.moduleName + ": " + finding.detail + " (PE Header)",
            finding.severity, 0, 0);
    }

    m_summary = std::move(finalSummary);
    m_progress.store(1.0f);
    m_running.store(false);
    CloseHandle(process);
}

std::string MemoryScanner::NowTimestamp() {
    std::time_t t = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &t);
    std::ostringstream oss;
    oss << std::setfill('0')
        << std::setw(2) << local.tm_hour << ":"
        << std::setw(2) << local.tm_min << ":"
        << std::setw(2) << local.tm_sec;
    return oss.str();
}

std::string MemoryScanner::ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::vector<std::string> MemoryScanner::CheckWindowsServices() {
    std::vector<std::string> stoppedServices;

    SC_HANDLE scManager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scManager) {
        return stoppedServices;
    }

    for (const auto& serviceName : kWindowsServiceChecks) {
        SC_HANDLE service = OpenServiceA(scManager, serviceName.c_str(), SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS status;
            if (QueryServiceStatus(service, &status)) {
                if (status.dwCurrentState != SERVICE_RUNNING) {
                    stoppedServices.push_back(serviceName + " (Service Not Running)");
                }
            }
            CloseServiceHandle(service);
        } else {
            stoppedServices.push_back(serviceName + " (Service Not Found)");
        }
    }

    CloseServiceHandle(scManager);
    return stoppedServices;
}

} // namespace scanner