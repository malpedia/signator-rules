rule win_fct_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-04-08"
        version = "1"
        description = "Describes win.fct."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fct"
        malpedia_rule_date = "20220405"
        malpedia_hash = "ecd38294bd47d5589be5cd5490dc8bb4804afc2a"
        malpedia_version = ""
        malpedia_license = "CC BY-SA 4.0"
        malpedia_sharing = "TLP:WHITE"

    /* DISCLAIMER
     * The strings used in this rule have been automatically selected from the
     * disassembly of memory dumps and unpacked files, using YARA-Signator.
     * The code and documentation is published here:
     * https://github.com/fxb-cocacoding/yara-signator
     * As Malpedia is used as data source, please note that for a given
     * number of families, only single samples are documented.
     * This likely impacts the degree of generalization these rules will offer.
     * Take the described generation method also into consideration when you
     * apply the rules in your use cases and assign them confidence levels.
     */


    strings:
        $sequence_0 = { 8bcf 83e03f c1f906 6bd038 8b45fc 03148d50614100 8b00 }
            // n = 7, score = 100
            //   8bcf                 | mov                 ecx, edi
            //   83e03f               | and                 eax, 0x3f
            //   c1f906               | sar                 ecx, 6
            //   6bd038               | imul                edx, eax, 0x38
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   03148d50614100       | add                 edx, dword ptr [ecx*4 + 0x416150]
            //   8b00                 | mov                 eax, dword ptr [eax]

        $sequence_1 = { 8b404c 83b8a800000000 750e 8b04bd50614100 807c302900 741d }
            // n = 6, score = 100
            //   8b404c               | mov                 eax, dword ptr [eax + 0x4c]
            //   83b8a800000000       | cmp                 dword ptr [eax + 0xa8], 0
            //   750e                 | jne                 0x10
            //   8b04bd50614100       | mov                 eax, dword ptr [edi*4 + 0x416150]
            //   807c302900           | cmp                 byte ptr [eax + esi + 0x29], 0
            //   741d                 | je                  0x1f

        $sequence_2 = { 83e801 0f85b1000000 8b4508 dd00 ebc2 c745e448324100 }
            // n = 6, score = 100
            //   83e801               | sub                 eax, 1
            //   0f85b1000000         | jne                 0xb7
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   dd00                 | fld                 qword ptr [eax]
            //   ebc2                 | jmp                 0xffffffc4
            //   c745e448324100       | mov                 dword ptr [ebp - 0x1c], 0x413248

        $sequence_3 = { 0f8595010000 c745e438324100 e9???????? 894de0 }
            // n = 4, score = 100
            //   0f8595010000         | jne                 0x19b
            //   c745e438324100       | mov                 dword ptr [ebp - 0x1c], 0x413238
            //   e9????????           |                     
            //   894de0               | mov                 dword ptr [ebp - 0x20], ecx

        $sequence_4 = { 8d040a 41 3b8d74fdffff 72f1 6a00 6a00 }
            // n = 6, score = 100
            //   8d040a               | lea                 eax, dword ptr [edx + ecx]
            //   41                   | inc                 ecx
            //   3b8d74fdffff         | cmp                 ecx, dword ptr [ebp - 0x28c]
            //   72f1                 | jb                  0xfffffff3
            //   6a00                 | push                0
            //   6a00                 | push                0

        $sequence_5 = { 8b048550614100 f644082801 7406 8b440818 }
            // n = 4, score = 100
            //   8b048550614100       | mov                 eax, dword ptr [eax*4 + 0x416150]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   7406                 | je                  8
            //   8b440818             | mov                 eax, dword ptr [eax + ecx + 0x18]

        $sequence_6 = { 33c0 8d5102 89851cfdffff 898530fdffff 8945cc }
            // n = 5, score = 100
            //   33c0                 | xor                 eax, eax
            //   8d5102               | lea                 edx, dword ptr [ecx + 2]
            //   89851cfdffff         | mov                 dword ptr [ebp - 0x2e4], eax
            //   898530fdffff         | mov                 dword ptr [ebp - 0x2d0], eax
            //   8945cc               | mov                 dword ptr [ebp - 0x34], eax

        $sequence_7 = { 6a04 e8???????? 83bd48fdffff08 8d8d34fdffff }
            // n = 4, score = 100
            //   6a04                 | push                4
            //   e8????????           |                     
            //   83bd48fdffff08       | cmp                 dword ptr [ebp - 0x2b8], 8
            //   8d8d34fdffff         | lea                 ecx, dword ptr [ebp - 0x2cc]

        $sequence_8 = { 83fe08 8d45bc 8d4a02 0f4345bc 894dcc c704505c002a00 }
            // n = 6, score = 100
            //   83fe08               | cmp                 esi, 8
            //   8d45bc               | lea                 eax, dword ptr [ebp - 0x44]
            //   8d4a02               | lea                 ecx, dword ptr [edx + 2]
            //   0f4345bc             | cmovae              eax, dword ptr [ebp - 0x44]
            //   894dcc               | mov                 dword ptr [ebp - 0x34], ecx
            //   c704505c002a00       | mov                 dword ptr [eax + edx*2], 0x2a005c

        $sequence_9 = { 6bc838 8b049550614100 f644082801 7422 8d4508 }
            // n = 5, score = 100
            //   6bc838               | imul                ecx, eax, 0x38
            //   8b049550614100       | mov                 eax, dword ptr [edx*4 + 0x416150]
            //   f644082801           | test                byte ptr [eax + ecx + 0x28], 1
            //   7422                 | je                  0x24
            //   8d4508               | lea                 eax, dword ptr [ebp + 8]

    condition:
        7 of them and filesize < 204800
}