rule win_headertip_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.headertip."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.headertip"
        malpedia_rule_date = "20221118"
        malpedia_hash = "e0702e2e6d1d00da65c8a29a4ebacd0a4c59e1af"
        malpedia_version = "20221125"
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
        $sequence_0 = { ff35???????? 8945f8 ff15???????? e9???????? 55 8bec }
            // n = 6, score = 100
            //   ff35????????         |                     
            //   8945f8               | mov                 dword ptr [ebp - 8], eax
            //   ff15????????         |                     
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp

        $sequence_1 = { e9???????? 55 8bec 81ec8c000000 56 57 6a23 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec8c000000         | sub                 esp, 0x8c
            //   56                   | push                esi
            //   57                   | push                edi
            //   6a23                 | push                0x23

        $sequence_2 = { c6452f66 c645306f c6453157 885d32 c6459c49 c6459d6e }
            // n = 6, score = 100
            //   c6452f66             | mov                 byte ptr [ebp + 0x2f], 0x66
            //   c645306f             | mov                 byte ptr [ebp + 0x30], 0x6f
            //   c6453157             | mov                 byte ptr [ebp + 0x31], 0x57
            //   885d32               | mov                 byte ptr [ebp + 0x32], bl
            //   c6459c49             | mov                 byte ptr [ebp - 0x64], 0x49
            //   c6459d6e             | mov                 byte ptr [ebp - 0x63], 0x6e

        $sequence_3 = { 56 8d45e8 50 895df4 895df8 c645e849 }
            // n = 6, score = 100
            //   56                   | push                esi
            //   8d45e8               | lea                 eax, [ebp - 0x18]
            //   50                   | push                eax
            //   895df4               | mov                 dword ptr [ebp - 0xc], ebx
            //   895df8               | mov                 dword ptr [ebp - 8], ebx
            //   c645e849             | mov                 byte ptr [ebp - 0x18], 0x49

        $sequence_4 = { 56 33f6 39750c 7429 8b450c 2bc6 8945fc }
            // n = 7, score = 100
            //   56                   | push                esi
            //   33f6                 | xor                 esi, esi
            //   39750c               | cmp                 dword ptr [ebp + 0xc], esi
            //   7429                 | je                  0x2b
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   2bc6                 | sub                 eax, esi
            //   8945fc               | mov                 dword ptr [ebp - 4], eax

        $sequence_5 = { e9???????? 8b433c 8b441878 03c3 8b481c 8b5024 56 }
            // n = 7, score = 100
            //   e9????????           |                     
            //   8b433c               | mov                 eax, dword ptr [ebx + 0x3c]
            //   8b441878             | mov                 eax, dword ptr [eax + ebx + 0x78]
            //   03c3                 | add                 eax, ebx
            //   8b481c               | mov                 ecx, dword ptr [eax + 0x1c]
            //   8b5024               | mov                 edx, dword ptr [eax + 0x24]
            //   56                   | push                esi

        $sequence_6 = { 8b4508 8808 8b450c 8a4df1 8808 8b45f4 8b4d14 }
            // n = 7, score = 100
            //   8b4508               | mov                 eax, dword ptr [ebp + 8]
            //   8808                 | mov                 byte ptr [eax], cl
            //   8b450c               | mov                 eax, dword ptr [ebp + 0xc]
            //   8a4df1               | mov                 cl, byte ptr [ebp - 0xf]
            //   8808                 | mov                 byte ptr [eax], cl
            //   8b45f4               | mov                 eax, dword ptr [ebp - 0xc]
            //   8b4d14               | mov                 ecx, dword ptr [ebp + 0x14]

        $sequence_7 = { 7580 ff15???????? ff35???????? ff15???????? ff35???????? }
            // n = 5, score = 100
            //   7580                 | jne                 0xffffff82
            //   ff15????????         |                     
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   ff35????????         |                     

        $sequence_8 = { 8b45fc 0fb700 8b4df4 8b0481 03c3 8945f8 }
            // n = 6, score = 100
            //   8b45fc               | mov                 eax, dword ptr [ebp - 4]
            //   0fb700               | movzx               eax, word ptr [eax]
            //   8b4df4               | mov                 ecx, dword ptr [ebp - 0xc]
            //   8b0481               | mov                 eax, dword ptr [ecx + eax*4]
            //   03c3                 | add                 eax, ebx
            //   8945f8               | mov                 dword ptr [ebp - 8], eax

        $sequence_9 = { 8b0cb1 03cb 894df8 eb3e }
            // n = 4, score = 100
            //   8b0cb1               | mov                 ecx, dword ptr [ecx + esi*4]
            //   03cb                 | add                 ecx, ebx
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   eb3e                 | jmp                 0x40

    condition:
        7 of them and filesize < 174080
}