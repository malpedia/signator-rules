rule win_newposthings_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.newposthings."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.newposthings"
        malpedia_rule_date = "20230124"
        malpedia_hash = "2ee0eebba83dce3d019a90519f2f972c0fcf9686"
        malpedia_version = "20230125"
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
        $sequence_0 = { c20400 68f0110210 6a4c e8???????? 8bf0 }
            // n = 5, score = 100
            //   c20400               | ret                 4
            //   68f0110210           | push                0x100211f0
            //   6a4c                 | push                0x4c
            //   e8????????           |                     
            //   8bf0                 | mov                 esi, eax

        $sequence_1 = { c78528ffffff00000000 c68518ffffff00 c645fc10 837d9010 720e ffb57cffffff }
            // n = 6, score = 100
            //   c78528ffffff00000000     | mov    dword ptr [ebp - 0xd8], 0
            //   c68518ffffff00       | mov                 byte ptr [ebp - 0xe8], 0
            //   c645fc10             | mov                 byte ptr [ebp - 4], 0x10
            //   837d9010             | cmp                 dword ptr [ebp - 0x70], 0x10
            //   720e                 | jb                  0x10
            //   ffb57cffffff         | push                dword ptr [ebp - 0x84]

        $sequence_2 = { 8b7de4 c3 6a04 b8bb4d0110 e8???????? e8???????? 83b89400000000 }
            // n = 7, score = 100
            //   8b7de4               | mov                 edi, dword ptr [ebp - 0x1c]
            //   c3                   | ret                 
            //   6a04                 | push                4
            //   b8bb4d0110           | mov                 eax, 0x10014dbb
            //   e8????????           |                     
            //   e8????????           |                     
            //   83b89400000000       | cmp                 dword ptr [eax + 0x94], 0

        $sequence_3 = { 53 ff15???????? 85c0 750d 68e8030000 ffd7 46 }
            // n = 7, score = 100
            //   53                   | push                ebx
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   750d                 | jne                 0xf
            //   68e8030000           | push                0x3e8
            //   ffd7                 | call                edi
            //   46                   | inc                 esi

        $sequence_4 = { eb13 80c980 884c3704 8b049d481d0210 8064302480 837d0800 5f }
            // n = 7, score = 100
            //   eb13                 | jmp                 0x15
            //   80c980               | or                  cl, 0x80
            //   884c3704             | mov                 byte ptr [edi + esi + 4], cl
            //   8b049d481d0210       | mov                 eax, dword ptr [ebx*4 + 0x10021d48]
            //   8064302480           | and                 byte ptr [eax + esi + 0x24], 0x80
            //   837d0800             | cmp                 dword ptr [ebp + 8], 0
            //   5f                   | pop                 edi

        $sequence_5 = { 8886a0050210 46 ebe5 ff35???????? ff15???????? 85c0 7513 }
            // n = 7, score = 100
            //   8886a0050210         | mov                 byte ptr [esi + 0x100205a0], al
            //   46                   | inc                 esi
            //   ebe5                 | jmp                 0xffffffe7
            //   ff35????????         |                     
            //   ff15????????         |                     
            //   85c0                 | test                eax, eax
            //   7513                 | jne                 0x15

        $sequence_6 = { c645fc03 68e8c40110 8d9568ffffff 8d8de4feffff e8???????? 83c404 c645fc04 }
            // n = 7, score = 100
            //   c645fc03             | mov                 byte ptr [ebp - 4], 3
            //   68e8c40110           | push                0x1001c4e8
            //   8d9568ffffff         | lea                 edx, [ebp - 0x98]
            //   8d8de4feffff         | lea                 ecx, [ebp - 0x11c]
            //   e8????????           |                     
            //   83c404               | add                 esp, 4
            //   c645fc04             | mov                 byte ptr [ebp - 4], 4

        $sequence_7 = { ff24859f564000 33c0 838de8fbffffff 8bd8 8985a0fbffff }
            // n = 5, score = 100
            //   ff24859f564000       | jmp                 dword ptr [eax*4 + 0x40569f]
            //   33c0                 | xor                 eax, eax
            //   838de8fbffffff       | or                  dword ptr [ebp - 0x418], 0xffffffff
            //   8bd8                 | mov                 ebx, eax
            //   8985a0fbffff         | mov                 dword ptr [ebp - 0x460], eax

        $sequence_8 = { 83c404 c645fc07 8d4d08 51 8bd0 8d4dc0 }
            // n = 6, score = 100
            //   83c404               | add                 esp, 4
            //   c645fc07             | mov                 byte ptr [ebp - 4], 7
            //   8d4d08               | lea                 ecx, [ebp + 8]
            //   51                   | push                ecx
            //   8bd0                 | mov                 edx, eax
            //   8d4dc0               | lea                 ecx, [ebp - 0x40]

        $sequence_9 = { 50 8d8d40feffff e8???????? c745fc01000000 83bd50feffff00 752b 6a00 }
            // n = 7, score = 100
            //   50                   | push                eax
            //   8d8d40feffff         | lea                 ecx, [ebp - 0x1c0]
            //   e8????????           |                     
            //   c745fc01000000       | mov                 dword ptr [ebp - 4], 1
            //   83bd50feffff00       | cmp                 dword ptr [ebp - 0x1b0], 0
            //   752b                 | jne                 0x2d
            //   6a00                 | push                0

    condition:
        7 of them and filesize < 827392
}