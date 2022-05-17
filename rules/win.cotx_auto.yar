rule win_cotx_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.cotx."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cotx"
        malpedia_rule_date = "20220513"
        malpedia_hash = "7f4b2229e6ae614d86d74917f6d5b41890e62a26"
        malpedia_version = "20220516"
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
        $sequence_0 = { c705????????a856701f c705????????597e743c c705????????c1e1039f c705????????0a9769e0 c705????????c4b85363 }
            // n = 5, score = 500
            //   c705????????a856701f     |     
            //   c705????????597e743c     |     
            //   c705????????c1e1039f     |     
            //   c705????????0a9769e0     |     
            //   c705????????c4b85363     |     

        $sequence_1 = { e8???????? 83ec20 8d8d00fcffff e8???????? }
            // n = 4, score = 500
            //   e8????????           |                     
            //   83ec20               | sub                 esp, 0x20
            //   8d8d00fcffff         | lea                 ecx, [ebp - 0x400]
            //   e8????????           |                     

        $sequence_2 = { 8bd3 83e103 f3a4 8d8d98f6ffff e8???????? }
            // n = 5, score = 500
            //   8bd3                 | mov                 edx, ebx
            //   83e103               | and                 ecx, 3
            //   f3a4                 | rep movsb           byte ptr es:[edi], byte ptr [esi]
            //   8d8d98f6ffff         | lea                 ecx, [ebp - 0x968]
            //   e8????????           |                     

        $sequence_3 = { 68???????? 50 e8???????? 8d55a0 83c420 }
            // n = 5, score = 500
            //   68????????           |                     
            //   50                   | push                eax
            //   e8????????           |                     
            //   8d55a0               | lea                 edx, [ebp - 0x60]
            //   83c420               | add                 esp, 0x20

        $sequence_4 = { 50 0fb745e6 50 0fb745e2 50 8d45a0 68???????? }
            // n = 7, score = 500
            //   50                   | push                eax
            //   0fb745e6             | movzx               eax, word ptr [ebp - 0x1a]
            //   50                   | push                eax
            //   0fb745e2             | movzx               eax, word ptr [ebp - 0x1e]
            //   50                   | push                eax
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   68????????           |                     

        $sequence_5 = { 0f1145e4 50 0f2805???????? 8d85bcfbffff }
            // n = 4, score = 500
            //   0f1145e4             | movups              xmmword ptr [ebp - 0x1c], xmm0
            //   50                   | push                eax
            //   0f2805????????       |                     
            //   8d85bcfbffff         | lea                 eax, [ebp - 0x444]

        $sequence_6 = { 42 84c0 75f9 8dbd98faffff }
            // n = 4, score = 500
            //   42                   | inc                 edx
            //   84c0                 | test                al, al
            //   75f9                 | jne                 0xfffffffb
            //   8dbd98faffff         | lea                 edi, [ebp - 0x568]

        $sequence_7 = { 0f1185a8faffff e8???????? 83c40c 8d45a0 6a40 6a00 }
            // n = 6, score = 500
            //   0f1185a8faffff       | movups              xmmword ptr [ebp - 0x558], xmm0
            //   e8????????           |                     
            //   83c40c               | add                 esp, 0xc
            //   8d45a0               | lea                 eax, [ebp - 0x60]
            //   6a40                 | push                0x40
            //   6a00                 | push                0

        $sequence_8 = { 57 8bfa 8bf1 e8???????? 56 }
            // n = 5, score = 500
            //   57                   | push                edi
            //   8bfa                 | mov                 edi, edx
            //   8bf1                 | mov                 esi, ecx
            //   e8????????           |                     
            //   56                   | push                esi

        $sequence_9 = { c705????????d468bcb5 c705????????a1a14538 c705????????2086e659 c705????????eec45abf }
            // n = 4, score = 500
            //   c705????????d468bcb5     |     
            //   c705????????a1a14538     |     
            //   c705????????2086e659     |     
            //   c705????????eec45abf     |     

    condition:
        7 of them and filesize < 1171456
}