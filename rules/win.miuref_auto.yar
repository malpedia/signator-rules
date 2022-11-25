rule win_miuref_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-11-21"
        version = "1"
        description = "Detects win.miuref."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.miuref"
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
        $sequence_0 = { 46 2bd0 3bf2 72da 5e c3 8b4c2404 }
            // n = 7, score = 200
            //   46                   | inc                 esi
            //   2bd0                 | sub                 edx, eax
            //   3bf2                 | cmp                 esi, edx
            //   72da                 | jb                  0xffffffdc
            //   5e                   | pop                 esi
            //   c3                   | ret                 
            //   8b4c2404             | mov                 ecx, dword ptr [esp + 4]

        $sequence_1 = { a5 a5 6a40 8d4588 a5 50 8d45e8 }
            // n = 7, score = 200
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   6a40                 | push                0x40
            //   8d4588               | lea                 eax, [ebp - 0x78]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]
            //   50                   | push                eax
            //   8d45e8               | lea                 eax, [ebp - 0x18]

        $sequence_2 = { 8906 8b7518 85f6 7409 53 e8???????? 59 }
            // n = 7, score = 200
            //   8906                 | mov                 dword ptr [esi], eax
            //   8b7518               | mov                 esi, dword ptr [ebp + 0x18]
            //   85f6                 | test                esi, esi
            //   7409                 | je                  0xb
            //   53                   | push                ebx
            //   e8????????           |                     
            //   59                   | pop                 ecx

        $sequence_3 = { a3???????? 6a19 83ec10 8bfc 8d75f0 a5 }
            // n = 6, score = 200
            //   a3????????           |                     
            //   6a19                 | push                0x19
            //   83ec10               | sub                 esp, 0x10
            //   8bfc                 | mov                 edi, esp
            //   8d75f0               | lea                 esi, [ebp - 0x10]
            //   a5                   | movsd               dword ptr es:[edi], dword ptr [esi]

        $sequence_4 = { ff7508 56 57 56 ff75fc ff15???????? ff75fc }
            // n = 7, score = 200
            //   ff7508               | push                dword ptr [ebp + 8]
            //   56                   | push                esi
            //   57                   | push                edi
            //   56                   | push                esi
            //   ff75fc               | push                dword ptr [ebp - 4]
            //   ff15????????         |                     
            //   ff75fc               | push                dword ptr [ebp - 4]

        $sequence_5 = { 59 85f6 745b 8b16 8b4e04 2bca }
            // n = 6, score = 200
            //   59                   | pop                 ecx
            //   85f6                 | test                esi, esi
            //   745b                 | je                  0x5d
            //   8b16                 | mov                 edx, dword ptr [esi]
            //   8b4e04               | mov                 ecx, dword ptr [esi + 4]
            //   2bca                 | sub                 ecx, edx

        $sequence_6 = { 8b4608 8d0c88 8b39 c1e202 8b0402 8901 8b4608 }
            // n = 7, score = 200
            //   8b4608               | mov                 eax, dword ptr [esi + 8]
            //   8d0c88               | lea                 ecx, [eax + ecx*4]
            //   8b39                 | mov                 edi, dword ptr [ecx]
            //   c1e202               | shl                 edx, 2
            //   8b0402               | mov                 eax, dword ptr [edx + eax]
            //   8901                 | mov                 dword ptr [ecx], eax
            //   8b4608               | mov                 eax, dword ptr [esi + 8]

        $sequence_7 = { 3b3d???????? 7452 8b15???????? 3bfa 7448 3b3d???????? 7440 }
            // n = 7, score = 200
            //   3b3d????????         |                     
            //   7452                 | je                  0x54
            //   8b15????????         |                     
            //   3bfa                 | cmp                 edi, edx
            //   7448                 | je                  0x4a
            //   3b3d????????         |                     
            //   7440                 | je                  0x42

        $sequence_8 = { a1???????? c3 55 8bec 81ec80000000 6880000000 8d4580 }
            // n = 7, score = 200
            //   a1????????           |                     
            //   c3                   | ret                 
            //   55                   | push                ebp
            //   8bec                 | mov                 ebp, esp
            //   81ec80000000         | sub                 esp, 0x80
            //   6880000000           | push                0x80
            //   8d4580               | lea                 eax, [ebp - 0x80]

        $sequence_9 = { c705????????01000000 ff7610 57 ff15???????? 0fb74306 ff45fc }
            // n = 6, score = 200
            //   c705????????01000000     |     
            //   ff7610               | push                dword ptr [esi + 0x10]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   0fb74306             | movzx               eax, word ptr [ebx + 6]
            //   ff45fc               | inc                 dword ptr [ebp - 4]

    condition:
        7 of them and filesize < 180224
}