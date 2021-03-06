rule win_alma_communicator_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2022-05-16"
        version = "1"
        description = "Detects win.alma_communicator."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alma_communicator"
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
        $sequence_0 = { 66a1???????? 668907 894df8 8a02 }
            // n = 4, score = 100
            //   66a1????????         |                     
            //   668907               | mov                 word ptr [edi], ax
            //   894df8               | mov                 dword ptr [ebp - 8], ecx
            //   8a02                 | mov                 al, byte ptr [edx]

        $sequence_1 = { e8???????? 837ddc04 8bf0 59 0f85c8000000 }
            // n = 5, score = 100
            //   e8????????           |                     
            //   837ddc04             | cmp                 dword ptr [ebp - 0x24], 4
            //   8bf0                 | mov                 esi, eax
            //   59                   | pop                 ecx
            //   0f85c8000000         | jne                 0xce

        $sequence_2 = { 41 83f904 75f1 8b9d18ddffff 8d8520ddffff 8b8d08ddffff 8d0498 }
            // n = 7, score = 100
            //   41                   | inc                 ecx
            //   83f904               | cmp                 ecx, 4
            //   75f1                 | jne                 0xfffffff3
            //   8b9d18ddffff         | mov                 ebx, dword ptr [ebp - 0x22e8]
            //   8d8520ddffff         | lea                 eax, [ebp - 0x22e0]
            //   8b8d08ddffff         | mov                 ecx, dword ptr [ebp - 0x22f8]
            //   8d0498               | lea                 eax, [eax + ebx*4]

        $sequence_3 = { 8802 42 84c0 75f6 8b442418 }
            // n = 5, score = 100
            //   8802                 | mov                 byte ptr [edx], al
            //   42                   | inc                 edx
            //   84c0                 | test                al, al
            //   75f6                 | jne                 0xfffffff8
            //   8b442418             | mov                 eax, dword ptr [esp + 0x18]

        $sequence_4 = { 2bca 3bcf 7307 83c8ff }
            // n = 4, score = 100
            //   2bca                 | sub                 ecx, edx
            //   3bcf                 | cmp                 ecx, edi
            //   7307                 | jae                 9
            //   83c8ff               | or                  eax, 0xffffffff

        $sequence_5 = { 8db8908b4100 57 ff15???????? ff0d???????? }
            // n = 4, score = 100
            //   8db8908b4100         | lea                 edi, [eax + 0x418b90]
            //   57                   | push                edi
            //   ff15????????         |                     
            //   ff0d????????         |                     

        $sequence_6 = { e8???????? 59 59 8945f4 8d45f8 50 }
            // n = 6, score = 100
            //   e8????????           |                     
            //   59                   | pop                 ecx
            //   59                   | pop                 ecx
            //   8945f4               | mov                 dword ptr [ebp - 0xc], eax
            //   8d45f8               | lea                 eax, [ebp - 8]
            //   50                   | push                eax

        $sequence_7 = { 803d????????00 7449 6a02 5b ff36 e8???????? ff7604 }
            // n = 7, score = 100
            //   803d????????00       |                     
            //   7449                 | je                  0x4b
            //   6a02                 | push                2
            //   5b                   | pop                 ebx
            //   ff36                 | push                dword ptr [esi]
            //   e8????????           |                     
            //   ff7604               | push                dword ptr [esi + 4]

        $sequence_8 = { a4 8dbdfcfdffff 4f 8a4f01 47 84c9 75f8 }
            // n = 7, score = 100
            //   a4                   | movsb               byte ptr es:[edi], byte ptr [esi]
            //   8dbdfcfdffff         | lea                 edi, [ebp - 0x204]
            //   4f                   | dec                 edi
            //   8a4f01               | mov                 cl, byte ptr [edi + 1]
            //   47                   | inc                 edi
            //   84c9                 | test                cl, cl
            //   75f8                 | jne                 0xfffffffa

        $sequence_9 = { 83ec20 53 56 8bda 8bf1 68d0070000 895dec }
            // n = 7, score = 100
            //   83ec20               | sub                 esp, 0x20
            //   53                   | push                ebx
            //   56                   | push                esi
            //   8bda                 | mov                 ebx, edx
            //   8bf1                 | mov                 esi, ecx
            //   68d0070000           | push                0x7d0
            //   895dec               | mov                 dword ptr [ebp - 0x14], ebx

    condition:
        7 of them and filesize < 245760
}