rule win_polyvice_auto {

    meta:
        author = "Felix Bilstein - yara-signator at cocacoding dot com"
        date = "2023-01-25"
        version = "1"
        description = "Detects win.polyvice."
        info = "autogenerated rule brought to you by yara-signator"
        tool = "yara-signator v0.6.0"
        signator_config = "callsandjumps;datarefs;binvalue"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.polyvice"
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
        $sequence_0 = { 4501cc 41c1c707 4431e7 c1c70c 4101fd 4531e9 4589ce }
            // n = 7, score = 100
            //   4501cc               | xor                 ebp, esi
            //   41c1c707             | mov                 dword ptr [esp + 0x14], eax
            //   4431e7               | inc                 esp
            //   c1c70c               | mov                 eax, esp
            //   4101fd               | inc                 esp
            //   4531e9               | xor                 ebp, ebp
            //   4589ce               | inc                 esp

        $sequence_1 = { 41c1c902 4501da 478d5c1500 4489ce 4189d9 41c1c90d 4189dd }
            // n = 7, score = 100
            //   41c1c902             | add                 ebx, esi
            //   4501da               | inc                 esp
            //   478d5c1500           | mov                 edi, esp
            //   4489ce               | inc                 edx
            //   4189d9               | lea                 edi, [eax + eax]
            //   41c1c90d             | inc                 esp
            //   4189dd               | mov                 eax, esp

        $sequence_2 = { 41c1eb10 410fb6dd 450fb6db 41333498 0fb6dc 4489e8 33b1b0000000 }
            // n = 7, score = 100
            //   41c1eb10             | inc                 ecx
            //   410fb6dd             | ror                 edx, 0xd
            //   450fb6db             | inc                 ecx
            //   41333498             | mov                 esi, edi
            //   0fb6dc               | inc                 esp
            //   4489e8               | add                 edx, edx
            //   33b1b0000000         | inc                 ebp

        $sequence_3 = { 4431d7 01fd 4489c7 c1ce06 c1cf0b 4521ec }
            // n = 6, score = 100
            //   4431d7               | mov                 dword ptr [esp + 0x2b0], edx
            //   01fd                 | dec                 eax
            //   4489c7               | mov                 edx, dword ptr [eax + 0x10]
            //   c1ce06               | dec                 eax
            //   c1cf0b               | mov                 dword ptr [esp + 0x2b8], edx
            //   4521ec               | dec                 eax

        $sequence_4 = { 89da 4c89f1 e8???????? 6641892c24 31d2 89d0 4881c4a8230000 }
            // n = 7, score = 100
            //   89da                 | lea                 esi, [edx + eax + 0x10]
            //   4c89f1               | dec                 esp
            //   e8????????           |                     
            //   6641892c24           | mov                 dword ptr [esp + 0x30], edi
            //   31d2                 | inc                 ebp
            //   89d0                 | mov                 edi, esi
            //   4881c4a8230000       | dec                 eax

        $sequence_5 = { 488d45c0 498d7c2440 4883e0c0 488d5c0640 660f1f840000000000 4889f1 4889fa }
            // n = 7, score = 100
            //   488d45c0             | inc                 edi
            //   498d7c2440           | lea                 ecx, [ecx + ebp + 0x1e376c08]
            //   4883e0c0             | and                 edi, ecx
            //   488d5c0640           | ror                 ebx, 0xb
            //   660f1f840000000000     | xor    edi, edx
            //   4889f1               | inc                 esp
            //   4889fa               | add                 edi, ecx

        $sequence_6 = { 4589d1 4531fb 4509c1 4131fb 4121c9 c1c902 4589df }
            // n = 7, score = 100
            //   4589d1               | movzx               ebp, ch
            //   4531fb               | inc                 ebp
            //   4509c1               | xor                 esp, dword ptr [edi + eax*4]
            //   4131fb               | inc                 ecx
            //   4121c9               | shr                 ebp, 0x18
            //   c1c902               | inc                 ebp
            //   4589df               | movzx               ebp, ch

        $sequence_7 = { 84834c000200 74a7 80bb4d00020000 7412 4139f4 740d }
            // n = 6, score = 100
            //   84834c000200         | lea                 ecx, [0x1b08f]
            //   74a7                 | mov                 edx, eax
            //   80bb4d00020000       | nop                 
            //   7412                 | dec                 eax
            //   4139f4               | lea                 edx, [0x1affb]
            //   740d                 | dec                 eax

        $sequence_8 = { 480faffd 4d0fafcc 4c01f7 4d89c6 4d0faff7 4d01cb 4c0faf442408 }
            // n = 7, score = 100
            //   480faffd             | xor                 ebx, eax
            //   4d0fafcc             | inc                 ecx
            //   4c01f7               | rol                 ebx, 1
            //   4d89c6               | inc                 esp
            //   4d0faff7             | mov                 ebx, edi
            //   4d01cb               | inc                 ebp
            //   4c0faf442408         | xor                 ebx, edi

        $sequence_9 = { 4189c8 89c1 428d94026dc631a8 4431f9 4489442428 4589e0 4421f1 }
            // n = 7, score = 100
            //   4189c8               | inc                 ecx
            //   89c1                 | bswap               ebp
            //   428d94026dc631a8     | inc                 ecx
            //   4431f9               | rol                 edi, 5
            //   4489442428           | inc                 esp
            //   4589e0               | lea                 edx, [edi + ebx - 0x70e44324]
            //   4421f1               | mov                 edi, dword ptr [esp + 0x1c]

    condition:
        7 of them and filesize < 369664
}